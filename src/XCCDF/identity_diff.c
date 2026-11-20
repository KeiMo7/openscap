/*
 * Copyright 2026 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "identity_diff_priv.h"

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "common/util.h"
#include "common/public/oscap_helpers.h"
#include "common/debug_priv.h"
#include "common/list.h"
#include "source/oscap_source_priv.h"

/* ------------------------------------------------------------------ */
/* Artifact parsing                                                   */
/* ------------------------------------------------------------------ */

static xmlXPathObjectPtr cid_diff_xpath(xmlDocPtr doc, const char *expr)
{
	xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
	if (ctx == NULL)
		return NULL;
	xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	xmlXPathFreeContext(ctx);
	return obj;
}

static char *cid_text_content(xmlNodePtr node)
{
	xmlChar *text = xmlNodeGetContent(node);
	if (text == NULL)
		return NULL;
	char *copy = oscap_strdup((char *) text);
	xmlFree(text);
	return copy;
}

static void cid_rule_outcome_free(void *ptr)
{
	struct cid_rule_outcome *outcome = ptr;
	if (outcome == NULL)
		return;
	free(outcome->rule_id);
	free(outcome->result);
	free(outcome);
}

static void cid_extract_outcomes(struct cid_artifact *artifact)
{
	artifact->outcomes = oscap_htable_new();
	xmlXPathObjectPtr rr = cid_diff_xpath(artifact->doc,
		"//*[local-name()='rule-result']");
	if (rr == NULL || rr->nodesetval == NULL) {
		if (rr != NULL)
			xmlXPathFreeObject(rr);
		return;
	}
	for (int i = 0; i < rr->nodesetval->nodeNr; ++i) {
		xmlNodePtr node = rr->nodesetval->nodeTab[i];
		xmlChar *idref = xmlGetProp(node, BAD_CAST "idref");
		if (idref == NULL)
			continue;
		char *result_text = NULL;
		for (xmlNodePtr child = node->children; child != NULL; child = child->next) {
			if (child->type == XML_ELEMENT_NODE
					&& xmlStrcmp(child->name, BAD_CAST "result") == 0) {
				result_text = cid_text_content(child);
				break;
			}
		}
		struct cid_rule_outcome *outcome = calloc(1, sizeof(struct cid_rule_outcome));
		outcome->rule_id = oscap_strdup((char *) idref);
		outcome->result = result_text != NULL ? result_text : oscap_strdup("unknown");
		oscap_htable_add(artifact->outcomes, outcome->rule_id, outcome);
		xmlFree(idref);
	}
	xmlXPathFreeObject(rr);
}

static void cid_extract_target(struct cid_artifact *artifact)
{
	xmlXPathObjectPtr targets = cid_diff_xpath(artifact->doc,
		"//*[local-name()='target'][1]/text()");
	if (targets != NULL && targets->nodesetval != NULL && targets->nodesetval->nodeNr > 0)
		artifact->target = cid_text_content(targets->nodesetval->nodeTab[0]);
	if (targets != NULL)
		xmlXPathFreeObject(targets);

	artifact->target_facts = oscap_list_new();
	xmlXPathObjectPtr facts = cid_diff_xpath(artifact->doc,
		"//*[local-name()='target-facts']/*[local-name()='fact']");
	if (facts != NULL && facts->nodesetval != NULL) {
		for (int i = 0; i < facts->nodesetval->nodeNr; ++i) {
			xmlNodePtr fact = facts->nodesetval->nodeTab[i];
			xmlChar *name = xmlGetProp(fact, BAD_CAST "name");
			char *value = cid_text_content(fact);
			if (name != NULL && value != NULL) {
				char *line = oscap_sprintf("%s=%s", (char *) name, value);
				oscap_list_add(artifact->target_facts, line);
			}
			if (name != NULL)
				xmlFree(name);
			free(value);
		}
	}
	if (facts != NULL)
		xmlXPathFreeObject(facts);
}

struct cid_artifact *cid_artifact_parse(const char *path)
{
	struct oscap_source *source = oscap_source_new_from_file(path);
	if (source == NULL)
		return NULL;
	xmlDocPtr doc = oscap_source_get_xmlDoc(source);
	if (doc == NULL) {
		oscap_source_free(source);
		return NULL;
	}

	struct cid_artifact *artifact = calloc(1, sizeof(struct cid_artifact));
	artifact->path = oscap_strdup(path);
	artifact->doc = doc;
	artifact->test_result = cid_find_test_result(doc);
	artifact->identity = cid_identity_parse_from_doc(doc);
	cid_extract_outcomes(artifact);
	cid_extract_target(artifact);

	/* Keep the doc alive: release source ownership of the xmlDoc. */
	oscap_source_pop_xmlDoc(source);
	oscap_source_free(source);
	return artifact;
}

void cid_artifact_free(struct cid_artifact *artifact)
{
	if (artifact == NULL)
		return;
	free(artifact->path);
	if (artifact->doc != NULL)
		xmlFreeDoc(artifact->doc);
	cid_identity_free(artifact->identity);
	oscap_htable_free(artifact->outcomes, cid_rule_outcome_free);
	free(artifact->target);
	oscap_list_free(artifact->target_facts, free);
	free(artifact);
}

const char *cid_artifact_outcome(const struct cid_artifact *artifact, const char *rule_id)
{
	if (artifact == NULL || artifact->outcomes == NULL || rule_id == NULL)
		return NULL;
	struct cid_rule_outcome *outcome = oscap_htable_get(artifact->outcomes, rule_id);
	return outcome != NULL ? outcome->result : NULL;
}

/* ------------------------------------------------------------------ */
/* Matching and attribution                                           */
/* ------------------------------------------------------------------ */

static struct cid_diff_entry *cid_diff_entry_new(const char *stable_key)
{
	struct cid_diff_entry *entry = calloc(1, sizeof(struct cid_diff_entry));
	entry->stable_key = oscap_strdup(stable_key);
	entry->category = CID_DIFF_UNCHANGED;
	entry->side = CID_SIDE_NONE;
	return entry;
}

void cid_diff_entry_free(struct cid_diff_entry *entry)
{
	if (entry == NULL)
		return;
	free(entry->stable_key);
	free(entry->old_id);
	free(entry->new_id);
	free(entry->old_result);
	free(entry->new_result);
	free(entry->reason);
	free(entry);
}

static int cid_entry_cmp(const void *a, const void *b)
{
	const struct cid_diff_entry *ea = *(const struct cid_diff_entry * const *) a;
	const struct cid_diff_entry *eb = *(const struct cid_diff_entry * const *) b;
	return strcmp(ea->stable_key, eb->stable_key);
}

static int cid_strcmp_qsort(const void *a, const void *b)
{
	return strcmp(*(const char * const *) a, *(const char * const *) b);
}

/* Find a new-side rule whose id has not been matched yet. */
static struct cid_rule *cid_find_unmatched_by(struct cid_identity *identity,
		struct oscap_htable *matched, const char *field, const char *value)
{
	if (value == NULL)
		return NULL;
	struct oscap_iterator *it = oscap_iterator_new(identity->rules);
	while (oscap_iterator_has_more(it)) {
		struct cid_rule *rule = oscap_iterator_next(it);
		if (oscap_htable_get(matched, rule->id) != NULL)
			continue;
		const char *candidate;
		if (strcmp(field, "cluster") == 0)
			candidate = rule->cluster_id;
		else if (strcmp(field, "id") == 0)
			candidate = rule->id;
		else
			candidate = rule->check_refs;
		/* check_refs is sorted, de-duplicated and newline-joined on both
		 * sides, so equal reference sets compare equal as whole strings. */
		if (candidate != NULL && strcmp(candidate, value) == 0) {
			oscap_iterator_free(it);
			return rule;
		}
	}
	oscap_iterator_free(it);
	return NULL;
}

/**
 * Cascade match an old rule into the new artifact's rules:
 * cluster id -> rule id -> check-content-ref set.  Returns NULL when
 * nothing unmatched correlates.
 */
static struct cid_rule *cid_match_rule(struct cid_identity *new_identity,
		struct cid_rule *old_rule, struct oscap_htable *matched)
{
	struct cid_rule *match = cid_find_unmatched_by(new_identity, matched, "cluster", old_rule->cluster_id);
	if (match != NULL)
		return match;
	match = cid_find_unmatched_by(new_identity, matched, "id", old_rule->id);
	if (match != NULL)
		return match;
	return cid_find_unmatched_by(new_identity, matched, "check-ref", old_rule->check_refs);
}

static bool cid_targets_comparable(struct cid_artifact *old_art, struct cid_artifact *new_art, char **message)
{
	if (old_art->target == NULL || new_art->target == NULL
			|| strcmp(old_art->target, new_art->target) != 0) {
		*message = oscap_sprintf(
			"Targets are not comparable: target names differ ('%s' vs '%s'). "
			"Refusing attribution; only a raw difference list is provided.",
			old_art->target ? old_art->target : "(none)",
			new_art->target ? new_art->target : "(none)");
		return false;
	}

	/* Compare target-fact fingerprints as sorted sets. */
	size_t on = oscap_list_get_itemcount(old_art->target_facts);
	size_t nn = oscap_list_get_itemcount(new_art->target_facts);
	if (on != nn) {
		*message = oscap_sprintf(
			"Targets are not comparable: target-facts collection scope differs (%zu vs %zu facts). "
			"Refusing attribution; only a raw difference list is provided.", on, nn);
		return false;
	}
	char **old_arr = malloc(on * sizeof(char *));
	char **new_arr = malloc(nn * sizeof(char *));
	struct oscap_iterator *oit = oscap_iterator_new(old_art->target_facts);
	struct oscap_iterator *nit = oscap_iterator_new(new_art->target_facts);
	for (size_t i = 0; i < on; ++i)
		old_arr[i] = oscap_iterator_next(oit);
	for (size_t i = 0; i < nn; ++i)
		new_arr[i] = oscap_iterator_next(nit);
	oscap_iterator_free(oit);
	oscap_iterator_free(nit);
	qsort(old_arr, on, sizeof(char *), cid_strcmp_qsort);
	qsort(new_arr, nn, sizeof(char *), cid_strcmp_qsort);
	bool equal = true;
	for (size_t i = 0; i < on; ++i) {
		if (strcmp(old_arr[i], new_arr[i]) != 0) {
			equal = false;
			*message = oscap_sprintf(
				"Targets are not comparable: target-fact fingerprint differs at '%s' vs '%s'. "
				"Refusing attribution; only a raw difference list is provided.",
				old_arr[i], new_arr[i]);
			break;
		}
	}
	free(old_arr);
	free(new_arr);
	return equal;
}

static bool cid_tailoring_matches_content(struct cid_artifact *artifact, char **message)
{
	struct cid_identity *identity = artifact->identity;
	if (identity == NULL || identity->tailoring == NULL)
		return true;
	const char *benchmark_digest = NULL;
	struct oscap_iterator *cit = oscap_iterator_new(identity->components);
	while (oscap_iterator_has_more(cit)) {
		struct cid_component *component = oscap_iterator_next(cit);
		if (strcmp(component->content_type, "xccdf") == 0) {
			benchmark_digest = component->digest;
			break;
		}
	}
	oscap_iterator_free(cit);

	if (benchmark_digest == NULL || identity->tailoring->benchmark_digest == NULL)
		return true; /* nothing to cross-check */
	if (strcmp(benchmark_digest, identity->tailoring->benchmark_digest) != 0) {
		*message = oscap_sprintf(
			"Tailoring/content version mismatch in '%s': tailoring references "
			"benchmark-digest '%s' but the XCCDF component digest is '%s'. "
			"Refusing to guess; aborting.",
			artifact->path, identity->tailoring->benchmark_digest, benchmark_digest);
		return false;
	}
	return true;
}

static void cid_set_reason(struct cid_diff_entry *entry, const char *reason)
{
	free(entry->reason);
	entry->reason = oscap_strdup(reason);
}

/* Takes ownership of the allocated reason string. */
static void cid_set_reason_owned(struct cid_diff_entry *entry, char *reason)
{
	free(entry->reason);
	entry->reason = reason;
}

static void cid_classify_pair(struct cid_diff_entry *entry,
		struct cid_rule *old_rule, struct cid_rule *new_rule,
		struct cid_artifact *old_art, struct cid_artifact *new_art)
{
	entry->old_id = oscap_strdup(old_rule != NULL ? old_rule->id : NULL);
	entry->new_id = oscap_strdup(new_rule != NULL ? new_rule->id : NULL);
	entry->old_result = oscap_strdup(cid_artifact_outcome(old_art,
		old_rule != NULL ? old_rule->id : NULL));
	entry->new_result = oscap_strdup(cid_artifact_outcome(new_art,
		new_rule != NULL ? new_rule->id : NULL));

	bool body_equal = old_rule && new_rule
		&& old_rule->body_digest && new_rule->body_digest
		&& strcmp(old_rule->body_digest, new_rule->body_digest) == 0;
	bool logic_equal = old_rule && new_rule
		&& old_rule->logic_digest && new_rule->logic_digest
		&& strcmp(old_rule->logic_digest, new_rule->logic_digest) == 0;
	bool version_equal = old_rule && new_rule
		&& ((old_rule->author_version == NULL && new_rule->author_version == NULL)
			|| (old_rule->author_version != NULL && new_rule->author_version != NULL
				&& strcmp(old_rule->author_version, new_rule->author_version) == 0));
	bool id_changed = old_rule && new_rule
		&& strcmp(old_rule->id, new_rule->id) != 0;
	bool moved = old_rule && new_rule
		&& ((old_rule->group_path == NULL && new_rule->group_path != NULL)
			|| (old_rule->group_path != NULL && new_rule->group_path == NULL)
			|| (old_rule->group_path != NULL && new_rule->group_path != NULL
				&& strcmp(old_rule->group_path, new_rule->group_path) != 0));
	bool result_changed = (entry->old_result != NULL || entry->new_result != NULL)
		&& ((entry->old_result == NULL) != (entry->new_result == NULL)
			|| (entry->old_result != NULL && entry->new_result != NULL
				&& strcmp(entry->old_result, entry->new_result) != 0));
	bool tailoring_changed = (old_rule && old_rule->customized) || (new_rule && new_rule->customized);

	/*
	 * Degradation 2: when either side failed to derive a rule digest,
	 * the content cannot be compared for this rule.  Mark it unknown
	 * instead of guessing a content change; the rest of the artifact is
	 * unaffected.  A result flip is still reported (from rule-results,
	 * which do not depend on the digest) but stays unattributed.
	 */
	bool digest_missing = (old_rule->body_digest == NULL || old_rule->logic_digest == NULL
			|| new_rule->body_digest == NULL || new_rule->logic_digest == NULL);
	if (digest_missing) {
		entry->side = CID_SIDE_UNKNOWN;
		if (result_changed) {
			entry->category = CID_DIFF_RESULT_FLIP;
			cid_set_reason(entry, "result flipped but content attribution unavailable: "
				"a rule digest is missing on one side (per-rule parse failure)");
		} else {
			entry->category = CID_DIFF_UNKNOWN;
			cid_set_reason(entry, "unknown: rule content digest missing on one side, "
				"content equality cannot be established (other rules unaffected)");
		}
		return;
	}

	/*
	 * Rename / move are structural facts established by the stable
	 * identity.  They are reported directly when nothing more decisive
	 * happened; a genuine result flip or logic change still takes
	 * precedence but keeps the rename/move context in the reason text.
	 */
	char structural_note[256] = "";
	if (id_changed && moved)
		snprintf(structural_note, sizeof(structural_note),
			" (also renamed '%s'->'%s' and moved '%s'->'%s')",
			old_rule->id, new_rule->id,
			old_rule->group_path ? old_rule->group_path : "-",
			new_rule->group_path ? new_rule->group_path : "-");
	else if (id_changed)
		snprintf(structural_note, sizeof(structural_note),
			" (also renamed '%s'->'%s')", old_rule->id, new_rule->id);
	else if (moved)
		snprintf(structural_note, sizeof(structural_note),
			" (moved '%s'->'%s')",
			old_rule->group_path ? old_rule->group_path : "-",
			new_rule->group_path ? new_rule->group_path : "-");

	if (!body_equal && !logic_equal) {
		entry->category = result_changed ? CID_DIFF_RESULT_FLIP : CID_DIFF_CONTENT_CHANGED;
		/* Name the actual decision criterion that moved, when visible. */
		char trigger[512] = "";
		if (old_rule->check_refs != NULL && new_rule->check_refs != NULL
				&& strcmp(old_rule->check_refs, new_rule->check_refs) != 0) {
			snprintf(trigger, sizeof(trigger),
				"; trigger check-content-ref changed: ['%s'] -> ['%s']",
				old_rule->check_refs, new_rule->check_refs);
		} else {
			snprintf(trigger, sizeof(trigger),
				"; trigger: check/complex-check/requires/conflicts/ident/platform subtree (logic-digest)");
		}
		if (result_changed) {
			entry->side = CID_SIDE_CONTENT;
			cid_set_reason_owned(entry, oscap_sprintf(
				"content-side: decision criteria changed and the result flipped%s%s",
				trigger, structural_note));
		} else {
			cid_set_reason_owned(entry, oscap_sprintf(
				"rule content changed (body/logic digest) but result did not flip%s%s",
				trigger, structural_note));
		}
		return;
	}

	if (body_equal && !version_equal) {
		entry->category = CID_DIFF_VERSION_LABEL_ONLY;
		entry->side = CID_SIDE_NONE;
		cid_set_reason(entry, "version-label-only: author version changed, rule body identical");
		return;
	}

	if (result_changed) {
		entry->category = CID_DIFF_RESULT_FLIP;
		if (tailoring_changed) {
			entry->side = CID_SIDE_TAILORING;
			cid_set_reason(entry, "tailoring-introduced: custom baseline differs, target evidence unchanged");
		} else {
			entry->side = CID_SIDE_TARGET;
			cid_set_reason_owned(entry, oscap_sprintf(
				"target-side: content identical, target evidence changed%s", structural_note));
		}
		return;
	}

	if (id_changed) {
		entry->category = CID_DIFF_RENAMED;
		entry->side = CID_SIDE_CONTENT;
		cid_set_reason(entry, "renamed: matched by stable identity, rule id changed, content equivalent");
		return;
	}
	if (moved) {
		entry->category = CID_DIFF_MOVED;
		entry->side = CID_SIDE_NONE;
		cid_set_reason(entry, "moved: stable identity matched, rule group path changed, content equivalent");
		return;
	}

	if (!body_equal) {
		entry->category = CID_DIFF_CONTENT_CHANGED;
		cid_set_reason(entry, "rule body changed while logic and result stayed equal");
		return;
	}

	if (entry->category == CID_DIFF_UNCHANGED && !id_changed && !moved) {
		cid_set_reason(entry, "unchanged");
	}
}

struct cid_diff_result *cid_diff_compute(struct cid_artifact *old_art, struct cid_artifact *new_art)
{
	struct cid_diff_result *result = calloc(1, sizeof(struct cid_diff_result));
	result->entries = oscap_list_new();
	result->status = CID_DIFF_STATUS_OK;

	bool old_has_id = old_art->identity != NULL;
	bool new_has_id = new_art->identity != NULL;
	result->missing_identity = !old_has_id || !new_has_id;

	/* Gate: target comparability. */
	char *gate_message = NULL;
	if (!cid_targets_comparable(old_art, new_art, &gate_message)) {
		result->status = CID_DIFF_STATUS_TARGET_INCOMPARABLE;
		result->status_message = gate_message;
	} else {
		/* Gate: tailoring/content consistency. */
		char *tail_msg_old = NULL, *tail_msg_new = NULL;
		if (!cid_tailoring_matches_content(old_art, &tail_msg_old)) {
			result->status = CID_DIFF_STATUS_TAILORING_MISMATCH;
			result->status_message = tail_msg_old;
		} else if (!cid_tailoring_matches_content(new_art, &tail_msg_new)) {
			result->status = CID_DIFF_STATUS_TAILORING_MISMATCH;
			result->status_message = tail_msg_new;
		}
	}

	struct oscap_htable *matched_new = oscap_htable_new();

	if (old_has_id && new_has_id && result->status == CID_DIFF_STATUS_OK) {
		/*
		 * Full identity-based matching with a stable-key cascade.
		 * The check-content-ref is a rename anchor but is itself part
		 * of the decision criteria, so a single key is not enough:
		 *   1. cluster id  (author-provided stable correlation)
		 *   2. rule id     (survives a check/criteria change)
		 *   3. check-refs  (survives a rename when id changes)
		 * A match at a lower level is only accepted while unmatched, so
		 * every rule is paired at most once and the result stays
		 * deterministic.
		 */
		struct oscap_iterator *oit = oscap_iterator_new(old_art->identity->rules);
		while (oscap_iterator_has_more(oit)) {
			struct cid_rule *old_rule = oscap_iterator_next(oit);
			struct cid_rule *new_rule = cid_match_rule(new_art->identity, old_rule, matched_new);
			struct cid_diff_entry *entry = cid_diff_entry_new(old_rule->stable_key);
			if (new_rule == NULL) {
				entry->category = CID_DIFF_REMOVED;
				entry->side = CID_SIDE_CONTENT;
				entry->old_id = oscap_strdup(old_rule->id);
				entry->old_result = oscap_strdup(cid_artifact_outcome(old_art, old_rule->id));
				cid_set_reason(entry, "disappeared: no stable identity matched in the new artifact");
			} else {
				oscap_htable_add(matched_new, new_rule->id, (void *) 1);
				cid_classify_pair(entry, old_rule, new_rule, old_art, new_art);
			}
			oscap_list_add(result->entries, entry);
		}
		oscap_iterator_free(oit);

		struct oscap_iterator *nit = oscap_iterator_new(new_art->identity->rules);
		while (oscap_iterator_has_more(nit)) {
			struct cid_rule *new_rule = oscap_iterator_next(nit);
			if (oscap_htable_get(matched_new, new_rule->id) != NULL)
				continue;
			struct cid_diff_entry *entry = cid_diff_entry_new(new_rule->stable_key);
			entry->category = CID_DIFF_ADDED;
			entry->side = CID_SIDE_CONTENT;
			entry->new_id = oscap_strdup(new_rule->id);
			entry->new_result = oscap_strdup(cid_artifact_outcome(new_art, new_rule->id));
			cid_set_reason(entry, "added: new stable identity not present in the baseline");
			oscap_list_add(result->entries, entry);
		}
		oscap_iterator_free(nit);
	} else {
		/*
		 * Degraded mode: missing identity or a failed gate.  Still emit a
		 * raw difference list keyed by rule id, explicitly marked unknown
		 * and never attributed.  Missing identities are never treated as
		 * "same content".
		 */
		struct oscap_htable *seen_old = oscap_htable_new();
		struct oscap_htable *seen_new_ids = oscap_htable_new();
		struct oscap_htable *all_ids = oscap_htable_new();

		xmlXPathObjectPtr old_rr = cid_diff_xpath(old_art->doc, "//*[local-name()='rule-result']");
		xmlXPathObjectPtr new_rr = cid_diff_xpath(new_art->doc, "//*[local-name()='rule-result']");
		if (old_rr && old_rr->nodesetval) {
			for (int i = 0; i < old_rr->nodesetval->nodeNr; ++i) {
				xmlChar *idref = xmlGetProp(old_rr->nodesetval->nodeTab[i], BAD_CAST "idref");
				if (idref) {
					oscap_htable_add(seen_old, (char *) idref, (void *) 1);
					oscap_htable_add(all_ids, (char *) idref, (void *) 1);
					xmlFree(idref);
				}
			}
		}
		if (new_rr && new_rr->nodesetval) {
			for (int i = 0; i < new_rr->nodesetval->nodeNr; ++i) {
				xmlChar *idref = xmlGetProp(new_rr->nodesetval->nodeTab[i], BAD_CAST "idref");
				if (idref) {
					oscap_htable_add(seen_new_ids, (char *) idref, (void *) 1);
					oscap_htable_add(all_ids, (char *) idref, (void *) 1);
					xmlFree(idref);
				}
			}
		}
		if (old_rr) xmlXPathFreeObject(old_rr);
		if (new_rr) xmlXPathFreeObject(new_rr);

		struct oscap_htable_iterator *hit = oscap_htable_iterator_new(all_ids);
		while (oscap_htable_iterator_has_more(hit)) {
			const struct oscap_htable_item *item = oscap_htable_iterator_next(hit);
			const char *id = item->key;
			char *stable_key = oscap_sprintf("id:%s", id);
			struct cid_diff_entry *entry = cid_diff_entry_new(stable_key);
			free(stable_key);
			entry->old_missing_identity = !old_has_id;
			entry->new_missing_identity = !new_has_id;
			entry->side = CID_SIDE_UNKNOWN;
			bool in_old = oscap_htable_get(seen_old, id) != NULL;
			bool in_new = oscap_htable_get(seen_new_ids, id) != NULL;
			entry->old_id = oscap_strdup(in_old ? id : NULL);
			entry->new_id = oscap_strdup(in_new ? id : NULL);
			entry->old_result = oscap_strdup(cid_artifact_outcome(old_art, id));
			entry->new_result = oscap_strdup(cid_artifact_outcome(new_art, id));
			if (!in_new) {
				entry->category = CID_DIFF_REMOVED;
				cid_set_reason(entry, "raw difference: rule absent from new artifact (not attributable: content identity missing)");
			} else if (!in_old) {
				entry->category = CID_DIFF_ADDED;
				cid_set_reason(entry, "raw difference: rule absent from old artifact (not attributable: content identity missing)");
			} else if (strcmp(entry->old_result ? entry->old_result : "",
					entry->new_result ? entry->new_result : "") != 0) {
				entry->category = CID_DIFF_UNKNOWN;
				cid_set_reason(entry, "raw result difference (not attributable: content identity missing or target incomparable)");
			} else {
				entry->category = CID_DIFF_UNCHANGED;
				cid_set_reason(entry, "raw records equal; attribution unavailable");
			}
			oscap_list_add(result->entries, entry);
		}
		oscap_htable_iterator_free(hit);
		oscap_htable_free0(seen_old);
		oscap_htable_free0(seen_new_ids);
		oscap_htable_free0(all_ids);
	}

	oscap_htable_free0(matched_new);

	/* Deterministic ordering. */
	size_t count = oscap_list_get_itemcount(result->entries);
	struct cid_diff_entry **arr = malloc(count * sizeof(struct cid_diff_entry *));
	struct oscap_iterator *eit = oscap_iterator_new(result->entries);
	for (size_t i = 0; i < count; ++i)
		arr[i] = oscap_iterator_next(eit);
	oscap_iterator_free(eit);
	qsort(arr, count, sizeof(struct cid_diff_entry *), cid_entry_cmp);
	oscap_list_free0(result->entries);
	result->entries = oscap_list_new();
	for (size_t i = 0; i < count; ++i)
		oscap_list_add(result->entries, arr[i]);
	free(arr);

	return result;
}

/* ------------------------------------------------------------------ */
/* Public API and rendering                                           */
/* ------------------------------------------------------------------ */

static const char *cid_category_name(cid_diff_category_t category)
{
	switch (category) {
	case CID_DIFF_UNCHANGED: return "unchanged";
	case CID_DIFF_ADDED: return "added";
	case CID_DIFF_REMOVED: return "disappeared";
	case CID_DIFF_RENAMED: return "renamed";
	case CID_DIFF_MOVED: return "moved";
	case CID_DIFF_RESULT_FLIP: return "result-flip";
	case CID_DIFF_VERSION_LABEL_ONLY: return "version-label-only";
	case CID_DIFF_CONTENT_CHANGED: return "content-changed";
	case CID_DIFF_UNKNOWN: return "unknown";
	}
	return "unknown";
}

static const char *cid_side_name(cid_diff_side_t side)
{
	switch (side) {
	case CID_SIDE_NONE: return "none";
	case CID_SIDE_TARGET: return "target-side";
	case CID_SIDE_CONTENT: return "content-side";
	case CID_SIDE_TAILORING: return "tailoring-introduced";
	case CID_SIDE_UNKNOWN: return "unknown";
	}
	return "unknown";
}

struct cid_diff_result *xccdf_identity_diff_files(const char *old_path, const char *new_path)
{
	struct cid_artifact *old_art = cid_artifact_parse(old_path);
	if (old_art == NULL)
		return NULL;
	struct cid_artifact *new_art = cid_artifact_parse(new_path);
	if (new_art == NULL) {
		cid_artifact_free(old_art);
		return NULL;
	}
	struct cid_diff_result *result = cid_diff_compute(old_art, new_art);
	cid_artifact_free(old_art);
	cid_artifact_free(new_art);
	return result;
}

void cid_diff_result_free(struct cid_diff_result *result)
{
	if (result == NULL)
		return;
	free(result->status_message);
	oscap_list_free(result->entries, (oscap_destruct_func) cid_diff_entry_free);
	free(result);
}

cid_diff_status_t cid_diff_result_get_status(const struct cid_diff_result *result)
{
	return result != NULL ? result->status : CID_DIFF_STATUS_ERROR;
}

const char *cid_diff_result_get_status_message(const struct cid_diff_result *result)
{
	return result != NULL ? result->status_message : NULL;
}

bool cid_diff_result_has_missing_identity(const struct cid_diff_result *result)
{
	return result != NULL && result->missing_identity;
}

size_t cid_diff_result_get_entry_count(const struct cid_diff_result *result)
{
	return result != NULL ? oscap_list_get_itemcount(result->entries) : 0;
}

const struct cid_diff_entry *cid_diff_result_get_entry(const struct cid_diff_result *result, size_t index)
{
	if (result == NULL)
		return NULL;
	struct oscap_iterator *it = oscap_iterator_new((struct oscap_list *) result->entries);
	const struct cid_diff_entry *found = NULL;
	for (size_t i = 0; oscap_iterator_has_more(it); ++i) {
		struct cid_diff_entry *entry = oscap_iterator_next(it);
		if (i == index) {
			found = entry;
			break;
		}
	}
	oscap_iterator_free(it);
	return found;
}

const char *cid_diff_entry_get_stable_key(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->stable_key : NULL; }
const char *cid_diff_entry_get_old_id(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->old_id : NULL; }
const char *cid_diff_entry_get_new_id(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->new_id : NULL; }
cid_diff_category_t cid_diff_entry_get_category(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->category : CID_DIFF_UNKNOWN; }
cid_diff_side_t cid_diff_entry_get_side(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->side : CID_SIDE_UNKNOWN; }
const char *cid_diff_entry_get_old_result(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->old_result : NULL; }
const char *cid_diff_entry_get_new_result(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->new_result : NULL; }
const char *cid_diff_entry_get_reason(const struct cid_diff_entry *entry)
{ return entry != NULL ? entry->reason : NULL; }

static void cid_append(char **buffer, size_t *used, size_t *capacity, const char *text)
{
	size_t len = strlen(text);
	if (*used + len + 1 > *capacity) {
		size_t new_cap = *capacity == 0 ? 256 : *capacity * 2;
		while (new_cap < *used + len + 1)
			new_cap *= 2;
		char *grown = realloc(*buffer, new_cap);
		if (grown == NULL)
			return;
		*buffer = grown;
		*capacity = new_cap;
	}
	memcpy(*buffer + *used, text, len + 1);
	*used += len;
}

char *cid_diff_result_render_text(const struct cid_diff_result *result)
{
	size_t used = 0, capacity = 0;
	char *out = NULL;

	if (result->status != CID_DIFF_STATUS_OK)
		cid_append(&out, &used, &capacity, result->status_message);
	cid_append(&out, &used, &capacity,
		result->missing_identity
			? "NOTICE: content identity missing on one or both artifacts; attribution unavailable.\n"
			: "Content identity present on both artifacts.\n");

	size_t added = 0, removed = 0, flipped = 0;
	struct oscap_iterator *it = oscap_iterator_new((struct oscap_list *) result->entries);
	while (oscap_iterator_has_more(it)) {
		struct cid_diff_entry *entry = oscap_iterator_next(it);
		if (entry->category == CID_DIFF_ADDED) ++added;
		if (entry->category == CID_DIFF_REMOVED) ++removed;
		if (entry->category == CID_DIFF_RESULT_FLIP) ++flipped;
	}
	oscap_iterator_free(it);
	char header[256];
	snprintf(header, sizeof(header),
		"Baseline lists: added=%zu disappeared=%zu flipped=%zu\n",
		added, removed, flipped);
	cid_append(&out, &used, &capacity, header);

	it = oscap_iterator_new((struct oscap_list *) result->entries);
	while (oscap_iterator_has_more(it)) {
		struct cid_diff_entry *entry = oscap_iterator_next(it);
		char line[1024];
		snprintf(line, sizeof(line),
			"[%s] key=%s old-id=%s new-id=%s old-result=%s new-result=%s side=%s\n  reason: %s\n",
			cid_category_name(entry->category),
			entry->stable_key ? entry->stable_key : "",
			entry->old_id ? entry->old_id : "-",
			entry->new_id ? entry->new_id : "-",
			entry->old_result ? entry->old_result : "-",
			entry->new_result ? entry->new_result : "-",
			cid_side_name(entry->side),
			entry->reason ? entry->reason : "");
		cid_append(&out, &used, &capacity, line);
	}
	oscap_iterator_free(it);
	return out;
}

static void cid_xml_escape_append(char **buffer, size_t *used, size_t *capacity, const char *text)
{
	if (text == NULL)
		return;
	for (const char *p = text; *p != '\0'; ++p) {
		const char *entity = NULL;
		switch (*p) {
		case '<': entity = "&lt;"; break;
		case '>': entity = "&gt;"; break;
		case '&': entity = "&amp;"; break;
		case '"': entity = "&quot;"; break;
		default: break;
		}
		if (entity != NULL)
			cid_append(buffer, used, capacity, entity);
		else {
			char one[2] = {*p, '\0'};
			cid_append(buffer, used, capacity, one);
		}
	}
}

char *cid_diff_result_render_xml(const struct cid_diff_result *result)
{
	size_t used = 0, capacity = 0;
	char *out = NULL;
	cid_append(&out, &used, &capacity,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<cid:identity-diff xmlns:cid=\"" XCCDF_CID_NS_URI "\" status=\"");
	cid_append(&out, &used, &capacity,
		result->status == CID_DIFF_STATUS_OK ? "ok" :
		result->status == CID_DIFF_STATUS_TARGET_INCOMPARABLE ? "target-incomparable" :
		result->status == CID_DIFF_STATUS_TAILORING_MISMATCH ? "tailoring-mismatch" : "error");
	cid_append(&out, &used, &capacity, "\" missing-identity=\"");
	cid_append(&out, &used, &capacity, result->missing_identity ? "true" : "false");
	cid_append(&out, &used, &capacity, "\">\n");
	if (result->status_message != NULL) {
		cid_append(&out, &used, &capacity, "  <cid:status-message>");
		cid_xml_escape_append(&out, &used, &capacity, result->status_message);
		cid_append(&out, &used, &capacity, "</cid:status-message>\n");
	}
	struct oscap_iterator *it = oscap_iterator_new((struct oscap_list *) result->entries);
	while (oscap_iterator_has_more(it)) {
		struct cid_diff_entry *entry = oscap_iterator_next(it);
		cid_append(&out, &used, &capacity, "  <cid:rule-entry category=\"");
		cid_append(&out, &used, &capacity, cid_category_name(entry->category));
		cid_append(&out, &used, &capacity, "\" side=\"");
		cid_append(&out, &used, &capacity, cid_side_name(entry->side));
		cid_append(&out, &used, &capacity, "\" stable-key=\"");
		cid_xml_escape_append(&out, &used, &capacity, entry->stable_key);
		cid_append(&out, &used, &capacity, "\">\n");
		if (entry->old_id) {
			cid_append(&out, &used, &capacity, "    <cid:old id=\"");
			cid_xml_escape_append(&out, &used, &capacity, entry->old_id);
			cid_append(&out, &used, &capacity, "\" result=\"");
			cid_xml_escape_append(&out, &used, &capacity, entry->old_result);
			cid_append(&out, &used, &capacity, "\"/>\n");
		}
		if (entry->new_id) {
			cid_append(&out, &used, &capacity, "    <cid:new id=\"");
			cid_xml_escape_append(&out, &used, &capacity, entry->new_id);
			cid_append(&out, &used, &capacity, "\" result=\"");
			cid_xml_escape_append(&out, &used, &capacity, entry->new_result);
			cid_append(&out, &used, &capacity, "\"/>\n");
		}
		cid_append(&out, &used, &capacity, "    <cid:reason>");
		cid_xml_escape_append(&out, &used, &capacity, entry->reason);
		cid_append(&out, &used, &capacity, "</cid:reason>\n  </cid:rule-entry>\n");
	}
	oscap_iterator_free(it);
	cid_append(&out, &used, &capacity, "</cid:identity-diff>\n");
	return out;
}
