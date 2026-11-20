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

#include "identity_priv.h"

#include <libxml/c14n.h>
#include <libxml/chvalid.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "common/util.h"
#include "common/public/oscap_helpers.h"
#include "common/debug_priv.h"
#include "common/list.h"
#include "common/oscap_digest.h"
#include "source/oscap_source_priv.h"
#include "helpers.h"
#include "item.h"
#include "public/xccdf_benchmark.h"
#include "public/xccdf_session.h"
#include "XCCDF_POLICY/public/xccdf_policy.h"
#include "XCCDF_POLICY/xccdf_policy_priv.h"
#include "XCCDF_POLICY/xccdf_policy_model_priv.h"

/* ------------------------------------------------------------------ */
/* Constructors / destructors                                         */
/* ------------------------------------------------------------------ */

struct cid_component *cid_component_new(const char *origin, const char *content_type, const char *digest)
{
	struct cid_component *component = calloc(1, sizeof(struct cid_component));
	if (component == NULL)
		return NULL;
	component->origin = oscap_strdup(origin);
	component->content_type = oscap_strdup(content_type);
	component->digest = oscap_strdup(digest);
	return component;
}

void cid_component_free(struct cid_component *component)
{
	if (component == NULL)
		return;
	free(component->origin);
	free(component->content_type);
	free(component->digest);
	free(component);
}

struct cid_tailoring_entry *cid_tailoring_entry_new(const char *kind, const char *idref, const char *value)
{
	struct cid_tailoring_entry *entry = calloc(1, sizeof(struct cid_tailoring_entry));
	if (entry == NULL)
		return NULL;
	entry->kind = oscap_strdup(kind);
	entry->idref = oscap_strdup(idref);
	entry->value = oscap_strdup(value);
	return entry;
}

void cid_tailoring_entry_free(struct cid_tailoring_entry *entry)
{
	if (entry == NULL)
		return;
	free(entry->kind);
	free(entry->idref);
	free(entry->value);
	free(entry);
}

struct cid_tailoring *cid_tailoring_new(void)
{
	struct cid_tailoring *tailoring = calloc(1, sizeof(struct cid_tailoring));
	if (tailoring != NULL)
		tailoring->entries = oscap_list_new();
	return tailoring;
}

void cid_tailoring_free(struct cid_tailoring *tailoring)
{
	if (tailoring == NULL)
		return;
	free(tailoring->origin);
	free(tailoring->digest);
	free(tailoring->profile_id);
	free(tailoring->benchmark_digest);
	oscap_list_free(tailoring->entries, (oscap_destruct_func) cid_tailoring_entry_free);
	free(tailoring);
}

struct cid_rule *cid_rule_new(void)
{
	return calloc(1, sizeof(struct cid_rule));
}

void cid_rule_free(struct cid_rule *rule)
{
	if (rule == NULL)
		return;
	free(rule->id);
	free(rule->cluster_id);
	free(rule->stable_key);
	free(rule->key_basis);
	free(rule->group_path);
	free(rule->body_digest);
	free(rule->logic_digest);
	free(rule->author_version);
	free(rule->check_refs);
	free(rule);
}

struct cid_identity *cid_identity_new(void)
{
	struct cid_identity *identity = calloc(1, sizeof(struct cid_identity));
	if (identity == NULL)
		return NULL;
	identity->algorithm = oscap_strdup(XCCDF_CID_ALGORITHM);
	identity->canonicalization = oscap_strdup(XCCDF_CID_CANONICALIZATION);
	identity->components = oscap_list_new();
	identity->rules = oscap_list_new();
	return identity;
}

void cid_identity_free(struct cid_identity *identity)
{
	if (identity == NULL)
		return;
	free(identity->algorithm);
	free(identity->canonicalization);
	oscap_list_free(identity->components, (oscap_destruct_func) cid_component_free);
	oscap_list_free(identity->rules, (oscap_destruct_func) cid_rule_free);
	cid_tailoring_free(identity->tailoring);
	free(identity);
}

struct cid_identity *cid_identity_clone(const struct cid_identity *identity)
{
	if (identity == NULL)
		return NULL;
	struct cid_identity *clone = cid_identity_new();
	if (clone == NULL)
		return NULL;

	free(clone->algorithm);
	free(clone->canonicalization);
	clone->algorithm = oscap_strdup(identity->algorithm);
	clone->canonicalization = oscap_strdup(identity->canonicalization);

	struct oscap_iterator *cit = oscap_iterator_new((struct oscap_list *) identity->components);
	while (oscap_iterator_has_more(cit)) {
		struct cid_component *src = oscap_iterator_next(cit);
		struct cid_component *dst = cid_component_new(src->origin, src->content_type, src->digest);
		if (dst != NULL)
			oscap_list_add(clone->components, dst);
	}
	oscap_iterator_free(cit);

	struct oscap_iterator *rit = oscap_iterator_new((struct oscap_list *) identity->rules);
	while (oscap_iterator_has_more(rit)) {
		struct cid_rule *src = oscap_iterator_next(rit);
		struct cid_rule *dst = cid_rule_new();
		dst->id = oscap_strdup(src->id);
		dst->cluster_id = oscap_strdup(src->cluster_id);
		dst->stable_key = oscap_strdup(src->stable_key);
		dst->key_basis = oscap_strdup(src->key_basis);
		dst->group_path = oscap_strdup(src->group_path);
		dst->body_digest = oscap_strdup(src->body_digest);
		dst->logic_digest = oscap_strdup(src->logic_digest);
		dst->author_version = oscap_strdup(src->author_version);
		dst->check_refs = oscap_strdup(src->check_refs);
		dst->selected = src->selected;
		dst->customized = src->customized;
		oscap_list_add(clone->rules, dst);
	}
	oscap_iterator_free(rit);

	if (identity->tailoring != NULL) {
		struct cid_tailoring *tail = cid_tailoring_new();
		tail->origin = oscap_strdup(identity->tailoring->origin);
		tail->digest = oscap_strdup(identity->tailoring->digest);
		tail->profile_id = oscap_strdup(identity->tailoring->profile_id);
		tail->benchmark_digest = oscap_strdup(identity->tailoring->benchmark_digest);
		struct oscap_iterator *eit = oscap_iterator_new((struct oscap_list *) identity->tailoring->entries);
		while (oscap_iterator_has_more(eit)) {
			struct cid_tailoring_entry *src = oscap_iterator_next(eit);
			struct cid_tailoring_entry *dst = cid_tailoring_entry_new(src->kind, src->idref, src->value);
			if (dst != NULL)
				oscap_list_add(tail->entries, dst);
		}
		oscap_iterator_free(eit);
		clone->tailoring = tail;
	}
	return clone;
}

/* ------------------------------------------------------------------ */
/* Canonicalization and digests                                       */
/* ------------------------------------------------------------------ */

static bool _cid_is_blank_text(xmlNodePtr node)
{
	if (node == NULL || node->type != XML_TEXT_NODE || node->content == NULL)
		return false;
	for (xmlChar *p = node->content; *p != '\0'; ++p) {
		if (!xmlIsBlank_ch(*p))
			return false;
	}
	return true;
}

/**
 * Recursively strip whitespace-only text nodes on a copy of a node.
 * Comments are removed as well.  Whitespace inside elements with mixed
 * textual content (descriptions, rationale) is preserved verbatim.
 */
static void _cid_strip_blank(xmlNodePtr node)
{
	xmlNodePtr child = node->children;
	while (child != NULL) {
		xmlNodePtr next = child->next;
		if (child->type == XML_COMMENT_NODE) {
			xmlUnlinkNode(child);
			xmlFreeNode(child);
		} else if (_cid_is_blank_text(child)) {
			xmlUnlinkNode(child);
			xmlFreeNode(child);
		} else if (child->type == XML_ELEMENT_NODE) {
			_cid_strip_blank(child);
		}
		child = next;
	}
}

/**
 * Remove xccdf:version child elements from a copied rule subtree.  The
 * author-supplied version is a label, not content: a version bump with
 * an otherwise unchanged body must keep the body digest stable so the
 * difference can be reported as version-label-only.
 */
static void cid_strip_version_elements(xmlNodePtr node)
{
	xmlNodePtr child = node->children;
	while (child != NULL) {
		xmlNodePtr next = child->next;
		if (child->type == XML_ELEMENT_NODE
				&& xmlStrcmp(child->name, BAD_CAST "version") == 0) {
			xmlUnlinkNode(child);
			xmlFreeNode(child);
		}
		child = next;
	}
}

char *cid_c14n_node(xmlNodePtr node, size_t *out_size)
{
	if (node == NULL || node->doc == NULL)
		return NULL;

	xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc == NULL)
		return NULL;
	xmlNodePtr copy = xmlCopyNode(node, 1);
	if (copy == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}
	xmlDocSetRootElement(doc, copy);
	_cid_strip_blank(copy);

	xmlChar *canonical = NULL;
	int rc = xmlC14NDocDumpMemory(doc, NULL, XML_C14N_1_0, NULL, 0, &canonical);
	xmlFreeDoc(doc);

	if (rc < 0 || canonical == NULL) {
		dE("XML canonicalization (C14N 1.0) failed.");
		return NULL;
	}
	*out_size = strlen((char *) canonical);
	return (char *) canonical;
}

char *cid_digest_node(xmlNodePtr node)
{
	size_t size = 0;
	char *canonical = cid_c14n_node(node, &size);
	if (canonical == NULL)
		return NULL;
	char *digest = oscap_digest_sha256_hex(canonical, size);
	xmlFree(canonical);
	return digest;
}

/**
 * Body digest over the full rule subtree excluding the author version
 * label (and whitespace/comments), so relabeling alone cannot move it.
 */
static char *cid_body_digest_rule(xmlNodePtr rule_node)
{
	if (rule_node == NULL || rule_node->doc == NULL)
		return NULL;
	xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc == NULL)
		return NULL;
	xmlNodePtr copy = xmlCopyNode(rule_node, 1);
	if (copy == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}
	xmlDocSetRootElement(doc, copy);
	_cid_strip_blank(copy);
	cid_strip_version_elements(copy);

	xmlChar *canonical = NULL;
	int rc = xmlC14NDocDumpMemory(doc, NULL, XML_C14N_1_0, NULL, 0, &canonical);
	xmlFreeDoc(doc);
	if (rc < 0 || canonical == NULL)
		return NULL;
	char *digest = oscap_digest_sha256_hex((char *) canonical, strlen((char *) canonical));
	xmlFree(canonical);
	return digest;
}

static char *cid_digest_source(struct oscap_source *source)
{
	if (source == NULL)
		return NULL;
	xmlDocPtr doc = oscap_source_get_xmlDoc(source);
	if (doc == NULL || xmlDocGetRootElement(doc) == NULL)
		return NULL;
	return cid_digest_node(xmlDocGetRootElement(doc));
}

/* ------------------------------------------------------------------ */
/* Per-rule identity                                                  */
/* ------------------------------------------------------------------ */

/* Decision-relevant Rule child elements (XCCDF local names). */
static const char *LOGIC_CHILDREN[] = {
	"check", "complex-check", "requires", "conflicts",
	"ident", "platform", NULL
};

/* Decision-relevant Rule attributes. */
static const char *LOGIC_ATTRIBUTES[] = {
	"role", "severity", "weight", "abstract", "hidden", NULL
};

static bool _cid_string_in_list(const char *value, const char **list)
{
	for (size_t i = 0; list[i] != NULL; ++i) {
		if (strcmp(value, list[i]) == 0)
			return true;
	}
	return false;
}

static bool _cid_is_logic_child(xmlNodePtr node)
{
	return node->type == XML_ELEMENT_NODE
		&& _cid_string_in_list((const char *) node->name, LOGIC_CHILDREN);
}

/**
 * Build a DOM containing only the decision-relevant parts of a rule:
 * a synthetic rule shell carrying the decision attributes and only the
 * logic child subtrees.  The caller frees the returned document.
 */
static xmlDocPtr _cid_logic_shell(xmlNodePtr rule_node)
{
	xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
	if (doc == NULL)
		return NULL;
	xmlNodePtr shell = xmlNewDocNode(doc, rule_node->ns, BAD_CAST "Rule", NULL);
	if (shell == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}
	xmlDocSetRootElement(doc, shell);

	for (xmlAttrPtr attr = rule_node->properties; attr != NULL; attr = attr->next) {
		if (attr->name == NULL)
			continue;
		if (_cid_string_in_list((const char *) attr->name, LOGIC_ATTRIBUTES))
			xmlCopyProp(shell, attr);
	}
	for (xmlNodePtr child = rule_node->children; child != NULL; child = child->next) {
		if (_cid_is_logic_child(child)) {
			xmlNodePtr copy = xmlCopyNode(child, 1);
			if (copy != NULL)
				xmlAddChild(shell, copy);
		}
	}
	return doc;
}

static char *cid_logic_digest_node(xmlNodePtr rule_node)
{
	xmlDocPtr shell = _cid_logic_shell(rule_node);
	if (shell == NULL)
		return NULL;
	char *digest = cid_digest_node(xmlDocGetRootElement(shell));
	xmlFreeDoc(shell);
	return digest;
}

/** Ancestor Group ids from the benchmark root down to the rule. */
static char *cid_group_path(struct xccdf_item *rule)
{
	/* collect ancestor groups, nearest ancestor first */
	const char *ids[1024];
	size_t n = 0;
	for (struct xccdf_item *cur = xccdf_item_get_parent(rule);
			cur != NULL && n < 1024;
			cur = xccdf_item_get_parent(cur)) {
		if (xccdf_item_get_type(cur) != XCCDF_GROUP)
			continue;
		const char *id = xccdf_item_get_id(cur);
		if (id != NULL)
			ids[n++] = id;
	}
	if (n == 0)
		return NULL;

	size_t total = 0;
	for (size_t i = 0; i < n; ++i)
		total += strlen(ids[i]) + 1;
	char *path = calloc(1, total + 1);
	if (path == NULL)
		return NULL;

	/* reverse: root-first order */
	for (size_t i = n; i > 0; --i) {
		if (i != n)
			strcat(path, "/");
		strcat(path, ids[i - 1]);
	}
	return path;
}

/** Sorted, de-duplicated "href#name" lines of all check-content-refs. */
static int cid_strcmp_qsort(const void *a, const void *b)
{
	return strcmp(*(const char * const *) a, *(const char * const *) b);
}

static char *cid_check_refs(struct xccdf_rule *rule)
{
	size_t capacity = 8;
	size_t n = 0;
	char **arr = malloc(capacity * sizeof(char *));
	if (arr == NULL)
		return NULL;

	struct xccdf_check_iterator *checks = xccdf_rule_get_checks(rule);
	while (xccdf_check_iterator_has_more(checks)) {
		struct xccdf_check *check = xccdf_check_iterator_next(checks);
		struct xccdf_check_content_ref_iterator *refs_it = xccdf_check_get_content_refs(check);
		while (xccdf_check_content_ref_iterator_has_more(refs_it)) {
			struct xccdf_check_content_ref *ref = xccdf_check_content_ref_iterator_next(refs_it);
			const char *href = xccdf_check_content_ref_get_href(ref);
			const char *name = xccdf_check_content_ref_get_name(ref);
			if (n == capacity) {
				capacity *= 2;
				char **grown = realloc(arr, capacity * sizeof(char *));
				if (grown == NULL)
					goto fail;
				arr = grown;
			}
			arr[n++] = oscap_sprintf("%s#%s", href ? href : "", name ? name : "");
			if (arr[n - 1] == NULL)
				goto fail;
		}
		xccdf_check_content_ref_iterator_free(refs_it);
	}
	xccdf_check_iterator_free(checks);

	if (n == 0) {
		free(arr);
		return NULL;
	}

	qsort(arr, n, sizeof(char *), cid_strcmp_qsort);

	/* de-duplicate and compute size */
	size_t total = 0;
	const char *prev = NULL;
	for (size_t i = 0; i < n; ++i) {
		if (prev != NULL && strcmp(arr[i], prev) == 0)
			continue;
		total += strlen(arr[i]) + 1;
		prev = arr[i];
	}
	char *joined = calloc(1, total + 1);
	if (joined == NULL)
		goto fail;
	prev = NULL;
	bool first = true;
	for (size_t i = 0; i < n; ++i) {
		if (prev != NULL && strcmp(arr[i], prev) == 0)
			continue;
		if (!first)
			strcat(joined, "\n");
		strcat(joined, arr[i]);
		first = false;
		prev = arr[i];
	}
	for (size_t i = 0; i < n; ++i)
		free(arr[i]);
	free(arr);
	return joined;

fail:
	for (size_t i = 0; i < n; ++i)
		free(arr[i]);
	free(arr);
	return NULL;
}

static void cid_rule_set_stable_key(struct cid_rule *cid, struct xccdf_rule *rule)
{
	/* check_refs is always populated when present; it is a matching key
	 * independent of which basis the primary stable_key uses. */
	cid->check_refs = cid_check_refs(rule);

	const char *cluster = xccdf_item_get_cluster_id(XITEM(rule));
	if (cluster != NULL && cluster[0] != '\0') {
		cid->key_basis = oscap_strdup("cluster");
		cid->stable_key = oscap_sprintf("cluster:%s", cluster);
		return;
	}
	if (cid->check_refs != NULL) {
		cid->key_basis = oscap_strdup("check-ref");
		cid->stable_key = oscap_sprintf("check-ref:%s", cid->check_refs);
		return;
	}
	cid->key_basis = oscap_strdup("id");
	cid->stable_key = oscap_sprintf("id:%s", xccdf_item_get_id(XITEM(rule)));
}

/** Map rule id -> original DOM node via XPath. */
static xmlXPathObjectPtr cid_xpath_rules(xmlDocPtr doc)
{
	xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
	if (ctx == NULL)
		return NULL;
	xmlXPathRegisterNs(ctx, BAD_CAST "xccdf",
		BAD_CAST "http://checklists.nist.gov/xccdf/1.2");
	/* 1.1 namespace as well, in case of older content */
	xmlXPathObjectPtr obj = xmlXPathEvalExpression(
		BAD_CAST "//xccdf:Rule | //*[local-name()='Rule']", ctx);
	xmlXPathFreeContext(ctx);
	return obj;
}

static xmlNodePtr cid_find_rule_node(xmlXPathObjectPtr obj, const char *id)
{
	if (obj == NULL || obj->nodesetval == NULL || id == NULL)
		return NULL;
	for (int i = 0; i < obj->nodesetval->nodeNr; ++i) {
		xmlNodePtr node = obj->nodesetval->nodeTab[i];
		xmlChar *node_id = xmlGetProp(node, BAD_CAST "id");
		if (node_id != NULL && strcmp((char *) node_id, id) == 0) {
			xmlFree(node_id);
			return node;
		}
		xmlFree(node_id);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Identity build                                                     */
/* ------------------------------------------------------------------ */

static bool cid_rule_is_customized(struct xccdf_policy *policy, struct xccdf_rule *rule)
{
	const char *id = xccdf_item_get_id(XITEM(rule));
	if (id == NULL)
		return false;
	struct xccdf_profile *profile = xccdf_policy_get_profile(policy);
	if (profile == NULL || !xccdf_profile_get_tailoring(profile))
		return false;

	struct xccdf_select_iterator *sel = xccdf_profile_get_selects(profile);
	while (xccdf_select_iterator_has_more(sel)) {
		struct xccdf_select *select = xccdf_select_iterator_next(sel);
		const char *item = xccdf_select_get_item(select);
		if (item != NULL && strcmp(item, id) == 0) {
			xccdf_select_iterator_free(sel);
			return true;
		}
	}
	xccdf_select_iterator_free(sel);

	struct xccdf_refine_rule_iterator *rr = xccdf_profile_get_refine_rules(profile);
	while (xccdf_refine_rule_iterator_has_more(rr)) {
		struct xccdf_refine_rule *refine = xccdf_refine_rule_iterator_next(rr);
		const char *item = xccdf_refine_rule_get_item(refine);
		if (item != NULL && strcmp(item, id) == 0) {
			xccdf_refine_rule_iterator_free(rr);
			return true;
		}
	}
	xccdf_refine_rule_iterator_free(rr);
	return false;
}

/** Recursively build a cid_rule for every rule under an item list. */
static void cid_collect_rules_from(struct cid_identity *identity, struct xccdf_policy *policy,
		struct xccdf_item *parent, xmlXPathObjectPtr rule_nodes)
{
	struct oscap_list *content;
	switch (xccdf_item_get_type(parent)) {
	case XCCDF_BENCHMARK:
		content = XITEM(parent)->sub.benchmark.content;
		break;
	case XCCDF_GROUP:
		content = XITEM(parent)->sub.group.content;
		break;
	default:
		return;
	}

	struct oscap_iterator *it = oscap_iterator_new(content);
	while (oscap_iterator_has_more(it)) {
		struct xccdf_item *item = oscap_iterator_next(it);
		if (xccdf_item_get_type(item) == XCCDF_GROUP) {
			cid_collect_rules_from(identity, policy, item, rule_nodes);
			continue;
		}
		if (xccdf_item_get_type(item) != XCCDF_RULE)
			continue;

		struct xccdf_rule *rule = (struct xccdf_rule *) item;
		struct cid_rule *cid = cid_rule_new();
		if (cid == NULL)
			continue;

		const char *id = xccdf_item_get_id(item);
		cid->id = oscap_strdup(id);
		cid->cluster_id = oscap_strdup(xccdf_item_get_cluster_id(item));
		cid->author_version = oscap_strdup(xccdf_item_get_version(item));
		cid->group_path = cid_group_path(item);
		cid->selected = xccdf_policy_is_item_selected(policy, id);
		cid->customized = cid_rule_is_customized(policy, rule);
		cid_rule_set_stable_key(cid, rule);

		xmlNodePtr rule_node = cid_find_rule_node(rule_nodes, id);
		if (rule_node != NULL) {
			cid->body_digest = cid_body_digest_rule(rule_node);
			cid->logic_digest = cid_logic_digest_node(rule_node);
		}
		oscap_list_add(identity->rules, cid);
	}
	oscap_iterator_free(it);
}

static void cid_collect_rules(struct cid_identity *identity, struct xccdf_policy *policy,
		struct xccdf_benchmark *benchmark, xmlXPathObjectPtr rule_nodes)
{
	cid_collect_rules_from(identity, policy, XITEM(benchmark), rule_nodes);
}

static int cid_add_source_components(struct cid_identity *identity,
		struct oscap_source **sources, size_t count, const char *type)
{
	for (size_t i = 0; i < count; ++i) {
		char *digest = cid_digest_source(sources[i]);
		if (digest == NULL)
			continue;
		struct cid_component *component = cid_component_new(
			oscap_source_readable_origin(sources[i]), type, digest);
		free(digest);
		if (component == NULL)
			return -1;
		oscap_list_add(identity->components, component);
	}
	return 0;
}

static int cid_collect_tailoring(struct cid_identity *identity,
		struct xccdf_session *session, struct xccdf_policy *policy,
		const char *benchmark_digest)
{
	struct xccdf_profile *profile = xccdf_policy_get_profile(policy);
	if (profile == NULL || !xccdf_profile_get_tailoring(profile))
		return 0;

	struct cid_tailoring *tailoring = cid_tailoring_new();
	if (tailoring == NULL)
		return -1;
	tailoring->profile_id = oscap_strdup(xccdf_session_get_profile_id(session));
	tailoring->benchmark_digest = oscap_strdup(benchmark_digest);

	struct oscap_source *tail_src = cid_session_get_tailoring_source(session);
	if (tail_src != NULL) {
		tailoring->origin = oscap_strdup(oscap_source_readable_origin(tail_src));
		tailoring->digest = cid_digest_source(tail_src);
	}

	struct xccdf_select_iterator *sel = xccdf_profile_get_selects(profile);
	while (xccdf_select_iterator_has_more(sel)) {
		struct xccdf_select *select = xccdf_select_iterator_next(sel);
		struct cid_tailoring_entry *entry = cid_tailoring_entry_new("select",
			xccdf_select_get_item(select),
			xccdf_select_get_selected(select) ? "true" : "false");
		if (entry != NULL)
			oscap_list_add(tailoring->entries, entry);
	}
	xccdf_select_iterator_free(sel);

	struct xccdf_setvalue_iterator *sv = xccdf_profile_get_setvalues(profile);
	while (xccdf_setvalue_iterator_has_more(sv)) {
		struct xccdf_setvalue *setvalue = xccdf_setvalue_iterator_next(sv);
		struct cid_tailoring_entry *entry = cid_tailoring_entry_new("set-value",
			xccdf_setvalue_get_item(setvalue),
			xccdf_setvalue_get_value(setvalue));
		if (entry != NULL)
			oscap_list_add(tailoring->entries, entry);
	}
	xccdf_setvalue_iterator_free(sv);

	struct xccdf_refine_rule_iterator *rr = xccdf_profile_get_refine_rules(profile);
	while (xccdf_refine_rule_iterator_has_more(rr)) {
		struct xccdf_refine_rule *refine = xccdf_refine_rule_iterator_next(rr);
		char payload[256];
		const char *selector = xccdf_refine_rule_get_selector(refine);
		snprintf(payload, sizeof(payload), "selector=%s;role=%d;severity=%d;weight=%f",
			selector ? selector : "",
			(int) xccdf_refine_rule_get_role(refine),
			(int) xccdf_refine_rule_get_severity(refine),
			xccdf_refine_rule_get_weight(refine));
		struct cid_tailoring_entry *entry = cid_tailoring_entry_new("refine-rule",
			xccdf_refine_rule_get_item(refine), payload);
		if (entry != NULL)
			oscap_list_add(tailoring->entries, entry);
	}
	xccdf_refine_rule_iterator_free(rr);

	identity->tailoring = tailoring;
	return 0;
}

struct cid_identity *cid_identity_build_for_session(struct xccdf_session *session)
{
	struct cid_identity *identity = cid_identity_new();
	if (identity == NULL)
		return NULL;

	struct xccdf_policy *policy = xccdf_session_get_xccdf_policy(session);
	if (policy == NULL) {
		cid_identity_free(identity);
		return NULL;
	}
	struct xccdf_benchmark *benchmark = xccdf_policy_get_benchmark(policy);
	if (benchmark == NULL) {
		cid_identity_free(identity);
		return NULL;
	}

	/* XCCDF benchmark component */
	struct oscap_source *xccdf_src = cid_session_get_xccdf_source(session);
	char *benchmark_digest = cid_digest_source(xccdf_src);
	if (benchmark_digest != NULL) {
		struct cid_component *component = cid_component_new(
			oscap_source_readable_origin(xccdf_src), "xccdf", benchmark_digest);
		if (component != NULL)
			oscap_list_add(identity->components, component);
	}

	/* OVAL and CPE components actually participating */
	size_t oval_count = 0, cpe_count = 0;
	struct oscap_source **oval_sources = cid_session_get_oval_sources(session, &oval_count);
	cid_add_source_components(identity, oval_sources, oval_count, "oval");
	free(oval_sources);
	struct oscap_source **cpe_sources = cid_session_get_cpe_sources(session, &cpe_count);
	cid_add_source_components(identity, cpe_sources, cpe_count, "cpe");
	free(cpe_sources);

	/* tailoring */
	cid_collect_tailoring(identity, session, policy, benchmark_digest);

	/* per-rule identity over the original benchmark DOM */
	xmlDocPtr bench_doc = xccdf_src != NULL ? oscap_source_get_xmlDoc(xccdf_src) : NULL;
	xmlXPathObjectPtr rule_nodes = bench_doc != NULL ? cid_xpath_rules(bench_doc) : NULL;

	cid_collect_rules(identity, policy, benchmark, rule_nodes);

	if (rule_nodes != NULL)
		xmlXPathFreeObject(rule_nodes);

	free(benchmark_digest);
	return identity;
}

/* ------------------------------------------------------------------ */
/* DOM emission                                                       */
/* ------------------------------------------------------------------ */

static xmlNodePtr cid_new_child(xmlNodePtr parent, xmlDocPtr doc, const char *name)
{
	xmlNodePtr node = xmlNewNode(NULL, BAD_CAST name);
	if (node == NULL)
		return NULL;
	xmlAddChild(parent, node);
	(void) doc;
	return node;
}

static void cid_new_prop(xmlNodePtr node, const char *name, const char *value)
{
	if (value != NULL)
		xmlNewProp(node, BAD_CAST name, BAD_CAST value);
}

int cid_identity_attach_dom(const struct cid_identity *identity, xmlNodePtr result_node, xmlDocPtr doc)
{
	if (identity == NULL || result_node == NULL || doc == NULL)
		return -1;

	xmlNsPtr ns = xmlSearchNsByHref(doc, result_node, BAD_CAST XCCDF_CID_NS_URI);
	if (ns == NULL) {
		ns = xmlNewNs(result_node, BAD_CAST XCCDF_CID_NS_URI, BAD_CAST XCCDF_CID_NS_PREFIX);
		if (ns == NULL)
			return -1;
	}

	/* XCCDF 1.2 TestResult extension slot: metadata after score. */
	xmlNodePtr metadata = xmlNewNode(NULL, BAD_CAST "metadata");
	if (metadata == NULL)
		return -1;
	/* The wrapper element itself belongs to the XCCDF namespace; only its
	 * children live in the foreign cid namespace (xsd:any ##other). */
	xmlNsPtr xccdf_ns = xmlSearchNsByHref(doc, result_node,
		BAD_CAST "http://checklists.nist.gov/xccdf/1.2");
	if (xccdf_ns == NULL)
		xccdf_ns = xmlSearchNsByHref(doc, result_node,
			BAD_CAST "http://checklists.nist.gov/xccdf/1.1");
	if (xccdf_ns != NULL)
		xmlSetNs(metadata, xccdf_ns);
	xmlAddChild(result_node, metadata);

	xmlNodePtr root = cid_new_child(metadata, doc, "content-identity");
	if (root == NULL)
		return -1;
	xmlSetNs(root, ns);
	cid_new_prop(root, "algorithm", identity->algorithm);
	cid_new_prop(root, "canonicalization", identity->canonicalization);

	struct oscap_iterator *cit = oscap_iterator_new(identity->components);
	while (oscap_iterator_has_more(cit)) {
		struct cid_component *component = oscap_iterator_next(cit);
		xmlNodePtr node = cid_new_child(root, doc, "component");
		if (node == NULL)
			return -1;
		xmlSetNs(node, ns);
		cid_new_prop(node, "origin", component->origin);
		cid_new_prop(node, "content-type", component->content_type);
		cid_new_prop(node, "digest", component->digest);
	}
	oscap_iterator_free(cit);

	if (identity->tailoring != NULL) {
		struct cid_tailoring *tail = identity->tailoring;
		xmlNodePtr node = cid_new_child(root, doc, "tailoring");
		if (node == NULL)
			return -1;
		xmlSetNs(node, ns);
		cid_new_prop(node, "origin", tail->origin);
		cid_new_prop(node, "digest", tail->digest);
		cid_new_prop(node, "profile-id", tail->profile_id);
		cid_new_prop(node, "benchmark-digest", tail->benchmark_digest);

		struct oscap_iterator *eit = oscap_iterator_new(tail->entries);
		while (oscap_iterator_has_more(eit)) {
			struct cid_tailoring_entry *entry = oscap_iterator_next(eit);
			xmlNodePtr enode = cid_new_child(node, doc, "tailoring-entry");
			if (enode == NULL)
				return -1;
			xmlSetNs(enode, ns);
			cid_new_prop(enode, "kind", entry->kind);
			cid_new_prop(enode, "idref", entry->idref);
			cid_new_prop(enode, "value", entry->value);
		}
		oscap_iterator_free(eit);
	}

	xmlNodePtr rules = cid_new_child(root, doc, "rules");
	if (rules == NULL)
		return -1;
	xmlSetNs(rules, ns);
	struct oscap_iterator *rit = oscap_iterator_new(identity->rules);
	while (oscap_iterator_has_more(rit)) {
		struct cid_rule *rule = oscap_iterator_next(rit);
		xmlNodePtr node = cid_new_child(rules, doc, "rule");
		if (node == NULL)
			return -1;
		xmlSetNs(node, ns);
		cid_new_prop(node, "id", rule->id);
		cid_new_prop(node, "cluster-id", rule->cluster_id);
		cid_new_prop(node, "stable-key", rule->stable_key);
		cid_new_prop(node, "key-basis", rule->key_basis);
		cid_new_prop(node, "group-path", rule->group_path);
		cid_new_prop(node, "body-digest", rule->body_digest);
		cid_new_prop(node, "logic-digest", rule->logic_digest);
		cid_new_prop(node, "author-version", rule->author_version);
		cid_new_prop(node, "check-refs", rule->check_refs);
		cid_new_prop(node, "selected", rule->selected ? "true" : "false");
		cid_new_prop(node, "customized", rule->customized ? "true" : "false");
	}
	oscap_iterator_free(rit);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Parsing                                                            */
/* ------------------------------------------------------------------ */

xmlNodePtr cid_find_test_result(xmlDocPtr doc)
{
	if (doc == NULL)
		return NULL;
	xmlNodePtr root = xmlDocGetRootElement(doc);
	if (root == NULL)
		return NULL;
	if (xmlStrcmp(root->name, BAD_CAST "TestResult") == 0)
		return root;

	xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
	if (ctx == NULL)
		return NULL;
	xmlXPathObjectPtr obj = xmlXPathEvalExpression(
		BAD_CAST "//*[local-name()='TestResult'][1]", ctx);
	xmlXPathFreeContext(ctx);
	if (obj == NULL || obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
		if (obj != NULL)
			xmlXPathFreeObject(obj);
		return NULL;
	}
	xmlNodePtr found = obj->nodesetval->nodeTab[0];
	xmlXPathFreeObject(obj);
	return found;
}

static char *cid_prop(xmlNodePtr node, const char *name)
{
	xmlChar *value = xmlGetProp(node, BAD_CAST name);
	if (value == NULL)
		return NULL;
	char *copy = oscap_strdup((char *) value);
	xmlFree(value);
	return copy;
}

static bool cid_is_cid_node(xmlNodePtr node)
{
	return node != NULL && node->type == XML_ELEMENT_NODE
		&& node->ns != NULL && node->ns->href != NULL
		&& xmlStrcmp(node->ns->href, BAD_CAST XCCDF_CID_NS_URI) == 0;
}

static xmlNodePtr cid_child(xmlNodePtr parent, const char *name)
{
	for (xmlNodePtr child = parent->children; child != NULL; child = child->next) {
		if (cid_is_cid_node(child) && xmlStrcmp(child->name, BAD_CAST name) == 0)
			return child;
	}
	return NULL;
}

struct cid_identity *cid_identity_parse_from_doc(xmlDocPtr doc)
{
	xmlNodePtr test_result = cid_find_test_result(doc);
	if (test_result == NULL)
		return NULL;

	xmlNodePtr metadata = NULL;
	for (xmlNodePtr child = test_result->children; child != NULL; child = child->next) {
		if (child->type != XML_ELEMENT_NODE)
			continue;
		if (xmlStrcmp(child->name, BAD_CAST "metadata") != 0)
			continue;
		xmlNodePtr root = cid_child(child, "content-identity");
		if (root != NULL) {
			metadata = root;
			break;
		}
	}
	if (metadata == NULL)
		return NULL;

	struct cid_identity *identity = cid_identity_new();
	if (identity == NULL)
		return NULL;
	free(identity->algorithm);
	free(identity->canonicalization);
	identity->algorithm = cid_prop(metadata, "algorithm");
	identity->canonicalization = cid_prop(metadata, "canonicalization");

	for (xmlNodePtr child = metadata->children; child != NULL; child = child->next) {
		if (!cid_is_cid_node(child))
			continue;
		if (xmlStrcmp(child->name, BAD_CAST "component") == 0) {
			char *origin = cid_prop(child, "origin");
			char *ctype = cid_prop(child, "content-type");
			char *digest = cid_prop(child, "digest");
			struct cid_component *component = cid_component_new(origin, ctype, digest);
			free(origin);
			free(ctype);
			free(digest);
			if (component != NULL)
				oscap_list_add(identity->components, component);
		} else if (xmlStrcmp(child->name, BAD_CAST "tailoring") == 0) {
			struct cid_tailoring *tail = cid_tailoring_new();
			tail->origin = cid_prop(child, "origin");
			tail->digest = cid_prop(child, "digest");
			tail->profile_id = cid_prop(child, "profile-id");
			tail->benchmark_digest = cid_prop(child, "benchmark-digest");
			for (xmlNodePtr e = child->children; e != NULL; e = e->next) {
				if (!cid_is_cid_node(e))
					continue;
				char *kind = cid_prop(e, "kind");
				char *idref = cid_prop(e, "idref");
				char *value = cid_prop(e, "value");
				struct cid_tailoring_entry *entry = cid_tailoring_entry_new(kind, idref, value);
				free(kind);
				free(idref);
				free(value);
				if (entry != NULL)
					oscap_list_add(tail->entries, entry);
			}
			identity->tailoring = tail;
		} else if (xmlStrcmp(child->name, BAD_CAST "rules") == 0) {
			for (xmlNodePtr r = child->children; r != NULL; r = r->next) {
				if (!cid_is_cid_node(r))
					continue;
				struct cid_rule *rule = cid_rule_new();
				rule->id = cid_prop(r, "id");
				rule->cluster_id = cid_prop(r, "cluster-id");
				rule->stable_key = cid_prop(r, "stable-key");
				rule->key_basis = cid_prop(r, "key-basis");
				rule->group_path = cid_prop(r, "group-path");
				rule->body_digest = cid_prop(r, "body-digest");
				rule->logic_digest = cid_prop(r, "logic-digest");
				rule->author_version = cid_prop(r, "author-version");
				rule->check_refs = cid_prop(r, "check-refs");
				xmlChar *sel = xmlGetProp(r, BAD_CAST "selected");
				rule->selected = sel != NULL && xmlStrcmp(sel, BAD_CAST "true") == 0;
				if (sel != NULL)
					xmlFree(sel);
				xmlChar *cust = xmlGetProp(r, BAD_CAST "customized");
				rule->customized = cust != NULL && xmlStrcmp(cust, BAD_CAST "true") == 0;
				if (cust != NULL)
					xmlFree(cust);
				oscap_list_add(identity->rules, rule);
			}
		}
	}
	return identity;
}
