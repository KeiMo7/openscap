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

/*
 * Host identity resolution and merging of XCCDF TestResults collected from
 * one or more (possibly remote) machines.
 *
 * Design notes
 * ------------
 * - Host identity is resolved by a single function, _resolve_host_identity().
 *   It reads only the XCCDF result metadata (target, target-address and
 *   target-facts), which is exactly the vocabulary that the evaluation writes
 *   through xccdf_result_fill_sysinfo().  The merger, the exported merged
 *   document and anything that reads that document (reports) therefore share
 *   one resolution rule; none of them computes its own variant.
 * - The merger is a pure accumulator.  It never mutates any input; every
 *   record is cloned before it is stored.
 * - Output must be byte-identical regardless of the order in which files (or
 *   records within files) were added and regardless of how the batch was
 *   split.  Therefore:
 *     * records are fully sorted before grouping,
 *     * grouping is a deterministic bucketing by identity token,
 *     * every list in the output is produced in a sorted order,
 *     * duplicate rule results are collapsed with a stable rule and the time
 *       series is carried in the merged record,
 *     * the per-scan history and the counters are written into the merged
 *       TestResult as target facts, so a second merge of the output carries
 *       exactly the same information forward.
 * - Identity conflicts (one identity key pointing at two mutually
 *   incompatible machine fingerprints) do not silently pick a winner: the
 *   records are kept as separate hosts and flagged.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "public/xccdf_result_merge.h"
#include "public/xccdf_benchmark.h"

#include "common/_error.h"
#include "common/debug_priv.h"
#include "common/list.h"
#include "common/util.h"
#include "common/public/oscap_text.h"
#include "oscap_helpers.h"
#include "source/public/oscap_source.h"
#include "source/oscap_source_priv.h"
#include "DS/public/ds_rds_session.h"
#include "DS/public/scap_ds.h"
#include "item.h"
#include "xccdf_impl.h"

/* Fact names used by the identity resolver. */
#define FACT_STABLE_EIN "urn:xccdf:fact:asset:identifier:ein"
#define FACT_STABLE_ID "urn:xccdf:fact:identifier"
#define FACT_HOST_ID "urn:xccdf:fact:asset:identifier:host_id"
#define FACT_HOST_ID_SOURCE "urn:xccdf:fact:asset:identifier:host_id_source"
#define FACT_HOST_ID_CONFLICT "urn:xccdf:fact:asset:identifier:host_id_conflict"
#define FACT_FQDN "urn:xccdf:fact:asset:identifier:fqdn"
#define FACT_HOST_NAME "urn:xccdf:fact:asset:identifier:host_name"
#define FACT_MAC "urn:xccdf:fact:asset:identifier:mac"
#define FACT_ETHERNET_MAC "urn:xccdf:fact:ethernet:MAC"
#define FACT_SCANNER_NAME "urn:xccdf:fact:scanner:name"
#define FACT_SCANNER_VERSION "urn:xccdf:fact:scanner:version"
#define FACT_SCAN_HISTORY "urn:openscap:fact:host:scan"

/* Merged record bookkeeping facts. */
#define FACT_SCAN_COUNT "urn:openscap:fact:host:scan_count"
#define FACT_RULE_COUNT "urn:openscap:fact:host:rule_count"
#define FACT_PASS_COUNT "urn:openscap:fact:host:pass_count"
#define FACT_FAIL_COUNT "urn:openscap:fact:host:fail_count"
#define FACT_ERROR_COUNT "urn:openscap:fact:host:error_count"
#define FACT_UNKNOWN_COUNT "urn:openscap:fact:host:unknown_count"

#define HOST_UNKNOWN_TOKEN "unknown"
#define HOST_UNKNOWN_DISPLAY "Unknown host"
#define MERGE_HISTORY_MARKER "[merge-history] "
#define MERGED_BENCHMARK_ID "xccdf_org.open-scap_benchmark_merged_results"
#define MERGED_BENCHMARK_VERSION "1.0"
#define DEFAULT_SCORING_SYSTEM "urn:xccdf:scoring:default"

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

struct _string_list {
	char **items;
	size_t count;
	size_t capacity;
};

static void _string_list_init(struct _string_list *list)
{
	list->items = NULL;
	list->count = 0;
	list->capacity = 0;
}

static bool _string_list_contains(const struct _string_list *list, const char *value)
{
	for (size_t i = 0; i < list->count; ++i)
		if (oscap_streq(list->items[i], value))
			return true;
	return false;
}

static void _string_list_add_uniq(struct _string_list *list, const char *value)
{
	if (value == NULL || value[0] == '\0')
		return;
	if (_string_list_contains(list, value))
		return;
	if (list->count == list->capacity) {
		size_t new_capacity = list->capacity == 0 ? 4 : list->capacity * 2;
		char **new_items = realloc(list->items, new_capacity * sizeof(char *));
		if (new_items == NULL)
			return;
		list->items = new_items;
		list->capacity = new_capacity;
	}
	list->items[list->count++] = oscap_strdup(value);
}

static void _string_list_free(struct _string_list *list)
{
	for (size_t i = 0; i < list->count; ++i)
		free(list->items[i]);
	free(list->items);
	_string_list_init(list);
}

static int _string_cmp(const void *a, const void *b)
{
	const char *sa = *(const char * const *)a;
	const char *sb = *(const char * const *)b;
	if (sa == NULL && sb == NULL) return 0;
	if (sa == NULL) return -1;
	if (sb == NULL) return 1;
	return strcmp(sa, sb);
}

/* Sort and remove duplicates.  Deterministic and independent of input order. */
static void _string_list_sort_uniq(struct _string_list *list)
{
	if (list->count < 2) {
		if (list->count == 1 && list->items[0] == NULL) {
			free(list->items[0]);
			list->items[0] = NULL;
			list->count = 0;
		}
		return;
	}
	qsort(list->items, list->count, sizeof(char *), _string_cmp);
	size_t out = 1;
	for (size_t i = 1; i < list->count; ++i) {
		if (list->items[i] == NULL || oscap_streq(list->items[i], list->items[out - 1]))
			free(list->items[i]);
		else
			list->items[out++] = list->items[i];
	}
	list->count = out;
}

/* A canonical, lower-cased short host name: strips the domain part so that
 * "web1", "web1.example.com" and "WEB1.example.com" all resolve to "web1". */
static char *_host_short_name(const char *name)
{
	if (name == NULL)
		return NULL;
	size_t len = strcspn(name, ".");
	if (len == 0)
		len = strlen(name);
	char *ret = malloc(len + 1);
	if (ret == NULL)
		return NULL;
	for (size_t i = 0; i < len; ++i)
		ret[i] = (char)tolower((unsigned char)name[i]);
	ret[len] = '\0';
	return ret;
}

static bool _looks_like_address(const char *value)
{
	if (value == NULL || value[0] == '\0')
		return false;
	/* IPv4 (digits and dots), IPv6 and MAC addresses (hex digits and
	 * colons/dashes). */
	bool only_digits_dots = true;
	for (const char *p = value; *p; ++p) {
		if (*p == ':')
			return true;
		if (!isdigit((unsigned char)*p) && *p != '.')
			only_digits_dots = false;
	}
	return only_digits_dots && strchr(value, '.') != NULL;
}

struct _string_builder {
	char *data;
	size_t length;
	size_t capacity;
};

static void _sb_init(struct _string_builder *sb)
{
	sb->data = NULL;
	sb->length = 0;
	sb->capacity = 0;
}

static void _sb_append(struct _string_builder *sb, const char *text)
{
	if (text == NULL)
		return;
	size_t len = strlen(text);
	if (sb->length + len + 1 > sb->capacity) {
		size_t new_capacity = sb->capacity == 0 ? 256 : sb->capacity;
		while (sb->length + len + 1 > new_capacity)
			new_capacity *= 2;
		char *new_data = realloc(sb->data, new_capacity);
		if (new_data == NULL)
			return;
		sb->data = new_data;
		sb->capacity = new_capacity;
	}
	memcpy(sb->data + sb->length, text, len + 1);
	sb->length += len;
}

static char *_sb_steal(struct _string_builder *sb)
{
	char *ret = sb->data != NULL ? sb->data : oscap_strdup("");
	sb->data = NULL;
	sb->length = 0;
	sb->capacity = 0;
	return ret;
}

/* ------------------------------------------------------------------ */
/* Host identity resolution                                           */
/* ------------------------------------------------------------------ */

const char *xccdf_host_identity_source_to_string(xccdf_host_identity_source_t source)
{
	switch (source) {
	case XCCDF_HOST_IDENTITY_STABLE:
		return "stable";
	case XCCDF_HOST_IDENTITY_HOSTNAME:
		return "hostname";
	case XCCDF_HOST_IDENTITY_ADDRESS:
		return "address";
	case XCCDF_HOST_IDENTITY_UNKNOWN:
	default:
		return "unknown";
	}
}

static xccdf_host_identity_source_t _source_from_token(const char *token)
{
	if (token == NULL)
		return XCCDF_HOST_IDENTITY_UNKNOWN;
	if (oscap_str_startswith(token, "stable:"))
		return XCCDF_HOST_IDENTITY_STABLE;
	if (oscap_str_startswith(token, "hostname:"))
		return XCCDF_HOST_IDENTITY_HOSTNAME;
	if (oscap_str_startswith(token, "address:"))
		return XCCDF_HOST_IDENTITY_ADDRESS;
	return XCCDF_HOST_IDENTITY_UNKNOWN;
}

/* All owned. */
struct _host_identity_view {
	xccdf_host_identity_source_t source;
	char *canonical_token;   /* may be NULL when unresolved */
	char *stable_id;
	char *fqdn;
	char *host_name;
	char *display_name;
	struct _string_list names;      /* all known names (target + facts) */
	struct _string_list addresses;
	struct _string_list macs;
	struct _string_list scanner;    /* scanner name values */
	struct _string_list scanner_versions;
	struct _string_list scan_history; /* carried scan entries, if any */
};

static void _host_identity_view_init(struct _host_identity_view *view)
{
	memset(view, 0, sizeof(*view));
	view->source = XCCDF_HOST_IDENTITY_UNKNOWN;
	_string_list_init(&view->names);
	_string_list_init(&view->addresses);
	_string_list_init(&view->macs);
	_string_list_init(&view->scanner);
	_string_list_init(&view->scanner_versions);
	_string_list_init(&view->scan_history);
}

static void _host_identity_view_free(struct _host_identity_view *view)
{
	free(view->canonical_token);
	free(view->stable_id);
	free(view->fqdn);
	free(view->host_name);
	free(view->display_name);
	_string_list_free(&view->names);
	_string_list_free(&view->addresses);
	_string_list_free(&view->macs);
	_string_list_free(&view->scanner);
	_string_list_free(&view->scanner_versions);
	_string_list_free(&view->scan_history);
}

/*
 * Single source of truth for host identity resolution.
 *
 * Reads one TestResult and fills the identity view.  Priority:
 *   1. stable identifier
 *   2. host name (short name normalized)
 *   3. network address (last resort only)
 * A pre-resolved canonical token written by an earlier merge is honored
 * verbatim, which is what makes the merge idempotent.
 */
static void _resolve_host_identity(const struct xccdf_result *result, struct _host_identity_view *view)
{
	_host_identity_view_init(view);
	char *injected_token = NULL;

	struct xccdf_target_fact_iterator *facts = xccdf_result_get_target_facts(result);
	while (xccdf_target_fact_iterator_has_more(facts)) {
		struct xccdf_target_fact *fact = xccdf_target_fact_iterator_next(facts);
		const char *name = xccdf_target_fact_get_name(fact);
		const char *value = xccdf_target_fact_get_value(fact);
		if (name == NULL || value == NULL || value[0] == '\0')
			continue;
		if (oscap_streq(name, FACT_FQDN)) {
			if (view->fqdn == NULL)
				view->fqdn = oscap_strdup(value);
			_string_list_add_uniq(&view->names, value);
		} else if (oscap_streq(name, FACT_HOST_NAME)) {
			if (view->host_name == NULL)
				view->host_name = oscap_strdup(value);
			_string_list_add_uniq(&view->names, value);
		} else if (oscap_streq(name, FACT_MAC) || oscap_streq(name, FACT_ETHERNET_MAC)) {
			_string_list_add_uniq(&view->macs, value);
		} else if (oscap_streq(name, FACT_STABLE_EIN) || oscap_streq(name, FACT_STABLE_ID)) {
			if (view->stable_id == NULL)
				view->stable_id = oscap_strdup(value);
		} else if (oscap_streq(name, FACT_HOST_ID)) {
			if (injected_token == NULL)
				injected_token = oscap_strdup(value);
		} else if (oscap_streq(name, FACT_SCANNER_NAME)) {
			_string_list_add_uniq(&view->scanner, value);
		} else if (oscap_streq(name, FACT_SCANNER_VERSION)) {
			_string_list_add_uniq(&view->scanner_versions, value);
		} else if (oscap_streq(name, FACT_SCAN_HISTORY)) {
			_string_list_add_uniq(&view->scan_history, value);
		}
	}
	xccdf_target_fact_iterator_free(facts);

	struct oscap_string_iterator *targets = xccdf_result_get_targets(result);
	while (oscap_string_iterator_has_more(targets)) {
		const char *target = oscap_string_iterator_next(targets);
		_string_list_add_uniq(&view->names, target);
	}
	oscap_string_iterator_free(targets);

	struct oscap_string_iterator *addresses = xccdf_result_get_target_addresses(result);
	while (oscap_string_iterator_has_more(addresses)) {
		const char *address = oscap_string_iterator_next(addresses);
		_string_list_add_uniq(&view->addresses, address);
	}
	oscap_string_iterator_free(addresses);

	/* A token written by a previous merge is authoritative: it already
	 * encodes the resolution decision made with the full input set. */
	if (injected_token != NULL && _source_from_token(injected_token) != XCCDF_HOST_IDENTITY_UNKNOWN) {
		view->source = _source_from_token(injected_token);
		view->canonical_token = injected_token;
		injected_token = NULL;
	} else {
		free(injected_token);
	}

	if (view->canonical_token == NULL && view->stable_id != NULL &&
			!oscap_streq(view->stable_id, HOST_UNKNOWN_TOKEN)) {
		view->source = XCCDF_HOST_IDENTITY_STABLE;
		view->canonical_token = oscap_sprintf("stable:%s", view->stable_id);
	}

	if (view->canonical_token == NULL) {
		const char *name = view->fqdn != NULL ? view->fqdn : view->host_name;
		if (name == NULL) {
			for (size_t i = 0; i < view->names.count; ++i) {
				if (!_looks_like_address(view->names.items[i])) {
					name = view->names.items[i];
					break;
				}
			}
		}
		if (name != NULL && !oscap_streq(name, HOST_UNKNOWN_DISPLAY) &&
				!oscap_streq(name, HOST_UNKNOWN_TOKEN)) {
			char *short_name = _host_short_name(name);
			if (short_name != NULL && short_name[0] != '\0') {
				view->source = XCCDF_HOST_IDENTITY_HOSTNAME;
				view->canonical_token = oscap_sprintf("hostname:%s", short_name);
				free(short_name);
			} else {
				free(short_name);
			}
		}
	}

	if (view->canonical_token == NULL && view->addresses.count > 0) {
		struct _string_list copy = { NULL, 0, 0 };
		for (size_t i = 0; i < view->addresses.count; ++i)
			_string_list_add_uniq(&copy, view->addresses.items[i]);
		_string_list_sort_uniq(&copy);
		if (copy.count > 0) {
			view->source = XCCDF_HOST_IDENTITY_ADDRESS;
			view->canonical_token = oscap_sprintf("address:%s", copy.items[0]);
		}
		_string_list_free(&copy);
	}

	if (view->canonical_token == NULL) {
		view->source = XCCDF_HOST_IDENTITY_UNKNOWN;
		view->canonical_token = oscap_strdup(HOST_UNKNOWN_TOKEN);
	}

	/* Preferred display name.  It is derived from the whole set of known
	 * names (not from the order they were encountered in), so that a merged
	 * document resolves to the same display name when it is merged again.
	 * The lexicographically smallest name is used; when there is no name the
	 * identity payload is the best available label. */
	{
		struct _string_list candidates = { NULL, 0, 0 };
		for (size_t i = 0; i < view->names.count; ++i)
			if (!oscap_streq(view->names.items[i], HOST_UNKNOWN_TOKEN) &&
					!oscap_streq(view->names.items[i], HOST_UNKNOWN_DISPLAY))
				_string_list_add_uniq(&candidates, view->names.items[i]);
		_string_list_sort_uniq(&candidates);
		if (candidates.count > 0) {
			view->display_name = oscap_strdup(candidates.items[0]);
		} else if (view->source == XCCDF_HOST_IDENTITY_STABLE && view->stable_id != NULL) {
			view->display_name = oscap_strdup(view->stable_id);
		} else if (view->source == XCCDF_HOST_IDENTITY_ADDRESS) {
			view->display_name = oscap_strdup(view->canonical_token + strlen("address:"));
		} else {
			view->display_name = oscap_strdup(HOST_UNKNOWN_DISPLAY);
		}
		_string_list_free(&candidates);
	}
}

xccdf_host_identity_source_t xccdf_result_get_host_identity_source(const struct xccdf_result *result)
{
	struct _host_identity_view view;
	_resolve_host_identity(result, &view);
	xccdf_host_identity_source_t source = view.source;
	_host_identity_view_free(&view);
	return source;
}

char *xccdf_result_get_host_identity(const struct xccdf_result *result)
{
	struct _host_identity_view view;
	_resolve_host_identity(result, &view);
	char *identity = oscap_strdup(view.canonical_token);
	_host_identity_view_free(&view);
	return identity;
}

char *xccdf_result_get_host_display_name(const struct xccdf_result *result)
{
	struct _host_identity_view view;
	_resolve_host_identity(result, &view);
	char *name = oscap_strdup(view.display_name);
	_host_identity_view_free(&view);
	return name;
}

/* ------------------------------------------------------------------ */
/* Record accumulation                                                */
/* ------------------------------------------------------------------ */

struct _host_record {
	struct xccdf_result *result;   /* owned clone */
	struct _host_identity_view view;
	char *fingerprint;             /* stable ids + MACs, NULL when unknown */
	char *origin;                  /* human readable origin for diagnostics */
};

struct xccdf_result_merger {
	struct oscap_list *records;     /* of struct _host_record * */
	size_t skipped;
	bool built;
	struct xccdf_benchmark *benchmark;
	/* counters reported from the last build */
	size_t host_count;
	size_t unknown_host_count;
	size_t conflict_count;
};

struct xccdf_result_merger *xccdf_result_merger_new(void)
{
	struct xccdf_result_merger *merger = calloc(1, sizeof(struct xccdf_result_merger));
	if (merger == NULL)
		return NULL;
	merger->records = oscap_list_new();
	return merger;
}

static void _host_record_free(struct _host_record *record)
{
	if (record == NULL)
		return;
	xccdf_result_free(record->result);
	_host_identity_view_free(&record->view);
	free(record->fingerprint);
	free(record->origin);
	free(record);
}

void xccdf_result_merger_free(struct xccdf_result_merger *merger)
{
	if (merger == NULL)
		return;
	oscap_list_free(merger->records, (oscap_destruct_func) _host_record_free);
	if (merger->benchmark != NULL)
		xccdf_benchmark_free(merger->benchmark);
	free(merger);
}

size_t xccdf_result_merger_get_record_count(const struct xccdf_result_merger *merger)
{
	return merger == NULL ? 0 : (size_t)oscap_list_get_itemcount(merger->records);
}

size_t xccdf_result_merger_get_skipped_count(const struct xccdf_result_merger *merger)
{
	return merger == NULL ? 0 : merger->skipped;
}

size_t xccdf_result_merger_get_host_count(const struct xccdf_result_merger *merger)
{
	return merger == NULL ? 0 : merger->host_count;
}

size_t xccdf_result_merger_get_unknown_host_count(const struct xccdf_result_merger *merger)
{
	return merger == NULL ? 0 : merger->unknown_host_count;
}

size_t xccdf_result_merger_get_conflict_count(const struct xccdf_result_merger *merger)
{
	return merger == NULL ? 0 : merger->conflict_count;
}

/* A machine fingerprint is the set of stable identifiers plus MAC
 * addresses.  Two records with a conflicting fingerprint are two machines
 * even if a weaker identity (host name, address) happens to be equal. */
static char *_machine_fingerprint(const struct _host_identity_view *view)
{
	if (view->stable_id == NULL && view->macs.count == 0)
		return NULL;
	struct _string_list parts = { NULL, 0, 0 };
	if (view->stable_id != NULL)
		_string_list_add_uniq(&parts, view->stable_id);
	for (size_t i = 0; i < view->macs.count; ++i)
		_string_list_add_uniq(&parts, view->macs.items[i]);
	_string_list_sort_uniq(&parts);
	struct _string_builder sb;
	_sb_init(&sb);
	for (size_t i = 0; i < parts.count; ++i) {
		_sb_append(&sb, parts.items[i]);
		_sb_append(&sb, "|");
	}
	_string_list_free(&parts);
	return _sb_steal(&sb);
}

/* Deterministic record ordering: end time, id, canonical identity, origin,
 * full result serialization as the last resort. */
static int _record_cmp(const void *a, const void *b)
{
	const struct _host_record *ra = *(const struct _host_record * const *)a;
	const struct _host_record *rb = *(const struct _host_record * const *)b;

	const char *ta = xccdf_result_get_end_time(ra->result);
	const char *tb = xccdf_result_get_end_time(rb->result);
	if (ta == NULL && tb != NULL) return -1;
	if (ta != NULL && tb == NULL) return 1;
	if (ta != NULL && tb != NULL) {
		int c = strcmp(ta, tb);
		if (c != 0) return c;
	}

	const char *ia = xccdf_result_get_id(ra->result);
	const char *ib = xccdf_result_get_id(rb->result);
	if (ia == NULL && ib != NULL) return -1;
	if (ia != NULL && ib == NULL) return 1;
	if (ia != NULL && ib != NULL) {
		int c = strcmp(ia, ib);
		if (c != 0) return c;
	}

	int c = strcmp(ra->view.canonical_token, rb->view.canonical_token);
	if (c != 0) return c;

	const char *oa = ra->origin != NULL ? ra->origin : "";
	const char *ob = rb->origin != NULL ? rb->origin : "";
	c = strcmp(oa, ob);
	if (c != 0) return c;

	const char *fa = ra->fingerprint != NULL ? ra->fingerprint : "";
	const char *fb = rb->fingerprint != NULL ? rb->fingerprint : "";
	return strcmp(fa, fb);
}

static struct _host_record *_host_record_new(struct xccdf_result *result, const char *origin)
{
	struct _host_record *record = calloc(1, sizeof(struct _host_record));
	if (record == NULL)
		return NULL;
	record->result = result;
	record->origin = oscap_strdup(origin);
	_resolve_host_identity(result, &record->view);
	record->fingerprint = _machine_fingerprint(&record->view);
	return record;
}

static bool _merger_add_result(struct xccdf_result_merger *merger, struct xccdf_result *result, const char *origin)
{
	if (result == NULL || xccdf_result_get_end_time(result) == NULL) {
		merger->skipped++;
		return false;
	}
	struct xccdf_result *clone = xccdf_result_clone(result);
	struct _host_record *record = _host_record_new(clone, origin);
	if (record == NULL) {
		xccdf_result_free(clone);
		merger->skipped++;
		return false;
	}
	oscap_list_add(merger->records, record);
	merger->built = false;
	return true;
}

/* Deep-copy one element into a standalone document, carrying the namespace
 * declarations it needs from its original document. */
static xmlDoc *_clone_node_to_doc(xmlDoc *source_doc, xmlNode *node)
{
	xmlDoc *target_doc = xmlNewDoc(BAD_CAST "1.0");
	if (target_doc == NULL)
		return NULL;
	xmlDOMWrapCtxtPtr ctxt = xmlDOMWrapNewCtxt();
	xmlNodePtr copy = NULL;
	if (xmlDOMWrapCloneNode(ctxt, source_doc, node, &copy, target_doc, NULL, 1, 0) != 0
			|| copy == NULL) {
		xmlDOMWrapFreeCtxt(ctxt);
		xmlFreeDoc(target_doc);
		return NULL;
	}
	xmlDocSetRootElement(target_doc, copy);
	xmlDOMWrapReconcileNamespaces(ctxt, copy, 0);
	xmlDOMWrapFreeCtxt(ctxt);
	return target_doc;
}

static int _merger_import_xccdf_source(struct xccdf_result_merger *merger, struct oscap_source *source,
		const char *origin)
{
	xmlDoc *doc = oscap_source_get_xmlDoc(source);
	if (doc == NULL) {
		oscap_setxmlerr(xmlGetLastError());
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Could not read XML from '%s'.", origin);
		return -1;
	}
	xmlNode *root = xmlDocGetRootElement(doc);
	if (root == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "'%s' contains no XML element.", origin);
		return -1;
	}

	const bool is_benchmark = oscap_streq((const char *)root->name, "Benchmark");
	const bool is_testresult = oscap_streq((const char *)root->name, "TestResult");
	if (!is_benchmark && !is_testresult) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF,
			"Unsupported root element '%s' in '%s'. Expected Benchmark or TestResult.",
			(const char *)root->name, origin);
		return -1;
	}

	/* Walk the TestResult elements one by one so that one malformed record
	 * is skipped and reported while the rest of the file is still merged.
	 * A Benchmark carries its TestResults as direct children; a bare result
	 * document has the record at the root. */
	size_t imported = 0;
	size_t local_skipped = 0;
	for (xmlNode *candidate = is_testresult ? root : root->children;
			candidate != NULL;
			candidate = candidate->next) {
		if (!oscap_streq((const char *)candidate->name, "TestResult"))
			continue;
		/* Isolate this single record and import it independently. */
		xmlDoc *record_doc = _clone_node_to_doc(doc, candidate);
		struct oscap_source *single_source = record_doc != NULL
			? oscap_source_new_from_xmlDoc(record_doc, origin) : NULL;
		struct xccdf_result *single = single_source != NULL
			? xccdf_result_import_source(single_source) : NULL;
		if (single_source != NULL)
			oscap_source_free(single_source);
		else if (record_doc != NULL)
			xmlFreeDoc(record_doc);
		if (single != NULL) {
			const char *record_id = xccdf_result_get_id(single);
			char *record_origin = oscap_sprintf("%s#%s", origin,
				record_id != NULL ? record_id : "");
			if (_merger_add_result(merger, single, record_origin))
				imported++;
			else
				local_skipped++;
			free(record_origin);
			xccdf_result_free(single);
		} else {
			oscap_clearerr();
			local_skipped++;
		}
	}

	if (local_skipped > 0)
		fprintf(stderr, "WARNING: Skipped %zu malformed TestResult record(s) in '%s'.\n",
			local_skipped, origin);

	if (imported == 0) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF,
			"No usable TestResult element found in '%s'.", origin);
		return -1;
	}
	return 0;
}

static int _merger_import_arf_source(struct xccdf_result_merger *merger, struct oscap_source *source,
		const char *origin)
{
	struct ds_rds_session *session = ds_rds_session_new_from_source(source);
	if (session == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Could not open ARF '%s'.", origin);
		return -1;
	}
	struct rds_index *rds = ds_rds_session_get_rds_idx(session);
	if (rds == NULL) {
		ds_rds_session_free(session);
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Could not read the ARF index of '%s'.", origin);
		return -1;
	}

	size_t imported = 0;
	struct rds_report_index_iterator *report_it = rds_index_get_reports(rds);
	while (rds_report_index_iterator_has_more(report_it)) {
		struct rds_report_index *report = rds_report_index_iterator_next(report_it);
		const char *report_id = rds_report_index_get_id(report);
		struct oscap_source *report_source = ds_rds_session_select_report(session, report_id);
		if (report_source == NULL) {
			oscap_clearerr();
			merger->skipped++;
			continue;
		}
		if (oscap_source_get_scap_type(report_source) != OSCAP_DOCUMENT_XCCDF) {
			/* Not an XCCDF report (e.g. an OVAL report); simply not our
			 * input. */
			oscap_clearerr();
			continue;
		}
		char *sub_origin = oscap_sprintf("%s#%s", origin, report_id);
		if (_merger_import_xccdf_source(merger, report_source, sub_origin) == 0)
			imported++;
		else
			merger->skipped++;
		free(sub_origin);
	}
	rds_report_index_iterator_free(report_it);
	ds_rds_session_free(session);

	if (imported == 0) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "No XCCDF TestResult found in ARF '%s'.", origin);
		return -1;
	}
	return 0;
}

int xccdf_result_merger_add_source(struct xccdf_result_merger *merger, struct oscap_source *source)
{
	if (merger == NULL || source == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Cannot add a NULL source to the result merger.");
		return -1;
	}
	const char *readable = oscap_source_readable_origin(source);
	const char *origin = readable != NULL ? readable : "<memory>";

	int ret;
	switch (oscap_source_get_scap_type(source)) {
	case OSCAP_DOCUMENT_ARF:
		ret = _merger_import_arf_source(merger, source, origin);
		break;
	case OSCAP_DOCUMENT_XCCDF:
	default:
		/* XCCDF results and Benchmarks, including a bare TestResult whose
		 * document type is the same XCCDF family. */
		ret = _merger_import_xccdf_source(merger, source, origin);
		break;
	}
	if (ret == 0)
		merger->built = false;
	return ret;
}

int xccdf_result_merger_add_file(struct xccdf_result_merger *merger, const char *filepath)
{
	if (merger == NULL || filepath == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Cannot add a NULL path to the result merger.");
		return -1;
	}
	struct oscap_source *source = oscap_source_new_from_file(filepath);
	if (source == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Could not open '%s'.", filepath);
		return -1;
	}
	int ret = xccdf_result_merger_add_source(merger, source);
	oscap_source_free(source);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Output construction                                                */
/* ------------------------------------------------------------------ */

struct _fact_pair {
	char *name;
	char *value;
};

static int _fact_pair_cmp(const void *a, const void *b)
{
	const struct _fact_pair *fa = *(const struct _fact_pair * const *)a;
	const struct _fact_pair *fb = *(const struct _fact_pair * const *)b;
	int c = strcmp(fa->name, fb->name);
	if (c != 0)
		return c;
	return strcmp(fa->value, fb->value);
}

static void _fact_pair_free(struct _fact_pair *pair)
{
	if (pair == NULL)
		return;
	free(pair->name);
	free(pair->value);
	free(pair);
}

static bool _is_bookkeeping_fact(const char *name)
{
	return oscap_streq(name, FACT_HOST_ID) ||
		oscap_streq(name, FACT_HOST_ID_SOURCE) ||
		oscap_streq(name, FACT_HOST_ID_CONFLICT) ||
		oscap_streq(name, FACT_SCAN_HISTORY) ||
		oscap_streq(name, FACT_SCAN_COUNT) ||
		oscap_streq(name, FACT_RULE_COUNT) ||
		oscap_streq(name, FACT_PASS_COUNT) ||
		oscap_streq(name, FACT_FAIL_COUNT) ||
		oscap_streq(name, FACT_ERROR_COUNT) ||
		oscap_streq(name, FACT_UNKNOWN_COUNT);
}

/* One occurrence of a rule result in one scan. */
struct _rule_occurrence {
	char *time;
	xccdf_test_result_type_t result;
	struct xccdf_rule_result *source;   /* borrowed, valid while records live */
};

struct _rule_history {
	char *idref;
	struct _rule_occurrence *occurrences;
	size_t occurrence_count;
	size_t occurrence_capacity;
	/* State carried from a merged input record. */
	bool carried;
	size_t carried_count;
	char *carried_first;
	char *carried_last;
	char *carried_results;   /* "pass|fail|..." in chronological order */
	struct xccdf_rule_result *carried_source;   /* borrowed */
	struct xccdf_rule_result *chosen;   /* borrowed from a record */
	char *chosen_time;
	xccdf_test_result_type_t chosen_result;
};

static char *_merge_strndup(const char *src, size_t len)
{
	char *ret = malloc(len + 1);
	if (ret == NULL)
		return NULL;
	memcpy(ret, src, len);
	ret[len] = '\0';
	return ret;
}

static int _rule_history_cmp(const void *a, const void *b)
{
	const struct _rule_history *ha = *(const struct _rule_history * const *)a;
	const struct _rule_history *hb = *(const struct _rule_history * const *)b;
	if (ha->idref == NULL && hb->idref != NULL) return -1;
	if (ha->idref != NULL && hb->idref == NULL) return 1;
	if (ha->idref == NULL) return 0;
	return strcmp(ha->idref, hb->idref);
}

static void _rule_history_free(struct _rule_history *history)
{
	free(history->idref);
	for (size_t i = 0; i < history->occurrence_count; ++i)
		free(history->occurrences[i].time);
	free(history->occurrences);
	free(history->carried_first);
	free(history->carried_last);
	free(history->carried_results);
	free(history->chosen_time);
	free(history);
}

static void _rule_history_add_occurrence(struct _rule_history *history, const char *time,
		xccdf_test_result_type_t result, struct xccdf_rule_result *source)
{
	/* Deduplicate identical (time, result) occurrences. */
	for (size_t i = 0; i < history->occurrence_count; ++i) {
		if (oscap_streq(history->occurrences[i].time, time) &&
				history->occurrences[i].result == result)
			return;
	}
	if (history->occurrence_count == history->occurrence_capacity) {
		size_t new_capacity = history->occurrence_capacity == 0 ? 4 : history->occurrence_capacity * 2;
		struct _rule_occurrence *items = realloc(history->occurrences,
			new_capacity * sizeof(struct _rule_occurrence));
		if (items == NULL)
			return;
		history->occurrences = items;
		history->occurrence_capacity = new_capacity;
	}
	struct _rule_occurrence *occ = &history->occurrences[history->occurrence_count++];
	occ->time = oscap_strdup(time != NULL ? time : "");
	occ->result = result;
	occ->source = source;
}

static struct _rule_history *_rule_history_get(struct oscap_list *histories, const char *idref)
{
	if (idref == NULL || idref[0] == '\0')
		return NULL;
	struct oscap_iterator *it = oscap_iterator_new(histories);
	while (oscap_iterator_has_more(it)) {
		struct _rule_history *history = oscap_iterator_next(it);
		if (oscap_streq(history->idref, idref)) {
			oscap_iterator_free(it);
			return history;
		}
	}
	oscap_iterator_free(it);
	struct _rule_history *history = calloc(1, sizeof(struct _rule_history));
	if (history == NULL)
		return NULL;
	history->idref = oscap_strdup(idref);
	oscap_list_add(histories, history);
	return history;
}

#define RULE_HISTORY_MARKER "[merge-history] "

static bool _parse_history_message(const struct xccdf_rule_result *rule_result, struct _rule_history *history)
{
	struct xccdf_message_iterator *messages = xccdf_rule_result_get_messages(rule_result);
	bool found = false;
	while (xccdf_message_iterator_has_more(messages)) {
		struct xccdf_message *message = xccdf_message_iterator_next(messages);
		const char *content = xccdf_message_get_content(message);
		if (content == NULL || !oscap_str_startswith(content, RULE_HISTORY_MARKER))
			continue;
		const char *body = content + strlen(RULE_HISTORY_MARKER);
		found = true;
		/* Format: count=N;first=T;last=T;results=a|b|c */
		const char *count_str = strstr(body, "count=");
		const char *first_str = strstr(body, "first=");
		const char *last_str = strstr(body, "last=");
		const char *results_str = strstr(body, "results=");
		if (count_str != NULL)
			history->carried_count = (size_t)strtoul(count_str + strlen("count="), NULL, 10);
		if (first_str != NULL) {
			const char *end = strchr(first_str + strlen("first="), ';');
			size_t len = end != NULL ? (size_t)(end - (first_str + strlen("first="))) : strlen(first_str + strlen("first="));
			history->carried_first = _merge_strndup(first_str + strlen("first="), len);
		}
		if (last_str != NULL) {
			const char *end = strchr(last_str + strlen("last="), ';');
			size_t len = end != NULL ? (size_t)(end - (last_str + strlen("last="))) : strlen(last_str + strlen("last="));
			history->carried_last = _merge_strndup(last_str + strlen("last="), len);
		}
		if (results_str != NULL) {
			const char *end = strchr(results_str + strlen("results="), ';');
			size_t len = end != NULL ? (size_t)(end - (results_str + strlen("results="))) : strlen(results_str + strlen("results="));
			history->carried_results = _merge_strndup(results_str + strlen("results="), len);
		}
	}
	xccdf_message_iterator_free(messages);
	if (found)
		history->carried = true;
	return found;
}

/* Collect the rule results of one record into the per-group histories. */
static void _collect_rule_results(struct oscap_list *histories, const struct _host_record *record)
{
	const char *record_time = xccdf_result_get_end_time(record->result);
	struct xccdf_rule_result_iterator *rule_results = xccdf_result_get_rule_results(record->result);
	while (xccdf_rule_result_iterator_has_more(rule_results)) {
		struct xccdf_rule_result *rule_result = xccdf_rule_result_iterator_next(rule_results);
		struct _rule_history *history = _rule_history_get(histories, xccdf_rule_result_get_idref(rule_result));
		if (history == NULL)
			continue;
		if (_parse_history_message(rule_result, history)) {
			/* The input record already represents a merged rule.  Carry its
			 * aggregate forward; the original single record is remembered
			 * so that it can be reproduced verbatim when nothing else is
			 * added (idempotency). */
			if (history->carried_source == NULL)
				history->carried_source = rule_result;
			continue;
		}
		const char *time = xccdf_rule_result_get_time(rule_result);
		_rule_history_add_occurrence(history, time != NULL ? time : record_time,
			xccdf_rule_result_get_result(rule_result), rule_result);
	}
	xccdf_rule_result_iterator_free(rule_results);
}

static int _occurrence_cmp(const void *a, const void *b)
{
	const struct _rule_occurrence *oa = (const struct _rule_occurrence *)a;
	const struct _rule_occurrence *ob = (const struct _rule_occurrence *)b;
	int c = strcmp(oa->time, ob->time);
	if (c != 0)
		return c;
	const char *ra = xccdf_test_result_type_get_text(oa->result);
	const char *rb = xccdf_test_result_type_get_text(ob->result);
	return oscap_strcmp(ra, rb);
}

static char *_result_text_sorted_csv(struct _string_list *results)
{
	if (results->count == 0)
		return oscap_strdup("");
	struct _string_list copy = { NULL, 0, 0 };
	for (size_t i = 0; i < results->count; ++i)
		_string_list_add_uniq(&copy, results->items[i]);
	_string_list_sort_uniq(&copy);
	struct _string_builder sb;
	_sb_init(&sb);
	for (size_t i = 0; i < copy.count; ++i) {
		if (i > 0)
			_sb_append(&sb, "|");
		_sb_append(&sb, copy.items[i]);
	}
	_string_list_free(&copy);
	return _sb_steal(&sb);
}

static void _rule_result_add_history_message(struct xccdf_rule_result *rule_result, size_t count,
		const char *first, const char *last, const char *results)
{
	char *content = oscap_sprintf(RULE_HISTORY_MARKER "count=%zu;first=%s;last=%s;results=%s",
		count, first != NULL ? first : "", last != NULL ? last : "",
		results != NULL ? results : "");
	struct xccdf_message *message = xccdf_message_new();
	xccdf_message_set_severity(message, XCCDF_MSG_INFO);
	xccdf_message_set_content(message, content);
	xccdf_rule_result_add_message(rule_result, message);
	free(content);
}

static void _rule_history_finalize(struct _rule_history *history)
{
	if (history->occurrence_count > 0) {
		qsort(history->occurrences, history->occurrence_count,
			sizeof(struct _rule_occurrence), _occurrence_cmp);
	}

	if (history->carried) {
		/* Start from the carried aggregate. */
		history->chosen = history->carried_source;
		history->chosen_result = xccdf_rule_result_get_result(history->carried_source);
		free(history->chosen_time);
		history->chosen_time = oscap_strdup(history->carried_last);
		/* A later, independently observed conclusion wins. */
		if (history->occurrence_count > 0) {
			struct _rule_occurrence *latest = &history->occurrences[history->occurrence_count - 1];
			if (history->carried_last == NULL ||
					strcmp(latest->time, history->carried_last) >= 0) {
				history->chosen = latest->source;
				history->chosen_result = latest->result;
				free(history->chosen_time);
				history->chosen_time = oscap_strdup(latest->time);
			}
		}
		return;
	}

	if (history->occurrence_count > 0) {
		/* Latest conclusion is the visible one. */
		struct _rule_occurrence *latest = &history->occurrences[history->occurrence_count - 1];
		history->chosen = latest->source;
		history->chosen_result = latest->result;
		free(history->chosen_time);
		history->chosen_time = oscap_strdup(latest->time);
	}
}

/* Build the merged rule-result for one rule history.  Returns NULL when the
 * history has no visible result. */
static struct xccdf_rule_result *_build_merged_rule_result(struct _rule_history *history)
{
	if (history->chosen == NULL)
		return NULL;

	/* Nothing new was observed on top of an already merged record: reproduce
	 * it verbatim so that merging a merged document is a no-op. */
	if (history->carried && history->occurrence_count == 0) {
		struct xccdf_rule_result *clone = xccdf_rule_result_clone(history->carried_source);
		if (clone != NULL && xccdf_rule_result_get_time(clone) == NULL && history->chosen_time != NULL)
			xccdf_rule_result_set_time(clone, history->chosen_time);
		return clone;
	}

	struct xccdf_rule_result *clone = xccdf_rule_result_clone(history->chosen);
	if (clone == NULL)
		return NULL;
	xccdf_rule_result_set_result(clone, history->chosen_result);
	if (history->chosen_time != NULL)
		xccdf_rule_result_set_time(clone, history->chosen_time);

	/* Combine the carried aggregate (if any) with the newly observed
	 * conclusions, keeping both the earliest and the latest timestamps. */
	struct _string_list results = { NULL, 0, 0 };
	size_t total = history->occurrence_count;
	const char *first = NULL;
	const char *last = NULL;
	if (history->carried) {
		total += history->carried_count;
		first = history->carried_first;
		last = history->carried_last;
		char *copy = oscap_strdup(history->carried_results != NULL ? history->carried_results : "");
		char *saveptr = NULL;
		for (char *token = strtok_r(copy, "|", &saveptr); token != NULL;
				token = strtok_r(NULL, "|", &saveptr))
			_string_list_add_uniq(&results, token);
		free(copy);
	}
	if (history->occurrence_count > 0) {
		if (first == NULL || strcmp(history->occurrences[0].time, first) < 0)
			first = history->occurrences[0].time;
		const char *occ_last = history->occurrences[history->occurrence_count - 1].time;
		if (last == NULL || strcmp(occ_last, last) > 0)
			last = occ_last;
	}
	for (size_t i = 0; i < history->occurrence_count; ++i) {
		const char *text = xccdf_test_result_type_get_text(history->occurrences[i].result);
		if (text != NULL && !_string_list_contains(&results, text))
			_string_list_add_uniq(&results, text);
	}
	char *results_csv = _result_text_sorted_csv(&results);
	_string_list_free(&results);
	/* A plain single observation needs no history annotation.  Keeping the
	 * output free of bookkeeping in that case is also what makes a
	 * re-merge treat the record exactly like the original scan. */
	if (total > 1 || history->carried)
		_rule_result_add_history_message(clone, total, first, last, results_csv);
	free(results_csv);
	return clone;
}

/* A single host view: all records that resolve to the same machine. */
struct _host_group {
	char *token;                 /* canonical token, possibly conflict-tagged */
	char *fingerprint;           /* may be NULL */
	xccdf_host_identity_source_t source;
	bool unknown;
	bool conflict;
	const struct _host_record **records;
	size_t record_count;
};

static void _host_group_free(struct _host_group *group)
{
	free(group->token);
	free(group->fingerprint);
	free(group->records);
	free(group);
}

static int _host_group_cmp(const void *a, const void *b)
{
	const struct _host_group *ga = *(const struct _host_group * const *)a;
	const struct _host_group *gb = *(const struct _host_group * const *)b;
	int c = strcmp(ga->token, gb->token);
	if (c != 0)
		return c;
	const char *fa = ga->fingerprint != NULL ? ga->fingerprint : "";
	const char *fb = gb->fingerprint != NULL ? gb->fingerprint : "";
	return strcmp(fa, fb);
}

static unsigned long _token_hash(const char *token)
{
	unsigned long hash = 5381;
	for (const char *p = token; p != NULL && *p; ++p)
		hash = ((hash << 5) + hash) + (unsigned char)*p;
	return hash & 0xffffffffUL;
}

/* Build the scan history entry for one record. */
static char *_scan_entry(const struct _host_record *record)
{
	struct _string_builder sb;
	_sb_init(&sb);
	const char *id = xccdf_result_get_id(record->result);
	const char *start = xccdf_result_get_start_time(record->result);
	const char *end = xccdf_result_get_end_time(record->result);
	size_t pass = 0, fail = 0, error = 0, unknown = 0, total = 0;
	struct xccdf_rule_result_iterator *rule_results = xccdf_result_get_rule_results(record->result);
	while (xccdf_rule_result_iterator_has_more(rule_results)) {
		struct xccdf_rule_result *rr = xccdf_rule_result_iterator_next(rule_results);
		total++;
		switch (xccdf_rule_result_get_result(rr)) {
		case XCCDF_RESULT_PASS:
		case XCCDF_RESULT_FIXED:
			pass++;
			break;
		case XCCDF_RESULT_FAIL:
			fail++;
			break;
		case XCCDF_RESULT_ERROR:
			error++;
			break;
		case XCCDF_RESULT_UNKNOWN:
			unknown++;
			break;
		default:
			break;
		}
	}
	xccdf_rule_result_iterator_free(rule_results);

	/* Pick the scanner version deterministically regardless of the order in
	 * which the facts appeared in the input. */
	struct _string_list scanner_versions = { NULL, 0, 0 };
	for (size_t i = 0; i < record->view.scanner_versions.count; ++i)
		_string_list_add_uniq(&scanner_versions, record->view.scanner_versions.items[i]);
	_string_list_sort_uniq(&scanner_versions);
	const char *scanner = scanner_versions.count > 0
		? scanner_versions.items[scanner_versions.count - 1] : "";
	struct _string_list scanner_names = { NULL, 0, 0 };
	for (size_t i = 0; i < record->view.scanner.count; ++i)
		_string_list_add_uniq(&scanner_names, record->view.scanner.items[i]);
	_string_list_sort_uniq(&scanner_names);
	const char *scanner_name = scanner_names.count > 0 ? scanner_names.items[0] : "";

	_sb_append(&sb, "id=");
	_sb_append(&sb, id != NULL ? id : "");
	_sb_append(&sb, ";start=");
	_sb_append(&sb, start != NULL ? start : "");
	_sb_append(&sb, ";end=");
	_sb_append(&sb, end != NULL ? end : "");
	_sb_append(&sb, ";scanner=");
	_sb_append(&sb, scanner_name);
	_sb_append(&sb, ";scanner_version=");
	_sb_append(&sb, scanner);
	char *counts = oscap_sprintf(";rules=%zu;pass=%zu;fail=%zu;error=%zu;unknown=%zu",
		total, pass, fail, error, unknown);
	_sb_append(&sb, counts);
	free(counts);
	_string_list_free(&scanner_versions);
	_string_list_free(&scanner_names);
	return _sb_steal(&sb);
}

static void _result_add_fact_string(struct xccdf_result *result, const char *name, const char *value)
{
	if (name == NULL || value == NULL)
		return;
	struct xccdf_target_fact *fact = xccdf_target_fact_new();
	xccdf_target_fact_set_name(fact, name);
	xccdf_target_fact_set_string(fact, value);
	xccdf_result_add_target_fact(result, fact);
}

/* Build one merged TestResult for a host group. */
static struct xccdf_result *_build_group_result(struct _host_group *group)
{
	struct xccdf_result *result = xccdf_result_new();

	/* Attributes: start is the earliest, end is the latest, the rest is
	 * taken from the latest record (records are sorted). */
	const char *start = NULL;
	const char *end = NULL;
	const struct _host_record *latest = group->records[group->record_count - 1];
	for (size_t i = 0; i < group->record_count; ++i) {
		const char *s = xccdf_result_get_start_time(group->records[i]->result);
		if (s != NULL && (start == NULL || strcmp(s, start) < 0))
			start = s;
		const char *e = xccdf_result_get_end_time(group->records[i]->result);
		if (e != NULL && (end == NULL || strcmp(e, end) > 0))
			end = e;
	}
	if (start != NULL)
		xccdf_result_set_start_time(result, start);
	if (end != NULL)
		xccdf_result_set_end_time(result, end);
	else
		xccdf_result_set_end_time(result, "1970-01-01T00:00:00Z");

	xccdf_result_set_version(result, xccdf_result_get_version(latest->result));
	if (xccdf_result_get_test_system(latest->result) != NULL)
		xccdf_result_set_test_system(result, xccdf_result_get_test_system(latest->result));
	if (xccdf_result_get_profile(latest->result) != NULL)
		xccdf_result_set_profile(result, xccdf_result_get_profile(latest->result));
	/* The benchmark URI of the inputs points at the original content file;
	 * it is intentionally not carried over so that the output does not
	 * depend on the names of the input files.  The merged Benchmark is
	 * self-describing. */

	char *id = oscap_sprintf("xccdf_org.open-scap_testresult_host_%08lx", _token_hash(group->token));
	xccdf_result_set_id(result, id);
	free(id);

	/* Names and addresses: the full history, sorted. */
	struct _string_list names = { NULL, 0, 0 };
	struct _string_list addresses = { NULL, 0, 0 };
	for (size_t i = 0; i < group->record_count; ++i) {
		const struct _host_identity_view *view = &group->records[i]->view;
		for (size_t j = 0; j < view->names.count; ++j)
			_string_list_add_uniq(&names, view->names.items[j]);
		for (size_t j = 0; j < view->addresses.count; ++j)
			_string_list_add_uniq(&addresses, view->addresses.items[j]);
	}
	_string_list_sort_uniq(&names);
	_string_list_sort_uniq(&addresses);

	/* The title is derived from the same canonical view as the resolver, so
	 * that re-merging the output reproduces it byte for byte. */
	const char *display_name = NULL;
	for (size_t i = 0; i < names.count; ++i) {
		if (!oscap_streq(names.items[i], HOST_UNKNOWN_TOKEN) &&
				!oscap_streq(names.items[i], HOST_UNKNOWN_DISPLAY)) {
			display_name = names.items[i];
			break;
		}
	}
	if (display_name == NULL)
		display_name = HOST_UNKNOWN_DISPLAY;
	char *title_text = oscap_sprintf("Merged results for host %s", display_name);
	struct oscap_text *title = oscap_text_new();
	oscap_text_set_text(title, title_text);
	xccdf_result_add_title(result, title);
	free(title_text);

	if (names.count == 0)
		xccdf_result_add_target(result, display_name);
	for (size_t i = 0; i < names.count; ++i)
		xccdf_result_add_target(result, names.items[i]);
	for (size_t i = 0; i < addresses.count; ++i)
		xccdf_result_add_target_address(result, addresses.items[i]);

	/* Facts: all non-bookkeeping facts from every scan, sorted and
	 * deduplicated, plus the identity and summary facts. */
	struct oscap_list *fact_pairs = oscap_list_new();
	for (size_t i = 0; i < group->record_count; ++i) {
		struct xccdf_target_fact_iterator *facts =
			xccdf_result_get_target_facts(group->records[i]->result);
		while (xccdf_target_fact_iterator_has_more(facts)) {
			struct xccdf_target_fact *fact = xccdf_target_fact_iterator_next(facts);
			const char *name = xccdf_target_fact_get_name(fact);
			const char *value = xccdf_target_fact_get_value(fact);
			if (name == NULL || value == NULL || _is_bookkeeping_fact(name))
				continue;
			struct _fact_pair *pair = calloc(1, sizeof(struct _fact_pair));
			pair->name = oscap_strdup(name);
			pair->value = oscap_strdup(value);
			oscap_list_add(fact_pairs, pair);
		}
		xccdf_target_fact_iterator_free(facts);
	}
	size_t pair_count = (size_t)oscap_list_get_itemcount(fact_pairs);
	struct _fact_pair **pairs = malloc((pair_count + 1) * sizeof(struct _fact_pair *));
	size_t pair_index = 0;
	struct oscap_iterator *pair_it = oscap_iterator_new(fact_pairs);
	while (oscap_iterator_has_more(pair_it))
		pairs[pair_index++] = oscap_iterator_next(pair_it);
	oscap_iterator_free(pair_it);
	if (pair_count > 1)
		qsort(pairs, pair_count, sizeof(struct _fact_pair *), _fact_pair_cmp);
	for (size_t i = 0; i < pair_count; ++i) {
		if (i > 0 && _fact_pair_cmp(&pairs[i], &pairs[i - 1]) == 0)
			continue;
		_result_add_fact_string(result, pairs[i]->name, pairs[i]->value);
	}
	free(pairs);
	oscap_list_free(fact_pairs, (oscap_destruct_func) _fact_pair_free);

	_result_add_fact_string(result, FACT_HOST_ID, group->token);
	_result_add_fact_string(result, FACT_HOST_ID_SOURCE,
		xccdf_host_identity_source_to_string(group->source));
	if (group->conflict)
		_result_add_fact_string(result, FACT_HOST_ID_CONFLICT, "true");

	/* Per-scan history.  A merged input record already carries its own
	 * history and must not gain a bogus extra entry. */
	struct _string_list history = { NULL, 0, 0 };
	for (size_t i = 0; i < group->record_count; ++i) {
		const struct _host_record *record = group->records[i];
		if (record->view.scan_history.count > 0) {
			for (size_t j = 0; j < record->view.scan_history.count; ++j)
				_string_list_add_uniq(&history, record->view.scan_history.items[j]);
		} else {
			char *entry = _scan_entry(record);
			_string_list_add_uniq(&history, entry);
			free(entry);
		}
	}
	_string_list_sort_uniq(&history);
	for (size_t i = 0; i < history.count; ++i)
		_result_add_fact_string(result, FACT_SCAN_HISTORY, history.items[i]);

	/* Rule results: one visible result per rule, with the time series kept
	 * in a merge-history message. */
	struct oscap_list *histories = oscap_list_new();
	for (size_t i = 0; i < group->record_count; ++i)
		_collect_rule_results(histories, group->records[i]);
	size_t history_count = (size_t)oscap_list_get_itemcount(histories);
	struct _rule_history **history_items = malloc((history_count + 1) * sizeof(struct _rule_history *));
	size_t history_index = 0;
	struct oscap_iterator *history_it = oscap_iterator_new(histories);
	while (oscap_iterator_has_more(history_it))
		history_items[history_index++] = oscap_iterator_next(history_it);
	oscap_iterator_free(history_it);
	if (history_count > 1)
		qsort(history_items, history_count, sizeof(struct _rule_history *), _rule_history_cmp);

	size_t pass_count = 0, fail_count = 0, error_count = 0, unknown_count = 0;
	for (size_t i = 0; i < history_count; ++i) {
		_rule_history_finalize(history_items[i]);
		struct xccdf_rule_result *merged = _build_merged_rule_result(history_items[i]);
		if (merged == NULL)
			continue;
		switch (xccdf_rule_result_get_result(merged)) {
		case XCCDF_RESULT_PASS:
		case XCCDF_RESULT_FIXED:
			pass_count++;
			break;
		case XCCDF_RESULT_FAIL:
			fail_count++;
			break;
		case XCCDF_RESULT_ERROR:
			error_count++;
			break;
		case XCCDF_RESULT_UNKNOWN:
			unknown_count++;
			break;
		default:
			break;
		}
		xccdf_result_add_rule_result(result, merged);
	}
	free(history_items);
	oscap_list_free(histories, (oscap_destruct_func) _rule_history_free);

	size_t all_rules = 0;
	struct xccdf_rule_result_iterator *count_it = xccdf_result_get_rule_results(result);
	while (xccdf_rule_result_iterator_has_more(count_it)) {
		xccdf_rule_result_iterator_next(count_it);
		all_rules++;
	}
	xccdf_rule_result_iterator_free(count_it);
	char *value = oscap_sprintf("%zu", (size_t)history.count);
	_result_add_fact_string(result, FACT_SCAN_COUNT, value);
	free(value);
	value = oscap_sprintf("%zu", all_rules);
	_result_add_fact_string(result, FACT_RULE_COUNT, value);
	free(value);
	value = oscap_sprintf("%zu", pass_count);
	_result_add_fact_string(result, FACT_PASS_COUNT, value);
	free(value);
	value = oscap_sprintf("%zu", fail_count);
	_result_add_fact_string(result, FACT_FAIL_COUNT, value);
	free(value);
	value = oscap_sprintf("%zu", error_count);
	_result_add_fact_string(result, FACT_ERROR_COUNT, value);
	free(value);
	value = oscap_sprintf("%zu", unknown_count);
	_result_add_fact_string(result, FACT_UNKNOWN_COUNT, value);
	free(value);

	/* Scores: other scoring systems are carried over from the latest scan.
	 * The default score is always recomputed from the visible details so the
	 * summary can be verified against them. */
	struct xccdf_score_iterator *scores = xccdf_result_get_scores(latest->result);
	while (xccdf_score_iterator_has_more(scores)) {
		struct xccdf_score *score = xccdf_score_iterator_next(scores);
		if (oscap_streq(xccdf_score_get_system(score), DEFAULT_SCORING_SYSTEM))
			continue;
		xccdf_result_add_score(result, xccdf_score_clone(score));
	}
	xccdf_score_iterator_free(scores);

	double weighted_score = 0.0;
	double weighted_maximum = 0.0;
	struct xccdf_rule_result_iterator *score_it = xccdf_result_get_rule_results(result);
	while (xccdf_rule_result_iterator_has_more(score_it)) {
		struct xccdf_rule_result *rr = xccdf_rule_result_iterator_next(score_it);
		xccdf_test_result_type_t rr_result = xccdf_rule_result_get_result(rr);
		if (xccdf_rule_result_get_role(rr) == XCCDF_ROLE_UNSCORED)
			continue;
		if (rr_result == XCCDF_RESULT_NOT_SELECTED ||
				rr_result == XCCDF_RESULT_NOT_APPLICABLE ||
				rr_result == XCCDF_RESULT_INFORMATIONAL ||
				rr_result == XCCDF_RESULT_NOT_CHECKED)
			continue;
		float weight = xccdf_rule_result_get_weight(rr);
		if (weight <= 0.0f)
			weight = 1.0f;
		weighted_maximum += weight;
		if (rr_result == XCCDF_RESULT_PASS || rr_result == XCCDF_RESULT_FIXED)
			weighted_score += weight;
	}
	xccdf_rule_result_iterator_free(score_it);
	double default_score = weighted_maximum > 0.0
		? (100.0 * weighted_score) / weighted_maximum : 0.0;
	struct xccdf_score *default_score_obj = xccdf_score_new();
	xccdf_score_set_system(default_score_obj, DEFAULT_SCORING_SYSTEM);
	xccdf_score_set_maximum(default_score_obj, 100.0);
	xccdf_score_set_score(default_score_obj, default_score);
	xccdf_result_add_score(result, default_score_obj);

	_string_list_free(&names);
	_string_list_free(&addresses);
	_string_list_free(&history);
	return result;
}

/* ------------------------------------------------------------------ */
/* Grouping                                                           */
/* ------------------------------------------------------------------ */

static void _group_add_record(struct _host_group *group, const struct _host_record *record)
{
	group->records = realloc(group->records, (group->record_count + 1) * sizeof(struct _host_record *));
	group->records[group->record_count++] = record;
}

/* Per-token bucket used while grouping. */
struct _token_bucket {
	char *token;
	struct oscap_list *list;       /* of struct _host_record * */
};

static struct _token_bucket *_bucket_for_token(struct oscap_list *buckets, const char *token)
{
	struct oscap_iterator *it = oscap_iterator_new(buckets);
	while (oscap_iterator_has_more(it)) {
		struct _token_bucket *bucket = oscap_iterator_next(it);
		if (oscap_streq(bucket->token, token)) {
			oscap_iterator_free(it);
			return bucket;
		}
	}
	oscap_iterator_free(it);
	struct _token_bucket *bucket = calloc(1, sizeof(struct _token_bucket));
	bucket->token = oscap_strdup(token);
	bucket->list = oscap_list_new();
	oscap_list_add(buckets, bucket);
	return bucket;
}

static void _token_bucket_free(struct _token_bucket *bucket)
{
	free(bucket->token);
	oscap_list_free0(bucket->list);
	free(bucket);
}

/* Build the deterministic list of host groups.
 *
 * Records are already sorted (end-time first), so appending them to a bucket
 * in iteration order keeps every group's records in chronological order.
 * Grouping is by canonical identity token, independently of adjacency in the
 * globally sorted array. */
static struct oscap_list *_build_groups(const struct _host_record **records, size_t count,
		size_t *out_conflicts)
{
	struct oscap_list *groups = oscap_list_new();
	struct oscap_list *buckets = oscap_list_new();
	*out_conflicts = 0;

	/* Pass 1: bucket records by identity token, preserving chronological
	 * order within each bucket. */
	for (size_t i = 0; i < count; ++i) {
		struct _token_bucket *bucket = _bucket_for_token(buckets, records[i]->view.canonical_token);
		oscap_list_add(bucket->list, (void *)records[i]);
	}

	/* Pass 2: split buckets whose records disagree on the machine
	 * fingerprint.  Everything else becomes one group per bucket. */
	struct oscap_iterator *bucket_it = oscap_iterator_new(buckets);
	while (oscap_iterator_has_more(bucket_it)) {
		struct _token_bucket *bucket = oscap_iterator_next(bucket_it);
		const size_t bucket_size = (size_t)oscap_list_get_itemcount(bucket->list);
		struct _host_record **items = malloc((bucket_size + 1) * sizeof(struct _host_record *));
		size_t index = 0;
		struct oscap_iterator *item_it = oscap_iterator_new(bucket->list);
		while (oscap_iterator_has_more(item_it))
			items[index++] = oscap_iterator_next(item_it);
		oscap_iterator_free(item_it);

		struct _string_list fingerprints = { NULL, 0, 0 };
		for (size_t i = 0; i < bucket_size; ++i)
			if (items[i]->fingerprint != NULL)
				_string_list_add_uniq(&fingerprints, items[i]->fingerprint);
		_string_list_sort_uniq(&fingerprints);

		if (fingerprints.count <= 1) {
			struct _host_group *group = calloc(1, sizeof(struct _host_group));
			group->token = oscap_strdup(items[0]->view.canonical_token);
			group->fingerprint = fingerprints.count == 1 ? oscap_strdup(fingerprints.items[0]) : NULL;
			group->source = items[0]->view.source;
			group->unknown = group->source == XCCDF_HOST_IDENTITY_UNKNOWN;
			for (size_t i = 0; i < bucket_size; ++i)
				_group_add_record(group, items[i]);
			oscap_list_add(groups, group);
		} else {
			/* The same identity key points at several machine
			 * fingerprints.  This is a conflict: keep the machines apart
			 * and flag them instead of silently choosing one. */
			*out_conflicts += fingerprints.count;
			for (size_t f = 0; f < fingerprints.count; ++f) {
				struct _host_group *group = calloc(1, sizeof(struct _host_group));
				group->token = oscap_strdup(items[0]->view.canonical_token);
				group->fingerprint = oscap_strdup(fingerprints.items[f]);
				group->source = items[0]->view.source;
				group->unknown = group->source == XCCDF_HOST_IDENTITY_UNKNOWN;
				group->conflict = true;
				for (size_t i = 0; i < bucket_size; ++i)
					if (items[i]->fingerprint != NULL &&
							oscap_streq(items[i]->fingerprint, group->fingerprint))
						_group_add_record(group, items[i]);
				oscap_list_add(groups, group);
			}
			/* Records without any fingerprint cannot be attributed to one
			 * of the conflicting machines; keep them in a separate group
			 * so they are neither lost nor silently merged. */
			bool has_unattributed = false;
			for (size_t i = 0; i < bucket_size; ++i)
				if (items[i]->fingerprint == NULL)
					has_unattributed = true;
			if (has_unattributed) {
				struct _host_group *group = calloc(1, sizeof(struct _host_group));
				group->token = oscap_strdup(items[0]->view.canonical_token);
				group->source = items[0]->view.source;
				group->unknown = group->source == XCCDF_HOST_IDENTITY_UNKNOWN;
				group->conflict = true;
				for (size_t i = 0; i < bucket_size; ++i)
					if (items[i]->fingerprint == NULL)
						_group_add_record(group, items[i]);
				oscap_list_add(groups, group);
			}
		}
		free(items);
		_string_list_free(&fingerprints);
	}
	oscap_iterator_free(bucket_it);

	oscap_list_free(buckets, (oscap_destruct_func) _token_bucket_free);
	return groups;
}

/* Stub Rules so that the merged benchmark can be consumed by the existing
 * report pipeline, which walks Benchmark/Rule.  Only ids that satisfy the
 * XCCDF Rule id pattern are turned into stubs. */
/* Copy severity/weight from the rule results of one rule.  When inputs
 * disagree the lowest severity and weight 1.0 are used, which keeps the
 * fallback deterministic and never inflates a score. */
static void _fill_stub_rule_metadata(struct xccdf_rule *rule, const char *idref,
		struct oscap_list *groups)
{
	xccdf_level_t severity = XCCDF_LEVEL_NOT_DEFINED;
	float weight = -1.0f;
	struct oscap_iterator *group_it = oscap_iterator_new(groups);
	while (oscap_iterator_has_more(group_it)) {
		struct _host_group *group = oscap_iterator_next(group_it);
		for (size_t i = 0; i < group->record_count; ++i) {
			struct xccdf_rule_result_iterator *rrs =
				xccdf_result_get_rule_results(group->records[i]->result);
			while (xccdf_rule_result_iterator_has_more(rrs)) {
				struct xccdf_rule_result *rr = xccdf_rule_result_iterator_next(rrs);
				if (!oscap_streq(xccdf_rule_result_get_idref(rr), idref))
					continue;
				xccdf_level_t rr_severity = xccdf_rule_result_get_severity(rr);
				if (rr_severity != XCCDF_LEVEL_NOT_DEFINED &&
						(severity == XCCDF_LEVEL_NOT_DEFINED || rr_severity > severity))
					severity = rr_severity;
				float rr_weight = xccdf_rule_result_get_weight(rr);
				if (rr_weight > 0.0f &&
						(weight < 0.0f || rr_weight < weight))
					weight = rr_weight;
			}
			xccdf_rule_result_iterator_free(rrs);
		}
	}
	oscap_iterator_free(group_it);
	if (severity != XCCDF_LEVEL_NOT_DEFINED)
		xccdf_rule_set_severity(rule, severity);
	if (weight > 0.0f)
		xccdf_rule_set_weight(rule, weight);
}

static void _add_stub_rules(struct xccdf_benchmark *benchmark, struct oscap_list *groups)
{
	struct oscap_list *rule_ids = oscap_list_new();
	struct oscap_iterator *group_it = oscap_iterator_new(groups);
	while (oscap_iterator_has_more(group_it)) {
		struct _host_group *group = oscap_iterator_next(group_it);
		for (size_t i = 0; i < group->record_count; ++i) {
			struct xccdf_rule_result_iterator *rrs =
				xccdf_result_get_rule_results(group->records[i]->result);
			while (xccdf_rule_result_iterator_has_more(rrs)) {
				struct xccdf_rule_result *rr = xccdf_rule_result_iterator_next(rrs);
				const char *idref = xccdf_rule_result_get_idref(rr);
				if (idref == NULL || !oscap_str_startswith(idref, "xccdf_"))
					continue;
				if (strstr(idref, "_rule_") == NULL)
					continue;
				bool found = false;
				struct oscap_iterator *id_it = oscap_iterator_new(rule_ids);
				while (oscap_iterator_has_more(id_it)) {
					if (oscap_streq(oscap_iterator_next(id_it), idref)) {
						found = true;
						break;
					}
				}
				oscap_iterator_free(id_it);
				if (!found)
					oscap_list_add(rule_ids, oscap_strdup(idref));
			}
			xccdf_rule_result_iterator_free(rrs);
		}
	}
	oscap_iterator_free(group_it);

	/* check-export elements in the copied rule results reference Values of
	 * the original benchmark.  Provide empty stubs so that the document
	 * remains schema-valid without inventing a value that could mislead a
	 * reader. */
	struct _string_list value_ids_list = { NULL, 0, 0 };
	struct oscap_iterator *g_it = oscap_iterator_new(groups);
	while (oscap_iterator_has_more(g_it)) {
		struct _host_group *group = oscap_iterator_next(g_it);
		for (size_t i = 0; i < group->record_count; ++i) {
			struct xccdf_rule_result_iterator *rrs =
				xccdf_result_get_rule_results(group->records[i]->result);
			while (xccdf_rule_result_iterator_has_more(rrs)) {
				struct xccdf_rule_result *rr = xccdf_rule_result_iterator_next(rrs);
				struct xccdf_check_iterator *checks = xccdf_rule_result_get_checks(rr);
				while (xccdf_check_iterator_has_more(checks)) {
					struct xccdf_check *check = xccdf_check_iterator_next(checks);
					struct xccdf_check_export_iterator *exports =
						xccdf_check_get_exports(check);
					while (xccdf_check_export_iterator_has_more(exports)) {
						struct xccdf_check_export *export =
							xccdf_check_export_iterator_next(exports);
						const char *value_id = xccdf_check_export_get_value(export);
						if (value_id != NULL && oscap_str_startswith(value_id, "xccdf_"))
							_string_list_add_uniq(&value_ids_list, value_id);
					}
					xccdf_check_export_iterator_free(exports);
				}
				xccdf_check_iterator_free(checks);
			}
			xccdf_rule_result_iterator_free(rrs);
		}
	}
	oscap_iterator_free(g_it);

	size_t id_count = (size_t)oscap_list_get_itemcount(rule_ids);
	char **ids = malloc((id_count + 1) * sizeof(char *));
	size_t index = 0;
	struct oscap_iterator *id_it = oscap_iterator_new(rule_ids);
	while (oscap_iterator_has_more(id_it))
		ids[index++] = oscap_iterator_next(id_it);
	oscap_iterator_free(id_it);
	if (id_count > 1)
		qsort(ids, id_count, sizeof(char *), _string_cmp);
	for (size_t i = 0; i < id_count; ++i) {
		if (i > 0 && oscap_streq(ids[i], ids[i - 1]))
			continue;
		struct xccdf_rule *rule = xccdf_rule_new();
		if (rule == NULL)
			continue;
		if (!xccdf_item_set_id((struct xccdf_item *)rule, ids[i])) {
			xccdf_rule_free((struct xccdf_item *)rule);
			continue;
		}
		/* Carry over the metadata visible in the input so that the existing
		 * report generators render the rule like they would for a plain
		 * single-host result. */
		_fill_stub_rule_metadata(rule, ids[i], groups);
		struct oscap_text *title = oscap_text_new();
		oscap_text_set_text(title, ids[i]);
		xccdf_rule_add_title(rule, title);
		xccdf_benchmark_add_rule(benchmark, rule);
	}
	free(ids);
	oscap_list_free(rule_ids, free);

	/* Emit the Value stubs in a deterministic order. */
	_string_list_sort_uniq(&value_ids_list);
	for (size_t i = 0; i < value_ids_list.count; ++i) {
		if (!oscap_str_startswith(value_ids_list.items[i], "xccdf_"))
			continue;
		if (strstr(value_ids_list.items[i], "_value_") == NULL)
			continue;
		struct xccdf_value *value_obj = xccdf_value_new(XCCDF_TYPE_STRING);
		if (value_obj == NULL)
			continue;
		if (!xccdf_item_set_id((struct xccdf_item *)value_obj, value_ids_list.items[i])) {
			xccdf_value_free((struct xccdf_item *)value_obj);
			continue;
		}
		struct oscap_text *value_title = oscap_text_new();
		oscap_text_set_text(value_title, value_ids_list.items[i]);
		xccdf_value_add_title(value_obj, value_title);
		struct xccdf_value_instance *instance = xccdf_value_new_instance(value_obj);
		if (instance != NULL) {
			xccdf_value_instance_set_value_string(instance, "placeholder");
			xccdf_value_add_instance(value_obj, instance);
		}
		xccdf_benchmark_add_value(benchmark, value_obj);
	}
	_string_list_free(&value_ids_list);
}

static struct xccdf_benchmark *_build_benchmark(struct oscap_list *groups)
{
	struct xccdf_benchmark *benchmark = xccdf_benchmark_new();
	if (benchmark == NULL)
		return NULL;

	xccdf_benchmark_set_schema_version(benchmark, xccdf_benchmark_supported_schema_version());
	xccdf_benchmark_set_id(benchmark, MERGED_BENCHMARK_ID);
	xccdf_benchmark_set_version(benchmark, MERGED_BENCHMARK_VERSION);

	struct xccdf_status *status = xccdf_status_new();
	xccdf_status_set_status(status, XCCDF_STATUS_INCOMPLETE);
	xccdf_benchmark_add_status(benchmark, status);

	struct oscap_text *title = oscap_text_new();
	oscap_text_set_text(title, "Merged XCCDF results");
	xccdf_benchmark_add_title(benchmark, title);

	_add_stub_rules(benchmark, groups);

	struct oscap_iterator *group_it = oscap_iterator_new(groups);
	while (oscap_iterator_has_more(group_it)) {
		struct _host_group *group = oscap_iterator_next(group_it);
		struct xccdf_result *result = _build_group_result(group);
		if (result != NULL)
			xccdf_benchmark_add_result(benchmark, result);
	}
	oscap_iterator_free(group_it);

	return benchmark;
}

static void _free_groups(struct oscap_list *groups)
{
	oscap_list_free(groups, (oscap_destruct_func) _host_group_free);
}

struct xccdf_benchmark *xccdf_result_merger_get_benchmark(struct xccdf_result_merger *merger)
{
	if (merger == NULL)
		return NULL;
	if (merger->built)
		return merger->benchmark;

	if (merger->benchmark != NULL) {
		xccdf_benchmark_free(merger->benchmark);
		merger->benchmark = NULL;
	}

	const size_t count = (size_t)oscap_list_get_itemcount(merger->records);
	if (count == 0)
		return NULL;

	/* Snapshot and sort the records.  Sorting is the cornerstone of
	 * determinism: it removes any dependence on the import order. */
	struct _host_record **records = malloc(count * sizeof(struct _host_record *));
	size_t index = 0;
	struct oscap_iterator *it = oscap_iterator_new(merger->records);
	while (oscap_iterator_has_more(it))
		records[index++] = oscap_iterator_next(it);
	oscap_iterator_free(it);
	qsort(records, count, sizeof(struct _host_record *), _record_cmp);

	size_t conflicts = 0;
	struct oscap_list *groups = _build_groups((const struct _host_record **)records, count, &conflicts);
	free(records);

	/* Order the groups deterministically. */
	size_t group_count = (size_t)oscap_list_get_itemcount(groups);
	struct _host_group **group_items = malloc((group_count + 1) * sizeof(struct _host_group *));
	index = 0;
	struct oscap_iterator *group_it = oscap_iterator_new(groups);
	while (oscap_iterator_has_more(group_it))
		group_items[index++] = oscap_iterator_next(group_it);
	oscap_iterator_free(group_it);
	if (group_count > 1)
		qsort(group_items, group_count, sizeof(struct _host_group *), _host_group_cmp);

	struct oscap_list *ordered_groups = oscap_list_new();
	size_t unknown_hosts = 0;
	for (size_t i = 0; i < group_count; ++i) {
		oscap_list_add(ordered_groups, group_items[i]);
		if (group_items[i]->unknown)
			unknown_hosts++;
	}
	free(group_items);

	merger->benchmark = _build_benchmark(ordered_groups);
	if (merger->benchmark == NULL) {
		oscap_list_free0(ordered_groups);
		_free_groups(groups);
		return NULL;
	}
	merger->host_count = group_count;
	merger->unknown_host_count = unknown_hosts;
	merger->conflict_count = conflicts;
	merger->built = true;

	/* The list only holds borrowed pointers; do not free its items. */
	oscap_list_free0(ordered_groups);
	_free_groups(groups);

	return merger->benchmark;
}

int xccdf_result_merger_export(struct xccdf_result_merger *merger, const char *filepath)
{
	if (merger == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF, "Cannot export a NULL merger.");
		return -1;
	}
	struct xccdf_benchmark *benchmark = xccdf_result_merger_get_benchmark(merger);
	if (benchmark == NULL) {
		oscap_seterr(OSCAP_EFAMILY_XCCDF,
			"Nothing to export: no usable TestResult has been added.");
		return -1;
	}
	struct oscap_source *source = xccdf_benchmark_export_source(benchmark, filepath);
	if (source == NULL)
		return -1;
	int ret = oscap_source_save_as(source, filepath);
	oscap_source_free(source);
	return ret == 0 ? 0 : -1;
}
