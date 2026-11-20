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

#pragma once
#ifndef XCCDF_IDENTITY_PRIV_H
#define XCCDF_IDENTITY_PRIV_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libxml/xmlwriter.h>

#include "common/list.h"

#define XCCDF_CID_NS_URI "https://open-scap.org/ns/content-identity/1.0"
#define XCCDF_CID_NS_PREFIX "cid"
#define XCCDF_CID_ALGORITHM "sha256"
#define XCCDF_CID_CANONICALIZATION "c14n-1.0"

struct xccdf_policy;
struct xccdf_session;
struct xccdf_result;
struct xccdf_benchmark;
struct oscap_source;

/**
 * Content-derived identity of one content component that actually
 * participated in the evaluation (XCCDF benchmark, OVAL definitions,
 * CPE dictionary, tailoring profile source).
 */
struct cid_component {
	char *origin;        ///< readable origin (href / path)
	char *content_type;  ///< "xccdf" | "oval" | "cpe" | "tailoring"
	char *digest;        ///< SHA-256 hex over the C14N document bytes
};

/**
 * One tailoring customization entry, snapshotted so offline diffs can
 * attribute result differences to the custom baseline.
 */
struct cid_tailoring_entry {
	char *kind;   ///< "select" | "set-value" | "refine-rule"
	char *idref;  ///< targeted item / value id
	char *value;  ///< textual payload (selected flag, value, or refinement)
};

/**
 * Identity record of the effective tailoring (may be NULL when no
 * tailoring was in use).
 */
struct cid_tailoring {
	char *origin;             ///< tailoring file origin, NULL for in-benchmark profile
	char *digest;             ///< digest of the tailoring component document
	char *profile_id;         ///< effective profile id
	char *benchmark_digest;   ///< digest of the XCCDF component it customizes
	struct oscap_list *entries; ///< cid_tailoring_entry
};

/**
 * Per-rule identity.  All rules of the benchmark are recorded (not only
 * selected ones); @selected marks rules that actually took part in the
 * evaluation.
 */
struct cid_rule {
	char *id;             ///< rule @id as present in the content
	char *cluster_id;     ///< cluster @id, may be NULL
	char *stable_key;     ///< matching key (see key_basis)
	char *key_basis;      ///< "cluster" | "check-ref" | "id"
	char *group_path;     ///< ancestor group ids joined by '/', may be NULL
	char *body_digest;    ///< digest over the full rule subtree
	char *logic_digest;   ///< digest over decision-relevant content only
	char *author_version; ///< author-supplied xccdf:version, may be NULL
	char *check_refs;     ///< sorted "href#name" lines joined by '\n', may be NULL
	bool selected;
	bool customized;
};

/**
 * Full content identity attached to one TestResult.
 */
struct cid_identity {
	char *algorithm;
	char *canonicalization;
	struct oscap_list *components; ///< cid_component
	struct cid_tailoring *tailoring;
	struct oscap_list *rules;      ///< cid_rule
};

struct cid_component *cid_component_new(const char *origin, const char *content_type, const char *digest);
void cid_component_free(struct cid_component *component);

struct cid_tailoring_entry *cid_tailoring_entry_new(const char *kind, const char *idref, const char *value);
void cid_tailoring_entry_free(struct cid_tailoring_entry *entry);
struct cid_tailoring *cid_tailoring_new(void);
void cid_tailoring_free(struct cid_tailoring *tailoring);

struct cid_rule *cid_rule_new(void);
void cid_rule_free(struct cid_rule *rule);

struct cid_identity *cid_identity_new(void);
void cid_identity_free(struct cid_identity *identity);

/** Deep copy of an identity record. */
struct cid_identity *cid_identity_clone(const struct cid_identity *identity);

/**
 * Canonicalize an XML node subtree (whitespace-only text nodes stripped,
 * libxml2 C14N 1.0, comments dropped) and return the resulting bytes.
 * The caller owns the returned buffer (free()).  *out_size receives the
 * byte length.  Returns NULL on failure.
 */
char *cid_c14n_node(xmlNodePtr node, size_t *out_size);

/**
 * SHA-256 hex digest over the canonical bytes of a node subtree.
 * Returns a freshly allocated hex string or NULL.
 */
char *cid_digest_node(xmlNodePtr node);

/**
 * Build the complete content identity for a finished evaluation session.
 * Returns NULL on hard failure; per-rule parse problems are recorded as
 * NULL digests on the affected cid_rule only (degraded, never fatal).
 */
struct cid_identity *cid_identity_build_for_session(struct xccdf_session *session);

/**
 * Serialize the identity into the cid:content-identity element tree and
 * attach it as an xccdf:metadata child of @result_node (which must be an
 * XCCDF 1.2 TestResult element).  Returns 0 on success, -1 on failure.
 */
int cid_identity_attach_dom(const struct cid_identity *identity, xmlNodePtr result_node, xmlDocPtr doc);

/**
 * Parse a cid:content-identity element from an arbitrary result document
 * (standalone TestResult or ARF).  Returns NULL when the document carries
 * no content identity (legacy artifact).
 */
struct cid_identity *cid_identity_parse_from_doc(xmlDocPtr doc);

/**
 * Locate the first TestResult element in a document (ARF or standalone
 * TestResult).  Returns NULL when none is found.
 */
xmlNodePtr cid_find_test_result(xmlDocPtr doc);

/*
 * Internal session accessors used while building the identity.  They are
 * implemented in xccdf_session.c, where the session struct is defined.
 * All returned pointers are borrowed (the session keeps ownership).
 */

/** Effective XCCDF component source (the resolved benchmark document). */
struct oscap_source *cid_session_get_xccdf_source(const struct xccdf_session *session);

/** Tailoring component source, or NULL when no tailoring is in use. */
struct oscap_source *cid_session_get_tailoring_source(const struct xccdf_session *session);

/**
 * NULL-terminated array of OVAL content resource sources actually loaded
 * for the evaluation (user-provided resources take precedence over the
 * ones referenced from the XCCDF content).  Borrowed pointers.
 */
struct oscap_source **cid_session_get_oval_sources(const struct xccdf_session *session, size_t *count);

/**
 * CPE dictionary / language component sources registered with the
 * session, or NULL when there are none.  Borrowed pointers.
 */
struct oscap_source **cid_session_get_cpe_sources(const struct xccdf_session *session, size_t *count);

#endif
