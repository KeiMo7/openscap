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
#ifndef XCCDF_IDENTITY_DIFF_H
#define XCCDF_IDENTITY_DIFF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "oscap_export.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Offline comparison of two XCCDF result artifacts (standalone
 * TestResult documents or ARF result datastreams).
 *
 * The comparison never rescans a target and never accesses the network:
 * every conclusion is derived solely from the two input files.
 */

/** Per-rule attribution categories. */
typedef enum {
	CID_DIFF_UNCHANGED = 0,       ///< result and identity identical
	CID_DIFF_ADDED,               ///< rule exists only in the new artifact
	CID_DIFF_REMOVED,             ///< rule exists only in the old artifact
	CID_DIFF_RENAMED,             ///< stable identity matched, @id changed
	CID_DIFF_MOVED,               ///< stable identity matched, group changed
	CID_DIFF_RESULT_FLIP,         ///< pass/fail outcome changed
	CID_DIFF_VERSION_LABEL_ONLY,  ///< only author version changed, content equal
	CID_DIFF_CONTENT_CHANGED,     ///< rule content/body changed, result equal
	CID_DIFF_UNKNOWN              ///< identity missing, raw result difference
} cid_diff_category_t;

/** Side responsible for an observed difference. */
typedef enum {
	CID_SIDE_NONE = 0,
	CID_SIDE_TARGET,   ///< target-side evidence changed, content identical
	CID_SIDE_CONTENT,  ///< decision content changed, target evidence equal
	CID_SIDE_TAILORING,///< difference introduced by the custom baseline
	CID_SIDE_UNKNOWN   ///< not attributable (missing identity)
} cid_diff_side_t;

/** Overall comparison status, also used as process exit codes. */
typedef enum {
	CID_DIFF_STATUS_OK = 0,             ///< comparison completed
	CID_DIFF_STATUS_TAILORING_MISMATCH = 3, ///< tailoring/content digest mismatch
	CID_DIFF_STATUS_TARGET_INCOMPARABLE = 2, ///< targets not comparable
	CID_DIFF_STATUS_ERROR = 1
} cid_diff_status_t;

struct cid_diff_result;

/**
 * Compare two result artifact files.  Returns a newly allocated result
 * object (free with cid_diff_result_free) or NULL on hard I/O error.
 * @param old_path baseline artifact
 * @param new_path artifact compared against the baseline
 */
OSCAP_API struct cid_diff_result *xccdf_identity_diff_files(const char *old_path, const char *new_path);

OSCAP_API void cid_diff_result_free(struct cid_diff_result *result);

/** Overall status. */
OSCAP_API cid_diff_status_t cid_diff_result_get_status(const struct cid_diff_result *result);

/** Human readable explanation of a gate failure (target mismatch, tailoring mismatch). */
OSCAP_API const char *cid_diff_result_get_status_message(const struct cid_diff_result *result);

/** True when at least one side lacked a content identity (legacy artifact). */
OSCAP_API bool cid_diff_result_has_missing_identity(const struct cid_diff_result *result);

/** Number of per-rule entries. */
OSCAP_API size_t cid_diff_result_get_entry_count(const struct cid_diff_result *result);

struct cid_diff_entry;

OSCAP_API const struct cid_diff_entry *cid_diff_result_get_entry(const struct cid_diff_result *result, size_t index);

OSCAP_API const char *cid_diff_entry_get_stable_key(const struct cid_diff_entry *entry);
OSCAP_API const char *cid_diff_entry_get_old_id(const struct cid_diff_entry *entry);
OSCAP_API const char *cid_diff_entry_get_new_id(const struct cid_diff_entry *entry);
OSCAP_API cid_diff_category_t cid_diff_entry_get_category(const struct cid_diff_entry *entry);
OSCAP_API cid_diff_side_t cid_diff_entry_get_side(const struct cid_diff_entry *entry);
OSCAP_API const char *cid_diff_entry_get_old_result(const struct cid_diff_entry *entry);
OSCAP_API const char *cid_diff_entry_get_new_result(const struct cid_diff_entry *entry);
OSCAP_API const char *cid_diff_entry_get_reason(const struct cid_diff_entry *entry);

/** Stable text rendering (sorted, deterministic) to stdout-like buffer. */
OSCAP_API char *cid_diff_result_render_text(const struct cid_diff_result *result);

/** XML rendering in the cid namespace. */
OSCAP_API char *cid_diff_result_render_xml(const struct cid_diff_result *result);

#ifdef __cplusplus
}
#endif

#endif
