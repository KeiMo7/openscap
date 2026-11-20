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
#ifndef XCCDF_IDENTITY_DIFF_PRIV_H
#define XCCDF_IDENTITY_DIFF_PRIV_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "identity_priv.h"
#include "public/xccdf_identity_diff.h"

/**
 * Rule result as recorded in the rule-result elements of a TestResult,
 * keyed by rule id.  Only the outcome text is needed for attribution.
 */
struct cid_rule_outcome {
	char *rule_id;
	char *result;       ///< "pass" | "fail" | "notselected" | ...
};

/**
 * Everything the diff engine needs from one parsed artifact.
 */
struct cid_artifact {
	char *path;
	xmlDocPtr doc;
	xmlNodePtr test_result;
	struct cid_identity *identity; ///< NULL for legacy artifacts
	struct oscap_htable *outcomes; ///< rule id -> cid_rule_outcome (borrowed strings)
	char *target;                  ///< first xccdf:target text
	struct oscap_list *target_facts; ///< "name=value" strings
};

struct cid_diff_entry {
	char *stable_key;
	char *old_id;
	char *new_id;
	cid_diff_category_t category;
	cid_diff_side_t side;
	char *old_result;
	char *new_result;
	char *reason;
	bool old_missing_identity;
	bool new_missing_identity;
};

struct cid_diff_result {
	cid_diff_status_t status;
	char *status_message;
	bool missing_identity;
	struct oscap_list *entries; ///< cid_diff_entry, sorted by stable_key
};

struct cid_artifact *cid_artifact_parse(const char *path);
void cid_artifact_free(struct cid_artifact *artifact);

/** Core matching/attribution routine operating on two parsed artifacts. */
struct cid_diff_result *cid_diff_compute(struct cid_artifact *old_art, struct cid_artifact *new_art);

void cid_diff_entry_free(struct cid_diff_entry *entry);

/** Lookup the outcome text for a rule id, NULL when the rule has no rule-result. */
const char *cid_artifact_outcome(const struct cid_artifact *artifact, const char *rule_id);

#endif
