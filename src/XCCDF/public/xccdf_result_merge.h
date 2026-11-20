/**
 * @addtogroup XCCDF
 * @{
 *
 * @file xccdf_result_merge.h
 * Host identity resolution and merging of XCCDF TestResults collected from
 * one or more (possibly remote) machines.
 *
 * The merged output is a regular XCCDF Benchmark with embedded TestResults,
 * so it can be consumed by the existing XCCDF report pipeline and can be
 * imported and merged again.  The original result files are never modified.
 */

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

#ifndef XCCDF_RESULT_MERGE_H_
#define XCCDF_RESULT_MERGE_H_

#include <stdbool.h>
#include <stddef.h>

#include <oscap_export.h>
#include <oscap_source.h>
#include <xccdf_benchmark.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Source of the host identity that was used to group a TestResult.
 *
 * This is the single source of truth for host identity resolution.  The
 * rules below are implemented once, in xccdf_result_get_host_identity(),
 * and are applied both by the result merging and by the merged document
 * that reports consume.  The resolver reads only the XCCDF result metadata
 * that the evaluation itself records through xccdf_result_fill_sysinfo(),
 * so no consumer needs to re-implement the decision.  The priority is:
 *
 *   1. stable identifier (e.g. urn:xccdf:fact:asset:identifier:ein)
 *   2. host name (fully qualified name or short name)
 *   3. network address (only when nothing else is available)
 *
 * A network address is never used to merge two records that carry any
 * stronger identity - addresses are re-assigned between machines and must
 * not tie unrelated machines together.
 */
typedef enum {
	XCCDF_HOST_IDENTITY_UNKNOWN = 0,  ///< no identity information at all
	XCCDF_HOST_IDENTITY_STABLE,       ///< stable machine identifier
	XCCDF_HOST_IDENTITY_HOSTNAME,     ///< host name / FQDN
	XCCDF_HOST_IDENTITY_ADDRESS       ///< network address (last resort)
} xccdf_host_identity_source_t;

/**
 * Convert a host identity source to a stable, human readable string.
 * The returned string is static and must not be freed.
 */
OSCAP_API const char *xccdf_host_identity_source_to_string(xccdf_host_identity_source_t source);

/**
 * Resolve the host identity source of a TestResult using the shared rules.
 * @memberof xccdf_result
 */
OSCAP_API xccdf_host_identity_source_t xccdf_result_get_host_identity_source(const struct xccdf_result *result);

/**
 * Resolve the canonical host identity of a TestResult using the shared rules.
 *
 * The returned string is prefixed with the identity source so that it can be
 * traced, e.g. "stable:host-123", "hostname:web1", "address:10.0.0.1" or
 * "unknown".  For host names the short name is used as the identity token so
 * that "web1" and "web1.example.com" resolve to the same host.
 *
 * @memberof xccdf_result
 * @return newly allocated string, caller is responsible for freeing it
 */
OSCAP_API char *xccdf_result_get_host_identity(const struct xccdf_result *result);

/**
 * Resolve the preferred display name of the target host of a TestResult.
 * @memberof xccdf_result
 * @return newly allocated string, caller is responsible for freeing it
 */
OSCAP_API char *xccdf_result_get_host_display_name(const struct xccdf_result *result);

/**
 * @struct xccdf_result_merger
 *
 * Accumulates XCCDF TestResults from any number of XCCDF result documents,
 * XCCDF Benchmarks and ARF files and produces one merged XCCDF Benchmark with
 * exactly one TestResult per resolved host.
 *
 * The merger never modifies its inputs.  The output is deterministic: the
 * same set of input records always produces the same document regardless of
 * the order of the input files or of the number of merger invocations used to
 * consume them.
 *
 * Merged output can be imported again (it is a valid XCCDF Benchmark with
 * embedded TestResults) and re-merging it yields the same document.
 */
struct xccdf_result_merger;

/// @memberof xccdf_result_merger
OSCAP_API struct xccdf_result_merger *xccdf_result_merger_new(void);

/// @memberof xccdf_result_merger
OSCAP_API void xccdf_result_merger_free(struct xccdf_result_merger *merger);

/**
 * Add all result records found in a single source.
 *
 * Supported documents are XCCDF TestResult documents, XCCDF Benchmarks with
 * embedded TestResults and ARF result data streams.  Every TestResult found
 * in the source is read - a single file containing multiple host records is
 * never truncated to its first record.
 *
 * A malformed record is skipped and counted; the remaining records are still
 * merged.  The number of skipped records is available through
 * xccdf_result_merger_get_skipped_count().
 *
 * @memberof xccdf_result_merger
 * @return 0 on success (even if some records were skipped), -1 on error
 */
OSCAP_API int xccdf_result_merger_add_source(struct xccdf_result_merger *merger, struct oscap_source *source);

/**
 * Add all result records found in the file at the given path.
 * @memberof xccdf_result_merger
 * @return 0 on success, -1 on error
 */
OSCAP_API int xccdf_result_merger_add_file(struct xccdf_result_merger *merger, const char *filepath);

/// @memberof xccdf_result_merger
OSCAP_API size_t xccdf_result_merger_get_record_count(const struct xccdf_result_merger *merger);

/// @memberof xccdf_result_merger
OSCAP_API size_t xccdf_result_merger_get_host_count(const struct xccdf_result_merger *merger);

/// @memberof xccdf_result_merger
OSCAP_API size_t xccdf_result_merger_get_unknown_host_count(const struct xccdf_result_merger *merger);

/// @memberof xccdf_result_merger
OSCAP_API size_t xccdf_result_merger_get_conflict_count(const struct xccdf_result_merger *merger);

/// @memberof xccdf_result_merger
OSCAP_API size_t xccdf_result_merger_get_skipped_count(const struct xccdf_result_merger *merger);

/**
 * Build (or return the already built) merged Benchmark.
 * The returned benchmark is owned by the merger and is valid until the merger
 * is freed.
 * @memberof xccdf_result_merger
 * @return merged benchmark or NULL if no records were merged
 */
OSCAP_API struct xccdf_benchmark *xccdf_result_merger_get_benchmark(struct xccdf_result_merger *merger);

/**
 * Export the merged Benchmark to the given file.
 * @memberof xccdf_result_merger
 * @return 0 on success, -1 on error
 */
OSCAP_API int xccdf_result_merger_export(struct xccdf_result_merger *merger, const char *filepath);

#ifdef __cplusplus
}
#endif

#endif /* XCCDF_RESULT_MERGE_H_ */

/// @}
