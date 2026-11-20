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
 *
 * Buffer-level cryptographic digest helpers used by the content identity
 * machinery.  The identity of a piece of SCAP content must be derivable
 * from the content bytes themselves, independent of author-supplied
 * version strings and timestamps.
 */

#pragma once
#ifndef OSCAP_DIGEST_H
#define OSCAP_DIGEST_H

#include <stddef.h>

/**
 * Compute SHA-256 over a memory buffer and return the digest as a
 * freshly allocated lowercase hex string (64 characters + NUL).
 * Returns NULL on failure.
 */
char *oscap_digest_sha256_hex(const void *data, size_t size);

/**
 * Length of the hex string returned by oscap_digest_sha256_hex,
 * excluding the terminating NUL byte.
 */
#define OSCAP_DIGEST_SHA256_HEX_LEN 64

#endif
