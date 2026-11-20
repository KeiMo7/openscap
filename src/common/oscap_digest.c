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

#include "oscap_digest.h"

#include <openssl/evp.h>

#include "common/debug_priv.h"

char *oscap_digest_sha256_hex(const void *data, size_t size)
{
	if (data == NULL)
		return NULL;

	unsigned char raw[EVP_MAX_MD_SIZE];
	unsigned int raw_len = 0;

	if (EVP_Digest(data, size, raw, &raw_len, EVP_sha256(), NULL) != 1) {
		dE("EVP_Digest (SHA-256) failed.");
		return NULL;
	}
	if (raw_len != 32) {
		dE("Unexpected SHA-256 digest length: %u.", raw_len);
		return NULL;
	}

	char *hex = malloc(OSCAP_DIGEST_SHA256_HEX_LEN + 1);
	if (hex == NULL)
		return NULL;

	static const char digits[] = "0123456789abcdef";
	for (unsigned int i = 0; i < raw_len; ++i) {
		hex[2 * i] = digits[(raw[i] >> 4) & 0x0F];
		hex[2 * i + 1] = digits[raw[i] & 0x0F];
	}
	hex[OSCAP_DIGEST_SHA256_HEX_LEN] = '\0';
	return hex;
}
