/* Copyright (C) 2020 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#pragma once

#include <glib.h>

enum MasterKeySecurity {
	MASTER_KEY_SECURITY_INTERACTIVE,
	MASTER_KEY_SECURITY_MODERATE,
	MASTER_KEY_SECURITY_SENSITIVE,
};

struct MasterKey;

gchar *masterkey_get_hash(struct MasterKey *);
gchar *masterkey_encrypt_password(struct MasterKey *, const char *password);
gchar *masterkey_decrypt_password(struct MasterKey *, const gchar *crypted);

struct MasterKey *masterkey_create(
	const gchar *password, enum MasterKeySecurity security
);

struct MasterKey *masterkey_from_hash(
	const gchar *password, const gchar *hash
);

void masterkey_free(struct MasterKey *);
