/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#pragma once

#include <glib.h>

struct MasterKey;

gchar *masterkey_get_hash(struct MasterKey *);

struct MasterKey *masterkey_create(const gchar *password);

struct MasterKey *masterkey_from_hash(
	const gchar *password, const gchar *hash
);

void masterkey_free(struct MasterKey *);
