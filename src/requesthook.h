/* Copyright (C) 2020 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#pragma once

#include <purple.h>

typedef gboolean (*AccountDecryptFunc)(PurpleAccount *account);

void request_hook_install(AccountDecryptFunc f);
void request_hook_uninstall(void);
