/* Copyright (C) 2020 Konrad Gräfe <kgraefe@paktolos.net>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#pragma once

#include "config.h"

#include <purple.h>
#include <pidgin.h>
#include <gtkplugin.h>
#include <glib.h>

#if GLIB_CHECK_VERSION(2,4,0)
#include <glib/gi18n-lib.h>
#else
#include <locale.h>
#include <libintl.h>
#define _(String) dgettext (GETTEXT_PACKAGE, String)
#define Q_(String) g_strip_context ((String), dgettext (GETTEXT_PACKAGE, String))
#ifdef gettext_noop
#define N_(String) gettext_noop (String)
#else
#define N_(String) (String)
#endif
#endif

#define debug(fmt, ...) \
	purple_debug_info(PLUGIN_STATIC_NAME, fmt, ##__VA_ARGS__)
#define warning(fmt, ...) \
	purple_debug_warning(PLUGIN_STATIC_NAME, fmt, ##__VA_ARGS__)
#define error(fmt, ...) \
	purple_debug_error(PLUGIN_STATIC_NAME, fmt, ##__VA_ARGS__)
