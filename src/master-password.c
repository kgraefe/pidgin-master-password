/* Copyright (C) 2018 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#define PURPLE_PLUGINS

#include <plugin.h>
#include <connection.h>
#include <version.h>
#include <debug.h>

#include "config.h"
#include "internal.h"

#define debug(fmt, ...) \
	purple_debug_info(PLUGIN_STATIC_NAME, fmt, ##__VA_ARGS__)
#define error(fmt, ...) \
	purple_debug_error(PLUGIN_STATIC_NAME, fmt, ##__VA_ARGS__)


static gboolean plugin_load(PurplePlugin *plugin) {
	debug("Master password plugin loaded.");
	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin) {
	debug("Master password plugin unloaded.");
	return TRUE;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,     /* type           */
	NULL,                       /* ui_requirement */
	0,                          /* flags          */
	NULL,                       /* dependencies   */
	PURPLE_PRIORITY_DEFAULT,    /* priority       */

	PLUGIN_ID,                  /* id             */
	NULL,                       /* name           */
	PLUGIN_VERSION,             /* version        */
	NULL,                       /* summary        */
	NULL,                       /* description    */
	PLUGIN_AUTHOR,              /* author         */
	PLUGIN_WEBSITE,             /* homepage       */

	plugin_load,                /* load           */
	plugin_unload,              /* unload         */
	NULL,                       /* destroy        */

	NULL,                       /* ui_info        */
	NULL,                       /* extra_info     */
	NULL,                       /* prefs_info     */
	NULL,                       /* actions        */
	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin *plugin) {
	info.name        = _("Master Password");
	info.summary     = _("Protect account passwords by a master password.");
	info.description = _("Protect account passwords by a master password.");
}

PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
