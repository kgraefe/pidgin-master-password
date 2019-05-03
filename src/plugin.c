/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"
#include "masterkey.h"

static PurplePlugin *plugin = NULL;
static struct MasterKey *key = NULL;

static void init_masterkey(void);
static void init_masterkey_cb(
	void *user_data, PurpleRequestFields *fields
) {
	const char *a, *b;
	gchar *hash;

	a = purple_request_fields_get_string(fields, "passwordA");
	b = purple_request_fields_get_string(fields, "passwordB");

	if(a && b && *a && purple_strequal(a, b)) {
		key = masterkey_create(a);
		hash = masterkey_get_hash(key);
		debug("Master Key Hash: %s\n", hash);
		purple_prefs_set_string(PLUGIN_PREFS_PREFIX "/password", hash);
		g_free(hash);
	} else {
		init_masterkey();
	}
}
static void init_masterkey(void) {
	PurpleRequestFields *fields;
	PurpleRequestField *f;
	PurpleRequestFieldGroup *group;

	group = purple_request_field_group_new(NULL);

	f = purple_request_field_string_new(
		"passwordA", _("Master Password"), NULL, FALSE
	);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(group, f);

	f = purple_request_field_string_new(
		"passwordB", _("Confirmation"), NULL, FALSE
	);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(group, f);

	fields = purple_request_fields_new();
	purple_request_fields_add_group(fields, group);

	purple_request_fields(plugin,
		_("Master Password"), _("Enter new master password:"), NULL, fields,
		_("OK"), G_CALLBACK(init_masterkey_cb),
		_("Cancel"), G_CALLBACK(NULL),
		NULL, NULL, NULL, NULL
	);
}

static void unlock_masterkey(void);
static void unlock_masterkey_cb(
	void *user_data, PurpleRequestFields *fields
) {
	key = masterkey_from_hash(
		purple_request_fields_get_string(fields, "masterpassword"),
		purple_prefs_get_string(PLUGIN_PREFS_PREFIX "/password")
	);
	if(!key) {
		unlock_masterkey();
	}
}
static void unlock_masterkey(void) {
	PurpleRequestFields *fields;
	PurpleRequestField *f;
	PurpleRequestFieldGroup *group;

	group = purple_request_field_group_new(NULL);

	f = purple_request_field_string_new(
		"masterpassword", _("Master Password"), NULL, FALSE
	);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(group, f);

	fields = purple_request_fields_new();
	purple_request_fields_add_group(fields, group);

	purple_request_fields(plugin,
		_("Master Password"), _("Enter master password:"), NULL, fields,
		_("OK"), G_CALLBACK(unlock_masterkey_cb),
		_("Cancel"), G_CALLBACK(NULL),
		NULL, NULL, NULL, NULL
	);
}

static gboolean plugin_load(PurplePlugin *p) {
	plugin = p;

	if(purple_prefs_exists(PLUGIN_PREFS_PREFIX "/password")) {
		unlock_masterkey();
	} else {
		init_masterkey();
	}

	debug("Master password plugin loaded.\n");
	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *p) {
	if(key) {
		masterkey_free(key);
		key = NULL;
	}
	purple_request_close_with_handle(plugin);
	debug("Master password plugin unloaded.\n");
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
	info.dependencies = g_list_prepend(info.dependencies, "ssl-nss");
	info.dependencies = g_list_prepend(info.dependencies, "purple-kgraefe-more-ciphers");

	info.name        = _("Master Password");
	info.summary     = _("Protect account passwords by a master password.");
	info.description = _("Protect account passwords by a master password.");

	purple_prefs_add_none(PLUGIN_PREFS_PREFIX);
}

PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
