/* Copyright (C) 2020 Konrad Gräfe <kgraefe@paktolos.net>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

#include <sodium.h>

#include <gtkblist.h>

#if defined(_WIN32)
#	include <win32dep.h>
#endif

#include "masterkey.h"
#include "requesthook.h"

typedef struct
{
	PurpleRequestType type;

	void *user_data;
	GtkWidget *dialog;

	/* ... */
} PidginRequestData;

static PurplePlugin *plugin = NULL;
static struct MasterKey *key = NULL;
static gboolean cancelled;

static gboolean account_decrypt(PurpleAccount *account) {
	const char *encrypted;
	gchar *password;

	if(!key) {
		return FALSE;
	}
	if(purple_account_get_password(account)) {
		return FALSE;
	}

	encrypted = purple_account_get_string(account, "password-encrypted", NULL);
	if(!encrypted) {
		return FALSE;
	}

	password = masterkey_decrypt_password(key, encrypted);
	if(!password) {
		error(
			"Could not decrypt password for %s (%s)\n",
			purple_account_get_username(account),
			purple_account_get_protocol_name(account)
		);
		purple_account_remove_setting(account, "password-encrypted");
		return FALSE;
	}

	purple_account_set_password(account, password);
	purple_account_set_remember_password(account, FALSE);

	return TRUE;
}
static void account_encrypt(PurpleAccount *account, gboolean new) {
	const char *password;
	gchar *encrypted;

	if(!key) {
		return;
	}

	if(new) {
		purple_account_remove_setting(account, "password-encrypted");
	}

	password = purple_account_get_password(account);
	if(!password) {
		return;
	}

	encrypted = masterkey_encrypt_password(key, password);
	if(!encrypted) {
		error(
			"Could not encrypt password for %s (%s)\n",
			purple_account_get_username(account),
			purple_account_get_protocol_name(account)
		);
		return;
	}

	purple_account_set_password(account, NULL);
	purple_account_set_remember_password(account, FALSE);

	purple_account_set_string(account, "password-encrypted", encrypted);
	g_free(encrypted);
}

static void masterkey_loaded_cb(gboolean new) {
	gchar *hash;
	GList *l;

	if(new) {
		hash = masterkey_get_hash(key);
		debug("Master Key Hash: %s\n", hash);
		purple_prefs_set_string(PLUGIN_PREFS_PREFIX "/password", hash);
		purple_prefs_trigger_callback(PLUGIN_PREFS_PREFIX "/password");
		g_free(hash);
	}

	/* Encrypt all stored passwords */
	for(l = purple_accounts_get_all(); l; l = l->next) {
		account_encrypt((PurpleAccount *)l->data, new);
	}

	pidgin_blist_update_plugin_actions();
}

static void dialog_cancel_cb(
	void *user_data, PurpleRequestFields *fields
) {
	cancelled = TRUE;
}

static GtkDialog *dialog_init_masterkey(gboolean change);
static void init_masterkey_cb(
	void *user_data, PurpleRequestFields *fields
) {
	const char *a, *b;
	enum MasterKeySecurity security;

	a = purple_request_fields_get_string(fields, "passwordA");
	b = purple_request_fields_get_string(fields, "passwordB");
	security = purple_request_fields_get_choice(fields, "security");

	if(a && b && *a && purple_strequal(a, b)) {
		key = masterkey_create(a, security);
	} else {
		warning("Master passwords do not match!\n");
	}

	/* Either start using the new key or spawn the dialog again. If we are
	 * running at Pidgin's startup this will be handled in plugin_load().
	 */
	if(gtk_main_level() != 0) {
		if(key) {
			masterkey_loaded_cb(TRUE);
		} else {
			dialog_init_masterkey(FALSE);
		}
	}
}
static void change_masterkey_cb(
	void *user_data, PurpleRequestFields *fields
) {
	const char *a, *b;
	enum MasterKeySecurity security;
	struct MasterKey *oldKey = NULL, *newKey = NULL;
	GList *l;

	if(!key) {
		error("Cannot change Master Password in locked state!\n");
		return;
	}

	a = purple_request_fields_get_string(fields, "passwordA");
	b = purple_request_fields_get_string(fields, "passwordB");
	security = purple_request_fields_get_choice(fields, "security");

	/* Check old password */
	oldKey = masterkey_from_hash(
		purple_request_fields_get_string(fields, "passwordOld"),
		purple_prefs_get_string(PLUGIN_PREFS_PREFIX "/password")
	);
	if(!oldKey) {
		warning("Wrong Master Password!\n");
		dialog_init_masterkey(TRUE);
		goto resubmission;
	}

	/* Check new passwords */
	if(a && b && *a && purple_strequal(a, b)) {
		newKey = masterkey_create(a, security);
	} else {
		warning("Master passwords do not match!\n");
		goto resubmission;
	}
	if(!newKey) {
		error("could not create new key!\n");
		goto resubmission;
	}

	/* Replace the global key with our local old key. This should normally be
	 * the same but an attacker might change the hash in the settings to pass
	 * the test above.
	 */
	masterkey_free(key);
	key = oldKey;

	/* Decrypt all accounts with the old key. */
	for(l = purple_accounts_get_all(); l; l = l->next) {
		account_decrypt((PurpleAccount *)l->data);
	}

	/* Set new key globally and encrypt all accounts */
	key = newKey;
	masterkey_loaded_cb(TRUE);

	masterkey_free(oldKey);
	return;

resubmission:
	masterkey_free(oldKey);
	masterkey_free(newKey);
	dialog_init_masterkey(TRUE);
}
static GtkDialog *dialog_init_masterkey(gboolean change) {
	PurpleRequestFields *fields;
	PurpleRequestField *f;
	PurpleRequestFieldGroup *group;
	PidginRequestData *data;
	GCallback ok_cb;

	group = purple_request_field_group_new(NULL);

	if(change) {
		f = purple_request_field_string_new(
			"passwordOld", _("Current Master Password"), NULL, FALSE
		);
		purple_request_field_string_set_masked(f, TRUE);
		purple_request_field_set_required(f, TRUE);
		purple_request_field_group_add_field(group, f);
	}

	f = purple_request_field_string_new(
		"passwordA", _("New Master Password"), NULL, FALSE
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

	f = purple_request_field_choice_new(
		"security", _("Security Level"), MASTER_KEY_SECURITY_MODERATE
	);
	/* The indices MUST correspond to enum MasterKeySecurity! */
	purple_request_field_choice_add(f, _("Interactive (fastest)"));
	purple_request_field_choice_add(f, _("Moderate"));
	purple_request_field_choice_add(f, _("Sensitive (slowest)"));
	purple_request_field_group_add_field(group, f);

	fields = purple_request_fields_new();
	purple_request_fields_add_group(fields, group);

	if(change) {
		ok_cb = G_CALLBACK(change_masterkey_cb);
	} else {
		ok_cb = G_CALLBACK(init_masterkey_cb);
	}

	data = purple_request_fields(plugin,
		_("Pidgin Master Password"), _("Enter new master password:"), NULL, fields,
		_("OK"), ok_cb,
		_("Cancel"), G_CALLBACK(dialog_cancel_cb),
		NULL, NULL, NULL, NULL
	);
	if(!data) {
		return NULL;
	}

#if defined(_WIN32)
	gtk_window_set_title(GTK_WINDOW(data->dialog), _("Pidgin Master Password"));
#endif

	return GTK_DIALOG(data->dialog);
}

static GtkDialog *dialog_unlock_masterkey(void);
static void unlock_masterkey_cb(
	void *data, PurpleRequestFields *fields
) {
	key = masterkey_from_hash(
		purple_request_fields_get_string(fields, "masterpassword"),
		purple_prefs_get_string(PLUGIN_PREFS_PREFIX "/password")
	);

	/* Either start using the key or spawn the dialog again. If we are running
	 * at Pidgin's startup this will be handled in plugin_load().
	 */
	if(gtk_main_level() != 0) {
		if(key) {
			masterkey_loaded_cb(FALSE);
		} else {
			dialog_unlock_masterkey();
		}
	}
}
static GtkDialog *dialog_unlock_masterkey(void) {
	PurpleRequestFields *fields;
	PurpleRequestField *f;
	PurpleRequestFieldGroup *group;
	PidginRequestData *data;

	group = purple_request_field_group_new(NULL);

	f = purple_request_field_string_new(
		"masterpassword", _("Master Password"), NULL, FALSE
	);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(group, f);

	fields = purple_request_fields_new();
	purple_request_fields_add_group(fields, group);

	data = purple_request_fields(plugin,
		_("Pidgin Master Password"), _("Enter master password:"), NULL, fields,
		_("OK"), G_CALLBACK(unlock_masterkey_cb),
		_("Cancel"), G_CALLBACK(dialog_cancel_cb),
		NULL, NULL, NULL, NULL
	);
	if(!data) {
		return NULL;
	}

#if defined(_WIN32)
	gtk_window_set_title(GTK_WINDOW(data->dialog), _("Pidgin Master Password"));
#endif

	return GTK_DIALOG(data->dialog);
}

static void delete_masterkey(gboolean delete_account_passwords) {
	PurpleAccount *account;
	GList *l;

	/* Delete or decrypt all account passwords */
	for(l = purple_accounts_get_all(); l; l = l->next) {
		account = (PurpleAccount *)l->data;

		if(key && !delete_account_passwords) {
			account_decrypt(account);
			if(purple_account_get_password(account)) {
				purple_account_set_remember_password(account, TRUE);
			}
		}
		purple_account_remove_setting(account, "password-encrypted");
	}

	/* Delete master key hash */
	purple_prefs_remove(PLUGIN_PREFS_PREFIX "/password");

	/* Delete master key */
	if(key) {
		masterkey_free(key);
		key = NULL;
	}

	pidgin_blist_update_plugin_actions();
}

static void dialog_delete_masterkey_unlocked(void);
static void dialog_delete_masterkey_unlocked_cb(
	void *user_data, PurpleRequestFields *fields
) {
	struct MasterKey *checkKey;

	/* Check password */
	checkKey = masterkey_from_hash(
		purple_request_fields_get_string(fields, "password"),
		purple_prefs_get_string(PLUGIN_PREFS_PREFIX "/password")
	);
	if(!checkKey) {
		warning("Wrong Master Password!\n");
		dialog_delete_masterkey_unlocked();
		return;
	}

	masterkey_free(checkKey);

	delete_masterkey(
		(purple_request_fields_get_choice(fields, "how") == 0)
	);
}
static void dialog_delete_masterkey_unlocked(void) {
	PurpleRequestFields *fields;
	PurpleRequestField *f;
	PurpleRequestFieldGroup *group;

	group = purple_request_field_group_new(NULL);

	f = purple_request_field_string_new(
		"password", _("Master Password"), NULL, FALSE
	);
	purple_request_field_string_set_masked(f, TRUE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(group, f);

	f = purple_request_field_choice_new(
		"how", _("Account Passwords:"), 0
	);
	purple_request_field_choice_add(f,
		_("Delete")
	);
	purple_request_field_choice_add(f,
		_("Store in plaintext")
	);
	purple_request_field_group_add_field(group, f);

	fields = purple_request_fields_new();
	purple_request_fields_add_group(fields, group);

	purple_request_fields(plugin,
		_("Pidgin Master Password"), _("Delete Master Password?"),
		NULL, fields,
		_("_Yes"), G_CALLBACK(dialog_delete_masterkey_unlocked_cb),
		_("_No"), G_CALLBACK(dialog_cancel_cb),
		NULL, NULL, NULL, NULL
	);
}

static void delete_masterkey_locked_cb(void *data, int i) {
	delete_masterkey(TRUE /* delete account passwords */ );
}
static void dialog_delete_masterkey_locked(void) {
	purple_request_yes_no(plugin,
		_("Pidgin Master Password"), _("Delete Master Password?"),
		_("This will delete all encrypted account passwords."),
		1, /* Default to "No" */
		NULL, NULL, NULL, NULL,
		G_CALLBACK(delete_masterkey_locked_cb),
		G_CALLBACK(dialog_cancel_cb)
	);
}

static void action_lock_cb(PurplePluginAction *action) {
	if(key) {
		masterkey_free(key);
		key = NULL;
		pidgin_blist_update_plugin_actions();
	}
}
static void action_change_cb(PurplePluginAction *action) {
	dialog_init_masterkey(TRUE);
}
static void action_unlock_cb(PurplePluginAction *action) {
	dialog_unlock_masterkey();
}
static void action_delete_cb(PurplePluginAction *action) {
	if(key) {
		dialog_delete_masterkey_unlocked();
	} else {
		dialog_delete_masterkey_locked();
	}
}
static void action_init_cb(PurplePluginAction *action) {
	dialog_init_masterkey(FALSE);
}
static GList *plugin_actions(PurplePlugin *plugin, gpointer context) {
	GList *l = NULL;

	if(key) {
		l = g_list_append(l, purple_plugin_action_new(
			_("Lock"), action_lock_cb
		));
		l = g_list_append(l, purple_plugin_action_new(
			_("Change"), action_change_cb
		));
		l = g_list_append(l, purple_plugin_action_new(
			_("Delete"), action_delete_cb
		));
	} else if(purple_prefs_exists(PLUGIN_PREFS_PREFIX "/password")) {
		l = g_list_append(l, purple_plugin_action_new(
			_("Unlock"), action_unlock_cb
		));
		l = g_list_append(l, purple_plugin_action_new(
			_("Delete"), action_delete_cb
		));
	} else {
		l = g_list_append(l, purple_plugin_action_new(
			_("Initialize"), action_init_cb
		));
	}
	return l;
}

static void account_connecting_cb(PurpleAccount *account, void *data) {
	debug("account-connecting: %s (%s)\n",
		purple_account_get_username(account),
		purple_account_get_protocol_name(account)
	);
	account_decrypt(account);
}
static void account_signed_on_cb(PurpleAccount *account, void *data) {
	const char *pw;

	debug("account-signed-on: %s (%s)\n",
		purple_account_get_username(account),
		purple_account_get_protocol_name(account)
	);

	account_encrypt(account, FALSE);

	/* Clear account password */
	pw = purple_account_get_password(account);
	if(pw) {
		sodium_memzero((char *)pw, strlen(pw));
	}
	purple_account_set_password(account, NULL);
}

static gboolean plugin_load(PurplePlugin *p) {
	plugin = p;

	debug("Using libsodium %s\n", sodium_version_string());

	if(sodium_init() < 0) {
		error("Could not initialize libsodium!\n");
		return FALSE;
	}

	/* Issue either unlock or init dialog to load/create a master key. */
	if(gtk_main_level() > 0) {
		if(purple_prefs_exists(PLUGIN_PREFS_PREFIX "/password")) {
			dialog_unlock_masterkey();
		} else {
			dialog_init_masterkey(FALSE);
		}
	} else {
		/* We are running at Pidgin's startup so we block here using
		 * gtk_dialog_run() to avoid protocols to connect before we are fully
		 * initialized.
		 */
		cancelled = FALSE;
		do {
			if(purple_prefs_exists(PLUGIN_PREFS_PREFIX "/password")) {
				gtk_dialog_run(dialog_unlock_masterkey());
				if(key) {
					masterkey_loaded_cb(FALSE);
				}
			} else {
				gtk_dialog_run(dialog_init_masterkey(FALSE));
				if(key) {
					masterkey_loaded_cb(TRUE);
				}
			}
		} while(!key && !cancelled);
	}

	purple_signal_connect(purple_accounts_get_handle(),
		"account-connecting", plugin,
		PURPLE_CALLBACK(account_connecting_cb), NULL
	);
	purple_signal_connect(purple_accounts_get_handle(),
		"account-signed-on", plugin,
		PURPLE_CALLBACK(account_signed_on_cb), NULL
	);

	/* For protocols that always require a password, Pidgin ask for the
	 * password *before* sending the "account-connecting" signal. Therefore we
	 * need to hook into the request API to catch the password request dialogs.
	 */
	request_hook_install(account_decrypt);

	debug("Master password plugin loaded.\n");
	return TRUE;
}
static gboolean plugin_unload(PurplePlugin *p) {
	if(key) {
		masterkey_free(key);
		key = NULL;
	}
	purple_request_close_with_handle(plugin);
	purple_signals_disconnect_by_handle(plugin);
	request_hook_uninstall();

	debug("Master password plugin unloaded.\n");
	return TRUE;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,     /* type           */
	PIDGIN_PLUGIN_TYPE,         /* ui_requirement */
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
	plugin_actions,             /* actions        */
	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin *plugin) {
#if defined(ENABLE_NLS)
	const char *str = "Master Password";
	gchar *plugins_locale_dir;

	plugins_locale_dir = g_build_filename(purple_user_dir(), "locale", NULL);

	bindtextdomain(GETTEXT_PACKAGE, plugins_locale_dir);
	if(str == _(str)) {
		bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
	}
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");

	g_free(plugins_locale_dir);
#endif

	info.name        = _("Master Password");
	info.summary     = _("Protect account passwords by a master password.");
	info.description = _("Protect account passwords by a master password.");

	purple_prefs_add_none(PLUGIN_PREFS_PREFIX);
}

PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
