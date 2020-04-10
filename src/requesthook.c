/* Copyright (C) 2020 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "requesthook.h"

typedef struct {
	PurpleAccount *account;
	PurpleRequestFields *fields;
	GCallback ok_cb;
	GCallback cancel_cb;
	gpointer user_data;
} RequestHookData;

static void *(*ui_request_fields)(
	const char *title, const char *primary, const char *secondary,
	PurpleRequestFields *fields, const char *ok_text, GCallback ok_cb,
	const char *cancel_text, GCallback cancel_cb,
	PurpleAccount *account, const char *who,
	PurpleConversation *conv, void *user_data
) = NULL;
static void (*ui_close_request)(
	PurpleRequestType type, void *ui_handle
) = NULL;

static AccountDecryptFunc account_decrypt = NULL;
static GList *handles = NULL;

static gboolean handle_deferred_request_cb(void *p) {
	RequestHookData *data = p;

	purple_request_field_string_set_value(
		purple_request_fields_get_field(data->fields, "password"),
		purple_account_get_password(data->account)
	);
	purple_request_field_bool_set_value(
		purple_request_fields_get_field(data->fields, "remember"),
		FALSE
	);

	if(data->ok_cb) {
		((PurpleRequestFieldsCb)data->ok_cb)(data->user_data, data->fields);
	}

	purple_request_close(PURPLE_REQUEST_FIELDS, data);

	return FALSE;
}

static void *request_fields(
	const char *title, const char *primary, const char *secondary,
	PurpleRequestFields *fields, const char *ok_text, GCallback ok_cb,
	const char *cancel_text, GCallback cancel_cb,
	PurpleAccount *account, const char *who,
	PurpleConversation *conv, void *user_data
) {
	RequestHookData *data;

	if(!account_decrypt || !account) {
		goto passthrough;
	}
	if(!purple_request_fields_get_field(fields, "password")) {
		goto passthrough;
	}
	if(!purple_request_fields_get_field(fields, "remember")) {
		goto passthrough;
	}

	debug("request-password: %s (%s)\n",
		purple_account_get_username(account),
		purple_account_get_protocol_name(account)
	);

	if(!account_decrypt(account)) {
		goto passthrough;
	}

	/* We cannot answer and close the request now since libpurple expects it to
	 * live when we return. Also we MUST NOT return NULL as libpurple does not
	 * check for that and adds the request to an internal list which is than
	 * searched by the pointer we return.  Therefore we allocate some memory
	 * saving the important parameters, return that pointer and handle the
	 * request as soon as Glib hits the idle loop again.
	 *
	 * That also means that we must hook into the close_request() function to
	 * free our own stuff and make sure those pointers are not leaked into the
	 * UI. Otherwise it will dereference our pointer as different structures
	 * and bad things will happen.
	 */
	data = g_new0(RequestHookData, 1);
	data->account = account;
	data->fields = fields;
	data->ok_cb = ok_cb;
	data->cancel_cb = cancel_cb;
	data->user_data = user_data;
	handles = g_list_append(handles, data);
	g_idle_add(handle_deferred_request_cb, data);
	return data;

passthrough:
	return ui_request_fields(
		title, primary, secondary,
		fields, ok_text, ok_cb, cancel_text, cancel_cb,
		account, who, conv, user_data
	);
}

static void close_request(PurpleRequestType type, void *ui_handle) {
	GList *l;
	RequestHookData *data;

	if(account_decrypt) {
		for(l = handles; l != NULL; l = l->next) {
			if(l->data == ui_handle) {
				data = l->data;
				handles = g_list_remove(handles, data);
				g_free(data);
				return;
			}
		}
	}

	/* Handle not found, so it must be a real UI handle. */
	ui_close_request(type, ui_handle);
}

void request_hook_install(AccountDecryptFunc f) {
	PurpleRequestUiOps *ops;

	ops = purple_request_get_ui_ops();
	if(!ops ||  !ops->request_fields) {
		return;
	}

	if(!ui_request_fields) {
		ui_request_fields = ops->request_fields;
		ops->request_fields = request_fields;

		ui_close_request = ops->close_request;
		ops->close_request = close_request;
	}

	account_decrypt = f;
}
void request_hook_uninstall(void) {
	RequestHookData *data;
	GList *l;

	/* If we have any open requests, cancel them now. */
	for(l = handles; l != NULL; l = l->next) {
		data = l->data;
		if(data->cancel_cb) {
			((PurpleRequestFieldsCb)data->cancel_cb)(data->user_data, data->fields);
		}

		purple_request_close(PURPLE_REQUEST_FIELDS, data);
	}

	/* We cannot revert the UI ops hooks since this might lead to a crash if
	 * another plugin uses the same hooks and both plugins get unloaded in the
	 * wrong order. However, since account_decrypt is set to NULL, our hooks
	 * will always just pass-through any calls.
	 */
	account_decrypt = NULL;
}
