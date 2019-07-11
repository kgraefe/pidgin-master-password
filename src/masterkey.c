/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "masterkey.h"

#include <sodium.h>

#include "plugin.h"

#define MASTER_KEY_LEN crypto_secretbox_KEYBYTES
#define MASTER_KEY_HASH_LEN crypto_generichash_blake2b_BYTES_MAX
#define MASTER_KEY_SALT_LEN crypto_pwhash_SALTBYTES
#define PASSWORD_NONCE_LEN crypto_secretbox_NONCEBYTES
#define PASSWORD_TAG_LEN crypto_secretbox_MACBYTES

struct MasterKey {
	unsigned char key[MASTER_KEY_LEN];
	unsigned char salt[MASTER_KEY_SALT_LEN];
	unsigned char hash[MASTER_KEY_HASH_LEN];

	unsigned long long opslimit;
	size_t memlimit;
	int alg;
};

static void hash_options_from_string(struct MasterKey *key, const char *str) {
	gchar **options = NULL, **option;
	gchar *opt, *val, *t;
	unsigned long long ival;

	options = g_strsplit(str, ",", -1);
	for(option = options; *option; option++) {
		opt = *option;
		val = strchr(opt, '=');
		if(!val) {
			continue;
		}
		*val = '\0';
		val++;
		ival = strtoll(val, &t, 10);
		if(t == val || *t != '\0') {
			continue;
		}

		if(purple_utf8_strcasecmp(opt, "opslimit") == 0) {
			key->opslimit = ival;
		}
		if(purple_utf8_strcasecmp(opt, "memlimit") == 0) {
			key->memlimit = ival;
		}
	}

	if(options) {
		g_strfreev(options);
	}
}

gchar *masterkey_get_hash(struct MasterKey *key) {
	gboolean success = FALSE;
	GString *str = NULL;
	gchar *tmp;

	str = g_string_new(NULL);
	if(!str) {
		return NULL;
	}

	/* Start with algorithm index (currently we support only one) */
	g_string_append_printf(str, "$%d", key->alg);

	/* Append options */
	g_string_append_printf(str,
		"$opslimit=%I64u,memlimit=%d",
		key->opslimit, key->memlimit
	);

	/* Append salt */
	tmp = g_base64_encode(key->salt, MASTER_KEY_SALT_LEN);
	if(!tmp) {
		goto exit;
	}
	g_string_append(str, "$");
	g_string_append(str, tmp);
	g_free(tmp);

	/* Append hash and finish with '$' */
	tmp = g_base64_encode(key->hash, MASTER_KEY_HASH_LEN);
	if(!tmp) {
		goto exit;
	}
	g_string_append(str, "$");
	g_string_append(str, tmp);
	g_free(tmp);

	/* Finish with '$' */
	g_string_append(str, "$");

	success = TRUE;

exit:
	/* g_string_free() frees the data and returns NULL if free_segment (second
	 * parameter) is TRUE. Otherwise it frees internal data structures and
	 * returns the data buffer to the caller. In that case the buffer must be
	 * free'd using g_free().
	 */
	return g_string_free(str, !success);
}
gchar *masterkey_encrypt_password(struct MasterKey *key, const char *password) {
	guchar *digest = NULL;
	gchar *digestStr = NULL, *nonceStr = NULL, *cryptStr = NULL;
	size_t passwordLen, digestLen;
	unsigned char nonce[PASSWORD_NONCE_LEN];

	passwordLen = strlen(password) + 1;

	/* Generate Nonce */
	randombytes_buf(nonce, PASSWORD_NONCE_LEN);

	/* Encrypt (result length will be input length + tag length) */
	digestLen = passwordLen + PASSWORD_TAG_LEN;
	digest = g_malloc(digestLen);
	if(!digest) {
		error("Could not allocate memory!\n");
		goto error;
	}
	if(crypto_secretbox_easy(digest,
		(unsigned char *)password, passwordLen,
		nonce, key->key
	) != 0) {
		error("Could not encrypt!\n");
		goto error;
	}

	/* Build digest string */
	nonceStr = g_base64_encode(nonce, PASSWORD_NONCE_LEN);
	if(!nonceStr) {
		goto error;
	}
	digestStr = g_base64_encode(digest, digestLen);
	if(!digestStr) {
		goto error;
	}
	cryptStr = g_strdup_printf("$1$%s$%s$", nonceStr, digestStr);
	if(!cryptStr) {
		error("Could not allocate memory!\n");
		goto error;
	}

	g_free(digestStr);
	g_free(nonceStr);
	g_free(digest);

	return cryptStr;

error:
	g_free(cryptStr);
	g_free(digestStr);
	g_free(nonceStr);
	g_free(digest);
	return NULL;
}
gchar *masterkey_decrypt_password(struct MasterKey *key, const gchar *crypted) {
	guchar *digest = NULL, *nonce = NULL;
	gchar *password = NULL;
	gsize digestLen, nonceLen;
	gchar **fields = NULL;

	/* Parse crypted string.
	 * Format: $1$nonce$encryptedpassword$
	 */
	fields = g_strsplit(crypted, "$", -1);
	if(!fields) {
		error("Could not parse encrypted string!\n");
		goto error;
	}
	if(!fields[0] || *fields[0] != '\0') {
		error("Could not parse encrypted string: Invalid start\n");
		goto error;
	}
	if(!fields[1] || !purple_strequal(fields[1], "1")) {
		error("Could not parse encrypted string: Invalid algorithm\n");
		goto error;
	}
	if(
		!fields[2]
		|| !(nonce = g_base64_decode(fields[2], &nonceLen))
		|| nonceLen != PASSWORD_NONCE_LEN
	) {
		error("Could not parse encrypted string: Invalid nonce\n");
		goto error;
	}
	if(!fields[3] || !(digest = g_base64_decode(fields[3], &digestLen))) {
		error("Could not parse encrypted string: Invalid ciphertext\n");
		goto error;
	}
	if(!fields[4] || *fields[4] != '\0') {
		error("Could not parse encrypted string: Invalid end\n");
		goto error;
	}

	/* Decrypt */
	password = g_malloc(digestLen);
	if(!password) {
		error("Could not allocate memory!\n");
		goto error;
	}
	if(crypto_secretbox_open_easy(
		(unsigned char *)password,
		digest, digestLen,
		nonce, key->key
	) != 0) {
		error("Could not decrypt!\n");
		goto error;
	}

	g_strfreev(fields);

	return password;

error:
	g_free(password);
	g_strfreev(fields);
	return NULL;
}

struct MasterKey *masterkey_create(const gchar *password) {
	struct MasterKey *key;

	/* Allocate secure memory */
	key = sodium_malloc(sizeof(struct MasterKey));
	if(!key) {
		error("Could not allocate memory!\n");
		goto error;
	}

	/* Set default parameters */
	key->opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
	key->memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
	key->alg = crypto_pwhash_ALG_DEFAULT;

	/* Get random salt */
	randombytes_buf(key->salt, crypto_pwhash_SALTBYTES);

	/* Retrieve master key from password */
	if(crypto_pwhash(
		key->key, MASTER_KEY_LEN, 
		password, strlen(password),
		key->salt, key->opslimit, key->memlimit, key->alg
	) != 0) {
		error("Could not generate master key!\n");
		goto error;
	}

	/* Retrieve master key hash from master key */
	if(crypto_generichash(
		key->hash, MASTER_KEY_HASH_LEN,
		key->key, MASTER_KEY_LEN,
		NULL, 0
	) != 0) {
		error("Could not generate master key hash!\n");
		goto error;
	}

	return key;

error:
	masterkey_free(key);
	return NULL;
}

struct MasterKey *masterkey_from_hash(
	const gchar *password, const gchar *string
) {
	struct MasterKey *key = NULL;
	gchar **fields = NULL, *field;
	int idx = 0;
	guchar calcHash[MASTER_KEY_HASH_LEN];
	guchar *buf;
	size_t bufLen;

	if(!password || *password == '\0' || !string) {
		goto error;
	}

	/* Allocate secure memory */
	key = sodium_malloc(sizeof(struct MasterKey));
	if(!key) {
		error("Could not allocate memory!\n");
		goto error;
	}

	/* Set default parameters */
	key->opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
	key->memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
	key->alg = crypto_pwhash_ALG_DEFAULT;

	/* Split fields */
	fields = g_strsplit(string, "$", -1);
	if(!fields) {
		goto error;
	}

	/* First field is expected to be empty */
	field = fields[idx++];
	if(!field || *field != '\0') {
		goto error;
	}

	/* Second field is expected to be the hash algorithm. We currently support
	 * only one.
	 */
	field = fields[idx++];
	if(!field || !purple_strequal(field, "2")) {
		goto error;
	}
	field++;

	/* Third field are the hash algorithm options. We must split here again. */
	field = fields[idx++];
	if(!field) {
		goto error;
	}
	hash_options_from_string(key, field);

	/* Fourth field is the salt. */
	field = fields[idx++];
	if(!field) {
		goto error;
	}
	buf = g_base64_decode(field, &bufLen);
	if(!buf || bufLen != MASTER_KEY_SALT_LEN) {
		goto error;
	}
	memcpy(key->salt, buf, MASTER_KEY_SALT_LEN);
	g_free(buf);

	/* Fifth field is the hash */
	field = fields[idx++];
	if(!field) {
		goto error;
	}
	buf = g_base64_decode(field, &bufLen);
	if(!buf || bufLen != MASTER_KEY_HASH_LEN) {
		goto error;
	}
	memcpy(key->hash, buf, MASTER_KEY_HASH_LEN);
	g_free(buf);
	

	/* Sixth field must be empty, seventh field must not exist. */
	field = fields[idx++];
	if(!field || *field != '\0') {
		goto error;
	}
	field = fields[idx++];
	if(field) {
		goto error;
	}

	/* Retrieve master key from password */
	if(crypto_pwhash(
		key->key, MASTER_KEY_LEN, 
		password, strlen(password),
		key->salt, key->opslimit, key->memlimit, key->alg
	) != 0) {
		error("Could not generate master key!\n");
		goto error;
	}

	/* Retrieve master key hash from master key and compare it to what we
	 * expect from the string
	 */
	if(crypto_generichash(
		calcHash, MASTER_KEY_HASH_LEN,
		key->key, MASTER_KEY_LEN,
		NULL, 0
	) != 0) {
		error("Could not generate master key hash!\n");
		goto error;
	}

	if(memcmp(calcHash, key->hash, MASTER_KEY_HASH_LEN) != 0) {
		error("Could not load master key: Hash mismatch (wrong password?)\n");
		goto error;
	}

	g_strfreev(fields);
	return key;

error:
	if(fields) {
		g_strfreev(fields);
	}
	masterkey_free(key);
	return NULL;
}

void masterkey_free(struct MasterKey *key) {
	if(key) {
		sodium_free(key);
	}
}
