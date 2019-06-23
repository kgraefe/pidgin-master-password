/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "masterkey.h"

#include "plugin.h"

#define MASTER_KEY_LEN 32
#define PASSWORD_IV_LEN 12
#define PASSWORD_TAG_LEN 16

struct MasterKey {
	guchar *key;
	size_t keyLen;

	guchar *salt;
	size_t saltLen;

	guchar *hash;
	size_t hashLen;

	GHashTable *hashOptions;
};

static guchar *random(size_t len) {
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;
	guchar *buf = NULL;
	size_t outLen;

	cipher = purple_ciphers_find_cipher("random");
	if(!cipher) {
		error("Could not find cipher 'random'!\n");
		goto error;
	}
	ctx = purple_cipher_context_new(cipher, NULL);
	if(!ctx) {
		error("Could not create cipher context!\n");
		goto error;
	}

	buf = g_malloc(len);
	if(!buf) {
		error("Could not allocate memory!\n");
		goto error;
	}

	if(!purple_cipher_context_digest(ctx,
		len, buf, &outLen
	)) {
		error("Could not generate random bytes!\n");
		goto error;
	}
	if(outLen != len) {
		error("Could not generate enough random bytes!\n");
		goto error;
	}

	purple_cipher_context_destroy(ctx);

	return buf;

error:
	if(ctx) {
		purple_cipher_context_destroy(ctx);
	}
	g_free(buf);
	return NULL;
}

static guchar *derive_key(
	const guchar *input, size_t inLen,
	guchar *salt, size_t saltLen,
	size_t *outLen,
	GHashTable *options
) {
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;
	guchar *digest = NULL, *ret = NULL;
	GList *opts = NULL, *l;
	gpointer opt, val;

	cipher = purple_ciphers_find_cipher("argon2id");
	if(!cipher) {
		error("Could not find cipher 'argon2id'!\n");
		goto exit;
	}
	ctx = purple_cipher_context_new(cipher, NULL);
	if(!ctx) {
		error("Could not create cipher context!\n");
		goto exit;
	}

	opts = g_hash_table_get_keys(options);
	for(l = opts; l; l = l->next) {
		opt = l->data;
		if(!opt) {
			continue;
		}
		val = g_hash_table_lookup(options, opt);
		purple_cipher_context_set_option(ctx, opt, val);
	}

	purple_cipher_context_set_option(ctx, "saltlen", GINT_TO_POINTER(saltLen));
	purple_cipher_context_set_salt(ctx, salt);
	purple_cipher_context_set_option(ctx,
		"outlen", GINT_TO_POINTER(MASTER_KEY_LEN)
	);

	purple_cipher_context_append(ctx, input, inLen);

	digest = g_malloc(MASTER_KEY_LEN);
	if(!digest) {
		error("Could not allocate memory!\n");
		goto exit;
	}

	if(!purple_cipher_context_digest(ctx,
		MASTER_KEY_LEN, digest, outLen
	)) {
		error("Could not generate hash!\n");
		goto exit;
	}

	ret = digest;

exit:
	if(ctx) {
		purple_cipher_context_destroy(ctx);
	}
	if(opts) {
		g_list_free(opts);
	}
	if(!ret) {
		g_free(digest);
	}

	return ret;
}

static guchar *hash(
	const guchar *input, size_t inLen, size_t *outLen
) {
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;
	guchar *digest = NULL, *ret = NULL;

	cipher = purple_ciphers_find_cipher("sha512");
	if(!cipher) {
		error("Could not find cipher 'sha512'!\n");
		goto exit;
	}
	ctx = purple_cipher_context_new(cipher, NULL);
	if(!ctx) {
		error("Could not create cipher context!\n");
		goto exit;
	}


	purple_cipher_context_append(ctx, input, inLen);

	*outLen = (512 / 8);
	digest = g_malloc(*outLen);
	if(!digest) {
		error("Could not allocate memory!\n");
		goto exit;
	}

	if(!purple_cipher_context_digest(ctx,
		*outLen, digest, outLen
	)) {
		error("Could not generate hash!\n");
		goto exit;
	}

	ret = digest;

exit:
	if(ctx) {
		purple_cipher_context_destroy(ctx);
	}
	if(!ret) {
		g_free(digest);
	}

	return ret;
}

static void hash_options_from_string(struct MasterKey *key, const char *str) {
	gchar **options = NULL, **option;
	gchar *opt, *val, *t;
	gint ival;

	options = g_strsplit(str, ",", -1);
	for(option = options; *option; option++) {
		opt = *option;
		val = strchr(opt, '=');
		if(!val) {
			continue;
		}
		*val = '\0';
		val++;
		ival = strtol(val, &t, 10);
		if(t == val || *t != '\0' || ival == LONG_MIN || ival == LONG_MAX) {
			continue;
		}

		g_hash_table_insert(key->hashOptions,
			g_strdup(opt), GINT_TO_POINTER(ival)
		);
	}

	if(options) {
		g_strfreev(options);
	}
}

gchar *masterkey_get_hash(struct MasterKey *key) {
	gboolean success = FALSE;
	GString *str = NULL;
	GList *opts = NULL, *l;
	gchar *opt, *tmp;
	const gchar *delimiter;
	gint val;

	str = g_string_new(NULL);
	if(!str) {
		return NULL;
	}

	/* Start with algorithm index (currently we support only one) */
	str = g_string_append(str, "$1");

	/* Append parameters */
	str = g_string_append(str, "$");
	delimiter = "";
	opts = g_hash_table_get_keys(key->hashOptions);
	for(l = opts; l; l = l->next) {
		opt = l->data;
		if(
			!opt
			|| purple_strequal(opt, "saltlen")
		) {
			continue;
		}
		val = GPOINTER_TO_INT(g_hash_table_lookup(key->hashOptions, opt));
		g_string_append_printf(str, "%s%s=%d", delimiter, opt, val);
		delimiter = ",";
	}
	g_list_free(opts);

	/* Append salt */
	tmp = g_base64_encode(key->salt, key->saltLen);
	if(!tmp) {
		goto exit;
	}
	g_string_append(str, "$");
	g_string_append(str, tmp);
	g_free(tmp);

	/* Append hash and finish with '$' */
	tmp = g_base64_encode(key->hash, key->hashLen);
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
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;
	guchar *digest = NULL, *iv = NULL;
	gchar *digestStr = NULL, *ivStr = NULL, *cryptStr = NULL;
	size_t digestLen;

	/* Initialize AES-GCM cipher */
	cipher = purple_ciphers_find_cipher("aes-gcm");
	if(!cipher) {
		error("Could not find cipher 'aes-gcm'!\n");
		goto error;
	}
	ctx = purple_cipher_context_new(cipher, NULL);
	if(!ctx) {
		error("Could not create cipher context!\n");
		goto error;
	}

	/* Generate and set IV */
	iv = random(PASSWORD_IV_LEN);
	if(!iv) {
		goto error;
	}
	purple_cipher_context_set_iv(ctx, iv, PASSWORD_IV_LEN);

	/* Set AES key and GCM tag length */
	purple_cipher_context_set_key_with_len(ctx, key->key, key->keyLen);
	purple_cipher_context_set_option(ctx,
		"taglen", GINT_TO_POINTER(PASSWORD_TAG_LEN)
	);


	/* Encrypt (result length will be input length + tag length) */
	digestLen = strlen(password) + PASSWORD_TAG_LEN;
	digest = g_malloc(digestLen);
	if(!digest) {
		error("Could not allocate memory!\n");
		goto error;
	}
	if(!purple_cipher_context_encrypt(ctx,
		(const guchar *)password, strlen(password), digest, &digestLen
	) < 0) {
		error("Could not encrypt!\n");
		goto error;
	}

	/* Build digest string */
	ivStr = g_base64_encode(iv, PASSWORD_IV_LEN);
	if(!ivStr) {
		goto error;
	}
	digestStr = g_base64_encode(digest, digestLen);
	if(!digestStr) {
		goto error;
	}
	cryptStr = g_strdup_printf("$1$%s$%s$", ivStr, digestStr);
	if(!cryptStr) {
		error("Could not allocate memory!\n");
		goto error;
	}

	g_free(digestStr);
	g_free(ivStr);
	g_free(iv);
	g_free(digest);
	purple_cipher_context_destroy(ctx);

	return cryptStr;

error:
	g_free(cryptStr);
	g_free(digestStr);
	g_free(ivStr);
	g_free(iv);
	g_free(digest);
	if(ctx) {
		purple_cipher_context_destroy(ctx);
	}
	return NULL;
}
gchar *masterkey_decrypt_password(struct MasterKey *key, const gchar *crypted) {
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;
	guchar *digest = NULL, *iv = NULL;
	gchar *password = NULL;
	gsize digestLen, ivLen, passwordLen;
	gchar **fields = NULL;

	/* Parse crypted string.
	 * Format: $1$iv$encryptedpassword$
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
	if(!fields[2] || !(iv = g_base64_decode(fields[2], &ivLen))) {
		error("Could not parse encrypted string: Invalid IV\n");
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

	/* Initialize AES-GCM cipher */
	cipher = purple_ciphers_find_cipher("aes-gcm");
	if(!cipher) {
		error("Could not find cipher 'aes-gcm'!\n");
		goto error;
	}
	ctx = purple_cipher_context_new(cipher, NULL);
	if(!ctx) {
		error("Could not create cipher context!\n");
		goto error;
	}

	/* Set IV, AES key and GCM tag length */
	purple_cipher_context_set_key_with_len(ctx, key->key, key->keyLen);
	purple_cipher_context_set_iv(ctx, iv, ivLen);
	purple_cipher_context_set_option(ctx,
		"taglen", GINT_TO_POINTER(PASSWORD_TAG_LEN)
	);

	/* Decrypt (buffer length must be input length) */
	password = g_malloc(digestLen);
	if(!password) {
		error("Could not allocate memory!\n");
		goto error;
	}
	if(!purple_cipher_context_decrypt(ctx,
		digest, digestLen, (guchar *)password, &passwordLen
	) < 0) {
		error("Could not decrypt!\n");
		goto error;
	}

	/* Make sure the password is NULL terminated.
	 * (The buffer should be larger than the actual password anyway due to the
	 * tag appended to the ciphertext but we're still checking.)
	 */
	if(passwordLen >= digestLen) {
		goto error;
	}
	password[passwordLen] = '\0';

	purple_cipher_context_destroy(ctx);
	g_strfreev(fields);

	return password;

error:
	g_free(password);
	if(ctx) {
		purple_cipher_context_destroy(ctx);
	}
	g_strfreev(fields);
	return NULL;
}

struct MasterKey *masterkey_create(const gchar *password) {
	struct MasterKey *key;

	key = g_new0(struct MasterKey, 1);
	if(!key) {
		error("Could not allocate memory!\n");
		goto error;
	}

	/* Set default hash parameters */
	key->hashOptions = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, NULL
	);
	hash_options_from_string(key,
		"time-cost=5,memory-cost=131072,lanes=4,threads=4"
	);

	/* Get random salt */
	key->saltLen = 16;
	key->salt = random(key->saltLen);
	if(!key->salt) {
		goto error;
	}

	/* Retrieve master key from password */
	key->key = derive_key(
		(const guchar *)password, strlen(password),
		key->salt, key->saltLen,
		&key->keyLen, key->hashOptions
	);
	if(!key->key) {
		error("Could not generate master key!\n");
		goto error;
	}

	/* Retrieve master key hash from master key */
	key->hash = hash(key->key, key->keyLen, &key->hashLen);
	if(!key->hash) {
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
	guchar *calcHash;
	size_t calcHashLen;

	if(!password || *password == '\0' || !string) {
		goto error;
	}

	key = g_new0(struct MasterKey, 1);
	if(!key) {
		error("Could not allocate memory!\n");
		goto error;
	}

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
	if(!field || !purple_strequal(field, "1")) {
		goto error;
	}
	field++;

	/* Third field are the hash algorithm options. We must split here again. */
	field = fields[idx++];
	if(!field) {
		goto error;
	}
	key->hashOptions = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, NULL
	);
	hash_options_from_string(key, field);

	/* Fourth field is the salt. */
	field = fields[idx++];
	if(!field) {
		goto error;
	}
	key->salt = g_base64_decode(field, &key->saltLen);
	if(!key->salt) {
		goto error;
	}

	/* Fifth field is the hash */
	field = fields[idx++];
	if(!field) {
		goto error;
	}
	key->hash = g_base64_decode(field, &key->hashLen);
	if(!key->hash) {
		goto error;
	}

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
	key->key = derive_key(
		(const guchar *)password, strlen(password),
		key->salt, key->saltLen,
		&key->keyLen, key->hashOptions
	);
	if(!key->key) {
		error("Could not generate master key!\n");
		goto error;
	}

	/* Retrieve master key hash from master key and compare it to what we
	 * expect from the string
	 */
	calcHash = hash(key->key, key->keyLen, &calcHashLen);
	if(!key->hash) {
		error("Could not generate master key hash!\n");
		goto error;
	}

	if(
		calcHashLen != key->hashLen
		|| memcmp(calcHash, key->hash, calcHashLen) != 0
	) {
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
		if(key->key) {
			memset(key->key, 0x00, key->keyLen);
			g_free(key->key);
		}
		if(key->salt) {
			memset(key->salt, 0x00, key->saltLen);
			g_free(key->salt);
		}
		if(key->hash) {
			memset(key->hash, 0x00, key->hashLen);
			g_free(key->hash);
		}
		if(key->hashOptions) {
			g_hash_table_destroy(key->hashOptions);
		}
		memset(key, 0x00, sizeof(struct MasterKey));
		g_free(key);
	}
}
