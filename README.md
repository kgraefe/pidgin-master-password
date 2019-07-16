# Pidgin Master Password

This is a Pidgin plugin that stores account passwords encrypted by a master
password.

If you find security relates issues please send a private (possibly [PGP
encrypted][3]) e-mail to <konradgraefe@aol.com>.

## Security Considerations
During login the account passwords must be sent to Pidgin/libpuple unencrypted.
From there a malicious third-party plugin can collect them **quite easily**.
This is a limitation of libpurple which all password manager and keyring
plugins suffer from.

## Encryption details
All operations are done with high-level [libsodium][2] functions so that best
practices are in place and will be updated with the library.

- From the master password a master key is derived using the [Argon2][4]
  algorithm which is designed to be slow and memory-consuming in order to
  prevent brute-force attacks. The security level choice corresponds to the
  `crypto_pwhash_OPSLIMIT_*` and `crypto_pwhash_MEMLIMIT_*` constants of
  libsodium.
- This master key is used to encrypt the account passwords with
  XChaCha20-Poly1305. This algorithm is equally secure as AES256-GCM but
  [harder to mess up][1].
- To verify the master password a hash of the master key is stored.
- The master key is protected in memory as good as possible by using
  libsodium's [Guarded heap allocations][5].

![encryption](doc/encryption.png)

[1]: https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm
[2]: https://libsodium.gitbook.io/doc/
[3]: https://keybase.io/konradgraefe
[4]: https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#key-derivation
[5]: https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations
