# Pidgin Master Password

[![License](https://img.shields.io/badge/License-GPLv2-blue.svg?style=flat)](COPYING)
[![Download](https://img.shields.io/badge/Download-Latest_Release-brightgreen.svg?style=flat)][6]

This is a Pidgin plugin that stores account passwords encrypted by a master
password.

If you find security relates issues please send a private (possibly [PGP
encrypted][3]) e-mail to <konradgraefe@aol.com>.

## Table of contents
- [Security Considerations](#security-considerations)
- [Installation](#installation)
    - [Installation on Windows](#installation-on-windows)
    - [Installation on Linux](#installation-on-linux)
- [Encryption details](#encryption-details)
- [Building from source](#building-from-source)
    - [Building on Windows](#building-on-windows)
    - [Building on Linux](#building-on-linux)
- [Contribution](#contribution)

## Security Considerations
During login the account passwords must be sent to Pidgin/libpuple unencrypted.
From there a malicious third-party plugin can collect them **quite easily**.
This is a limitation of libpurple which all password manager and keyring
plugins suffer from.

## Installation
### Installation on Windows
Download the ZIP file from the [latest release][6] and extract the contents of
`pidgin-master-password` either to the installation directory of Pidgin
(typically `C:\Program Files\Pidgin`) or to your .purple user directory
(typically `%APPDATA%\Roaming\.purple`).

### Installation on Linux
If your distribution has the plugin in its repository you can use that.
Otherwise you must build the plugin [from source](#building-on-linux).

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

## Building from source
### Building on Windows
In order to build the plugin for Windows an already-compiled source tree of
Pidgin is required. Please see the [Pidgin for Windows Build Instructions][8]
for details. Note that you *must* install `Strawberry Perl` as it is optional
for Pidgin but not for this plugin. The [pidgin-windev][9] does all that.

Additionally you need to download [libsodium-1.0.18-mingw.tar.gz][10] and
extract it into `win32-dev/libsodium-1.0.18-mingw` (the subdirectory must be
created).

After that you need to create a file named `local.mak` that points to the
Pidgin source tree, e.g.:

    PIDGIN_TREE_TOP=$(PLUGIN_TOP)/../../pidgin-2.12.0

Now you can build the plugin:

    make -f Makefile.mingw

### Building on Linux
To install the plugin on Linux you need to extract a release tarball and
compile it from source:

    sudo apt install pidgin-dev libsodium-dev
    ./configure
    make
    sudo make install

**Note:** By default the plugin will be installed to `/usr/local`.  If you
installed Pidgin through your package manager, it is most likely installed into
`/usr` (i.e. `which pidgin` returns `/usr/bin/pidgin`). Use `./configure
--prefix=/usr` in this case.

**Note:** When you use the repository directly or one of those auto-generated
"Source code" archives, you need to run `./autogen.sh` before running
`./configure`.

## Contribution
We love patches. :heart: Please fork the project, do your changes and make a
pull request.

You could also help translating this project on [Transifex][7].


[1]: https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm
[2]: https://libsodium.gitbook.io/doc/
[3]: https://keybase.io/konradgraefe
[4]: https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#key-derivation
[5]: https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations
[6]: https://github.com/kgraefe/pidgin-master-password/releases/latest
[7]: https://www.transifex.com/kgraefe/pidgin-master-password/
[8]: https://developer.pidgin.im/wiki/BuildingWinPidgin
[9]: https://github.com/kgraefe/pidgin-windev
[10]: https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-mingw.tar.gz
