Welcome to the OpenSSL Project
==============================
----


# Custom Entropic Encryption Implementation

This repository contains a custom implementation that modifies the ChaCha20-Poly1305 algorithm to support entropic encryption. Below are the detailed instructions on how to set up, execute, and test the custom OpenSSL environment.

## Overview of Changes
- Custom modifications have been applied to the ChaCha20-Poly1305 encryption algorithm. 
- The implementation includes enhanced logging to trace encryption and decryption processes, aiding in pinpointing specific operations within the following files:
  - `providers/implementations/ciphers/cipher_chacha20_poly1305_hw.c`: Has a one liner `ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);` that executes encryption. It is as simple as do entropic encryption there, maintaining the parameters `out`, `in`, `plen`. Otherwise, that line of code calls a function located in `providers/implementations/ciphers/cipher_chacha20_hw.c`
  - `providers/implementations/ciphers/cipher_chacha20_hw.c`: Contains a while loop that encrypts per blocks. The line of code that does the actual encryption is `ChaCha20_ctr32(out, in, blocks, ctx->key.d, ctx->counter);`. It has some logs added to check behavior. To test this algortihm, important to send long messages so that more than one block is encrypted. In case that not enough for one block data is sent, encryption happens outside the while loop. Find code in function below:
  - `providers/implementations/ciphers/cipher_chacha20.h` (accessed via **default path: /path/to/your/openssl/installation**)

Chacha encryption happening inside `providers/implementations/ciphers/cipher_chacha20_hw.c`
  ```c
static int chacha20_cipher(PROV_CIPHER_CTX *bctx, unsigned char *out, const unsigned char *in, size_t inl) {
    printf("\nchacha20_cipher hw\n\n\n\n\n\n\n\n");
    printf("\nThis function does both encryption and decryption of data\n");
    PROV_CHACHA20_CTX *ctx = (PROV_CHACHA20_CTX *)bctx;
    unsigned int n, rem, ctr32;

    n = ctx->partial_len;
    if (n > 0) {
        
        while (inl > 0 && n < CHACHA_BLK_SIZE) {
        printf("\nEncryption happenning per blocks 1\n");
            *out++ = *in++ ^ ctx->buf[n++];
            inl--;
        }
        ctx->partial_len = n;

        if (inl == 0)
            return 1;

        if (n == CHACHA_BLK_SIZE) {
            ctx->partial_len = 0;
            ctx->counter[0]++;
            if (ctx->counter[0] == 0)
                ctx->counter[1]++;
        }
    }
    printf("\nThis should should always....\n");
    rem = (unsigned int)(inl % CHACHA_BLK_SIZE);
    inl -= rem;
    ctr32 = ctx->counter[0];
    while (inl >= CHACHA_BLK_SIZE) {
        printf("\nEncryption happenning per blocks 2\n");
        size_t blocks = inl / CHACHA_BLK_SIZE;

        /*
         * 1<<28 is just a not-so-small yet not-so-large number...
         * Below condition is practically never met, but it has to
         * be checked for code correctness.
         */
        if (sizeof(size_t) > sizeof(unsigned int) && blocks > (1U << 28))
            blocks = (1U << 28);

        /*
         * As ChaCha20_ctr32 operates on 32-bit counter, caller
         * has to handle overflow. 'if' below detects the
         * overflow, which is then handled by limiting the
         * amount of blocks to the exact overflow point...
         */
        ctr32 += (unsigned int)blocks;
        if (ctr32 < blocks) {
            blocks -= ctr32;
            ctr32 = 0;
        }
        blocks *= CHACHA_BLK_SIZE;
        printf("Before ChaCha20_ctr32:\n");
        printf("  ctx->key.d: %.*s\n", 32, ctx->key.d); // Assuming key length is 32 bytes
        printf("  ctx->counter: %u %u\n", ctx->counter[0], ctx->counter[1]);
        printf("  Input to chacha20_ctr32: %.*s\n", (int)blocks, in);
        ChaCha20_ctr32(out, in, blocks, ctx->key.d, ctx->counter);
        printf("After ChaCha20_ctr32:\n");
        printf("  Output of chacha20_ctr32: %.*s\n", (int)blocks, out);

        inl -= blocks;
        in += blocks;
        out += blocks;

        ctx->counter[0] = ctr32;
        if (ctr32 == 0) ctx->counter[1]++;
    }

    if (rem > 0) {
        memset(ctx->buf, 0, sizeof(ctx->buf));
        printf("\nAbout to enter ChaCha20_ctr32 for remaining bytes\n");
        printf("  ctx->key.d: %.*s\n", 32, ctx->key.d); // Assuming key length is 32 bytes
        printf("  ctx->counter: %u %u\n", ctx->counter[0], ctx->counter[1]);
        ChaCha20_ctr32(ctx->buf, ctx->buf, CHACHA_BLK_SIZE, ctx->key.d, ctx->counter);
        printf("After ChaCha20_ctr32 for remaining bytes\n");
        for (n = 0; n < rem; n++)
            out[n] = in[n] ^ ctx->buf[n];
        ctx->partial_len = rem;
        printf("Remaining bytes: %u\n", rem);
        printf("Input: %.*s\n", rem, in);
        printf("Output: %.*s\n", rem, out);
    }

    return 1;
}
  ```

## Prerequisites
- Have installed library gf2x
- Have latest version of Openssl runnning. This can be done via a dockerfile, located in the server, which download this custom repository, or by download this repository into WSL. 
- Compile and build OpenSSL as per default instructions (e.g., ./Configure, make, make install)

## Running the Custom OpenSSL Environment

### Step 1: Generate Keys and Certificates
Use the following command to create RSA keys and a self-signed certificate:
```bash
openssl req -x509 -newkey rsa -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=NL/ST=Nord-Brabant/L=Eindhoven/O=Localhost/CN=Localhost.com"
```

### Step 2: Start the OpenSSL Server
Run the server with the following command:
```bash
sudo LD_LIBRARY_PATH=**/path/to/your/openssl** /path/to/your/openssl/apps/openssl s_server \
    -key key.pem \
    -cert cert.pem \
    -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -accept 443
```

### Step 3: Connect the Client
Connect to the server using the OpenSSL client:
```bash
LD_LIBRARY_PATH=**/path/to/your/openssl** /path/to/your/openssl/apps/openssl s_client -connect 127.0.0.1:443 -tls1_3
```

## To-Do List

1. **Figure out how to link the files having entropic encryption** -- `providers/implementations/ciphers/cipher_chacha20_poly1305_hw.c` -- To the openSSL build process. Not sure if this is to be done in a individual makefile that needs to be created, in ``providers\implementations\ciphers\build.info``, or `Makefile.in`. **We need to figure out this before continuing testing**
2. **Verify `gf2x` Installation**: Test the build in a Docker container (e.g., Mehmet’s setup) to confirm `gf2x` is correctly installed and linked. Verify that all the code integrated into `providers/implementations/ciphers/cipher_chacha20_poly1305_hw.c` is valid. That means, function declaration, headers, includes, etc. To make things easier, all function declarations can be added directly into `providers/implementations/ciphers/cipher_chacha20_poly1305_hw.c`. If I remember well, is not the most clean approach, but can be done!
3. **Check behavior**: Test that encryption actually does something.
4. **Add decryption**: Add decryption function. Check that output is the same as input.
5. **Hybrid symmetric encryption**: If desired, we can integrate first chachapoly encryption, then over the chachapoly encrypted test, perform entropic encryption. For decrypting, inverse process.

## Notes
- **The code is integrated with chachapoly encryption algorithm. It is also quantum-resistant, but much easier to work with than AES (at least in code).**
- Extensive logging has been added to facilitate debugging and confirm where encryption and decryption operations occur in the code.
- Running this implementation in Docker might require additional setup steps; adapt these commands as needed.

[![openssl logo]][www.openssl.org]

[![github actions ci badge]][github actions ci]
![Nightly OS Zoo ci badge](https://github.com/openssl/openssl/actions/workflows/os-zoo.yml/badge.svg)
![Provider Compatibility](https://github.com/openssl/openssl/actions/workflows/provider-compatibility.yml/badge.svg)
![Quic Interop](https://github.com/openssl/openssl/actions/workflows/run_quic_interop.yml/badge.svg)
![Daily checks](https://github.com/openssl/openssl/actions/workflows/run-checker-daily.yml/badge.svg)

OpenSSL is a robust, commercial-grade, full-featured Open Source Toolkit
for the TLS (formerly SSL), DTLS and QUIC (currently client side only)
protocols.

The protocol implementations are based on a full-strength general purpose
cryptographic library, which can also be used stand-alone. Also included is a
cryptographic module validated to conform with FIPS standards.

OpenSSL is descended from the SSLeay library developed by Eric A. Young
and Tim J. Hudson.

The official Home Page of the OpenSSL Project is [www.openssl.org].

Table of Contents
=================

 - [Overview](#overview)
 - [Download](#download)
 - [Build and Install](#build-and-install)
 - [Documentation](#documentation)
 - [License](#license)
 - [Support](#support)
 - [Contributing](#contributing)
 - [Legalities](#legalities)

Overview
========

The OpenSSL toolkit includes:

- **libssl**
  an implementation of all TLS protocol versions up to TLSv1.3 ([RFC 8446]),
  DTLS protocol versions up to DTLSv1.2 ([RFC 6347]) and
  the QUIC (currently client side only) version 1 protocol ([RFC 9000]).

- **libcrypto**
  a full-strength general purpose cryptographic library. It constitutes the
  basis of the TLS implementation, but can also be used independently.

- **openssl**
  the OpenSSL command line tool, a swiss army knife for cryptographic tasks,
  testing and analyzing. It can be used for
  - creation of key parameters
  - creation of X.509 certificates, CSRs and CRLs
  - calculation of message digests
  - encryption and decryption
  - SSL/TLS/DTLS and client and server tests
  - QUIC client tests
  - handling of S/MIME signed or encrypted mail
  - and more...

Download
========

For Production Use
------------------

Source code tarballs of the official releases can be downloaded from
[www.openssl.org/source](https://www.openssl.org/source).
The OpenSSL project does not distribute the toolkit in binary form.

However, for a large variety of operating systems precompiled versions
of the OpenSSL toolkit are available. In particular, on Linux and other
Unix operating systems, it is normally recommended to link against the
precompiled shared libraries provided by the distributor or vendor.

We also maintain a list of third parties that produce OpenSSL binaries for
various Operating Systems (including Windows) on the [Binaries] page on our
wiki.

For Testing and Development
---------------------------

Although testing and development could in theory also be done using
the source tarballs, having a local copy of the git repository with
the entire project history gives you much more insight into the
code base.

The official OpenSSL Git Repository is located at [git.openssl.org].
There is a GitHub mirror of the repository at [github.com/openssl/openssl],
which is updated automatically from the former on every commit.

A local copy of the Git Repository can be obtained by cloning it from
the original OpenSSL repository using

    git clone git://git.openssl.org/openssl.git

or from the GitHub mirror using

    git clone https://github.com/openssl/openssl.git

If you intend to contribute to OpenSSL, either to fix bugs or contribute
new features, you need to fork the OpenSSL repository openssl/openssl on
GitHub and clone your public fork instead.

    git clone https://github.com/yourname/openssl.git

This is necessary because all development of OpenSSL nowadays is done via
GitHub pull requests. For more details, see [Contributing](#contributing).

Build and Install
=================

After obtaining the Source, have a look at the [INSTALL](INSTALL.md) file for
detailed instructions about building and installing OpenSSL. For some
platforms, the installation instructions are amended by a platform specific
document.

 * [Notes for UNIX-like platforms](NOTES-UNIX.md)
 * [Notes for Android platforms](NOTES-ANDROID.md)
 * [Notes for Windows platforms](NOTES-WINDOWS.md)
 * [Notes for the DOS platform with DJGPP](NOTES-DJGPP.md)
 * [Notes for the OpenVMS platform](NOTES-VMS.md)
 * [Notes on Perl](NOTES-PERL.md)
 * [Notes on Valgrind](NOTES-VALGRIND.md)

Specific notes on upgrading to OpenSSL 3.x from previous versions can be found
in the [ossl-guide-migration(7ossl)] manual page.

Documentation
=============

README Files
------------

There are some README.md files in the top level of the source distribution
containing additional information on specific topics.

 * [Information about the OpenSSL QUIC protocol implementation](README-QUIC.md)
 * [Information about the OpenSSL Provider architecture](README-PROVIDERS.md)
 * [Information about using the OpenSSL FIPS validated module](README-FIPS.md)
 * [Information about the legacy OpenSSL Engine architecture](README-ENGINES.md)

The OpenSSL Guide
-----------------

There are some tutorial and introductory pages on some important OpenSSL topics
within the [OpenSSL Guide].

Manual Pages
------------

The manual pages for the master branch and all current stable releases are
available online.

- [OpenSSL master](https://www.openssl.org/docs/manmaster)
- [OpenSSL 3.0](https://www.openssl.org/docs/man3.0)
- [OpenSSL 3.1](https://www.openssl.org/docs/man3.1)
- [OpenSSL 3.2](https://www.openssl.org/docs/man3.2)

Demos
-----

The are numerous source code demos for using various OpenSSL capabilities in the
[demos subfolder](./demos).

Wiki
----

There is a Wiki at [wiki.openssl.org] which is currently not very active.
It contains a lot of useful information, not all of which is up-to-date.

License
=======

OpenSSL is licensed under the Apache License 2.0, which means that
you are free to get and use it for commercial and non-commercial
purposes as long as you fulfill its conditions.

See the [LICENSE.txt](LICENSE.txt) file for more details.

Support
=======

There are various ways to get in touch. The correct channel depends on
your requirement. See the [SUPPORT](SUPPORT.md) file for more details.

Contributing
============

If you are interested and willing to contribute to the OpenSSL project,
please take a look at the [CONTRIBUTING](CONTRIBUTING.md) file.

Legalities
==========

A number of nations restrict the use or export of cryptography. If you are
potentially subject to such restrictions, you should seek legal advice before
attempting to develop or distribute cryptographic code.

Copyright
=========

Copyright (c) 1998-2024 The OpenSSL Project Authors

Copyright (c) 1995-1998 Eric A. Young, Tim J. Hudson

All rights reserved.

<!-- Links  -->

[www.openssl.org]:
    <https://www.openssl.org>
    "OpenSSL Homepage"

[git.openssl.org]:
    <https://git.openssl.org>
    "OpenSSL Git Repository"

[git.openssl.org]:
    <https://git.openssl.org>
    "OpenSSL Git Repository"

[github.com/openssl/openssl]:
    <https://github.com/openssl/openssl>
    "OpenSSL GitHub Mirror"

[wiki.openssl.org]:
    <https://wiki.openssl.org>
    "OpenSSL Wiki"

[ossl-guide-migration(7ossl)]:
    <https://www.openssl.org/docs/manmaster/man7/ossl-guide-migration.html>
    "OpenSSL Migration Guide"

[RFC 8446]:
     <https://tools.ietf.org/html/rfc8446>

[RFC 6347]:
     <https://tools.ietf.org/html/rfc6347>

[RFC 9000]:
     <https://tools.ietf.org/html/rfc9000>

[Binaries]:
    <https://wiki.openssl.org/index.php/Binaries>
    "List of third party OpenSSL binaries"

[OpenSSL Guide]:
    <https://www.openssl.org/docs/manmaster/man7/ossl-guide-introduction.html>
    "An introduction to OpenSSL"

<!-- Logos and Badges -->

[openssl logo]:
    doc/images/openssl.svg
    "OpenSSL Logo"

[github actions ci badge]:
    <https://github.com/openssl/openssl/workflows/GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/openssl/openssl/actions?query=workflow%3A%22GitHub+CI%22>
    "GitHub Actions CI"

[appveyor badge]:
    <https://ci.appveyor.com/api/projects/status/8e10o7xfrg73v98f/branch/master?svg=true>
    "AppVeyor Build Status"

[appveyor jobs]:
    <https://ci.appveyor.com/project/openssl/openssl/branch/master>
    "AppVeyor Jobs"
