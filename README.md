Welcome to the OpenSSL Project with hybrid symmetric encryption
==============================
----


# Custom Entropic Encryption Implementation of OpenSSL

This repository contains a custom implementation that modifies the ChaCha20-Poly1305 algorithm to support entropic encryption. Below are the detailed instructions on how to set up, execute, and test the custom OpenSSL environment.

## Overview of Changes
- **Custom Algorithm Modifications**: The ChaCha20-Poly1305 encryption algorithm has been enhanced to include entropic encryption.
- **Logging Enhancements**: Logging is added to trace encryption and decryption processes for debugging. The implementation includes enhanced logging to trace encryption and decryption        processes, aiding in pinpointing specific operations within the following files:
  - `providers/implementations/ciphers/cipher_chacha20_poly1305_hw.c`: Has a one liner `ctx->chacha.base.hw->cipher(&ctx->chacha.base, out, in, plen);` that executes encryption. It is as simple as do entropic encryption there, maintaining the parameters `out`, `in`, `plen`. Otherwise, that line of code calls a function located in `providers/implementations/ciphers/cipher_chacha20_hw.c`
  - `providers/implementations/ciphers/cipher_chacha20_hw.c`: Contains a while loop that encrypts per blocks. The line of code that does the actual encryption is `ChaCha20_ctr32(out, in, blocks, ctx->key.d, ctx->counter);`. It has some logs added to check behavior. To test this algortihm, important to send long messages so that more than one block is encrypted. In case that not enough for one block data is sent, encryption happens outside the while loop. Find code in function below:
  - `providers/implementations/ciphers/cipher_chacha20.h` (accessed via **default path: /path/to/your/openssl/installation**): In our case, custom openssl is at: `/home/TLS-GF2X/apps/openssl` or ` /home/TLS-GF2X `
  -  Chacha encryption happening inside `providers/implementations/ciphers/cipher_chacha20_hw.c`

**Note**: Testing long messages ensures multiple block encryption; short messages may bypass block-based processing.

---

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
1. Have installed library gf2x
2. Have latest version of Openssl runnning. This can be done via a dockerfile, located in the server, which download this custom repository, or by downloading this repository into WSL. 
3. Compile and build OpenSSL as per default instructions (e.g., ./Configure, make, make install)

Workflow for installing openssl in Ubuntu.
```bash
git clone https://github.com/rubiogarcia465179/TLS-GF2X.git
cd TLS-GF2X/
./Configure
make clean
make
make install
```

Workflow for installing openssl and gf2x - Dockerilfe: Installing openssl does not work because gf2x is not recognized. Added comments on Openssl build commands for debugging.
```Dockerfile
FROM ubuntu:20.04

# Set the working directory
WORKDIR /app

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get -y --no-install-recommends install \
    build-essential \
    clang \
    cmake \
    gdb \
    wget \
    libtool \
    texinfo \
    libc++-12-dev \
    valgrind \
    git

WORKDIR /app

RUN apt-get update
RUN apt-get install -y unzip g++ make automake
RUN wget https://gitlab.inria.fr/gf2x/gf2x/-/archive/master/gf2x-master.tar.gz
RUN gunzip gf2x-master.tar.gz
RUN mkdir gf2x  && tar xf gf2x-master.tar -C gf2x --strip-components 1


WORKDIR /app/gf2x
RUN libtoolize &&  aclocal && autoconf && autoheader &&  automake --add-missing
RUN ./configure && make
RUN make check
RUN make tune-lowlevel && make tune-toom && make tune-fft; exit 0
RUN make install -j
RUN ldconfig
WORKDIR /home
RUN git clone -b master https://github.com/rubiogarcia465179/TLS-GF2X.git
#RUN cd TLS-GF2X/
WORKDIR /home/TLS-GF2X
RUN pwd
RUN apt-get install -y autoconf
# Set CFLAGS and LDFLAGS before configuration
ENV CFLAGS="-fopenmp -I/usr/local/include"
ENV LDFLAGS="-L/usr/local/lib"

RUN ./Configure
RUN make clean
RUN make -j


```
---
### Install OpenSSL with reference to libraries GF2X and OpenMP

After some reserach, we found out that by executing this, we can link all of OpenSSL with GF2X and OpenMP. Use `unset CFLAGS LDFLAGS EX_LIBS` unset if you have set the variables before.

To ensure gf2x library is linked against openSSL, I have added the liking of gf2x library to all OpenSSL though file `Configurations\unix-Makefile.tmpl` where the configure options to create Makefile for OpenSSL are defined. Inside this file, you can now see the following:

```Makefile
                          '$(CNF_CPPFLAGS)', '$(CPPFLAGS)') -}
BIN_CFLAGS={- join(' ', $target{bin_cflags} || (),
                        @{$config{bin_cflags}},
                        '$(CNF_CFLAGS)', '$(CFLAGS)') -}
BIN_CXXFLAGS={- join(' ', $target{bin_cxxflags} || (),
                          @{$config{bin_cxxflags}},
                          '$(CNF_CXXFLAGS)', '$(CXXFLAGS)') -}
BIN_LDFLAGS={- join(' ', $target{bin_lflags} || (),
                         @{$config{bin_lflags}},
                         '$(CNF_LDFLAGS)', '$(LDFLAGS)') -}
BIN_EX_LIBS=$(CNF_EX_LIBS) $(EX_LIBS) -lgf2x
# Added gf2x here
# CPPFLAGS_Q is used for one thing only: to build up buildinf.h
CPPFLAGS_Q={- $cppflags1 =~ s|([\\"])|\\$1|g;
              $cppflags2 =~ s|([\\"])|\\$1|g;
              $lib_cppflags =~ s|([\\"])|\\$1|g;
              join(' ', $lib_cppflags || (), $cppflags2 || (),
                        $cppflags1 || ()) -}
```

This ensures that a "default" way of installing OpenSSL (below) already allows for gf2x without other manual things required...

```console
make clean
#unset CFLAGS LDFLAGS EX_LIBS
export CFLAGS="-fopenmp -I/usr/local/include"
export LDFLAGS="-L/usr/local/lib"
./Configure
make
```

### Verify `gf2x` Installation: `-L/usr/local/lib` is where the binaries for Gf2x are included. Not sure if needed, but here is the info:
```console
root@62a07dd4fc73:/home/TLS-GF2X# ll /usr/local/lib
total 3116
drwxr-xr-x 1 root root     4096 Nov  7 15:06 ./
drwxr-xr-x 1 root root     4096 Oct 11 02:03 ../
-rw-r--r-- 1 root root  1923222 Nov  7 15:06 libgf2x.a
-rwxr-xr-x 1 root root      932 Nov  7 15:06 libgf2x.la*
lrwxrwxrwx 1 root root       16 Nov  7 15:06 libgf2x.so -> libgf2x.so.4.0.0*
lrwxrwxrwx 1 root root       16 Nov  7 15:06 libgf2x.so.4 -> libgf2x.so.4.0.0*
-rwxr-xr-x 1 root root  1238920 Nov  7 15:06 libgf2x.so.4.0.0*
drwxr-xr-x 2 root root     4096 Nov  7 15:06 pkgconfig/
drwxrwsr-x 3 root staff    4096 Nov  7 14:45 python3.8/
root@62a07dd4fc73:/home/TLS-GF2X#
```

---
# If things above do not work, I can manually make it compile by:

1. Execute `./Configure` manually.
2. `nano Makefile`
3. Search for the string (Control + W) where external libraries are added: `BIN_EX_LIBS=`:
4. Add the **-lgf2x** library manually: `BIN_EX_LIBS=$(CNF_EX_LIBS) $(EX_LIBS) -lgf2x`
5. Save the file
6. `make`

 This is because the library gf2x, through -lgf2x, is compiled against the whole OpenSSL project. Maybe not the faster way to build it, but does not make a differece when running the algorithm.

---

## Running the Custom OpenSSL Environment

Github-downladed custom Openssl is, inr our case, located at: `root@62a07dd4fc73:/home/TLS-GF2X/apps# /home/TLS-GF2X/apps/openssl version -a`


### Step 1: Generate Keys and Certificates
Use the following command to create RSA keys and a self-signed certificate:
```bash
openssl req -x509 -newkey rsa -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=NL/ST=Nord-Brabant/L=Eindhoven/O=Localhost/CN=Localhost.com"
```

### Step 2: Start the OpenSSL Server
Run the server with the following command:
```bash
LD_LIBRARY_PATH=/home/TLS-GF2X /home/TLS-GF2X/apps/openssl s_server \
    -key key.pem \
    -cert cert.pem \
    -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -accept 443
```

### Step 3: Connect the Client
Connect to the server using the OpenSSL client:
```bash
LD_LIBRARY_PATH=/home/TLS-GF2X /home/TLS-GF2X/apps/openssl s_client -connect 127.0.0.1:443 -tls1_3
```

## To-Do List

3. **Check behavior**: Test that encryption actually does something. So far, entropic_encryption function generates a segfault error.
4. **Add decryption**: Add decryption function. Check that output is the same as input.
5. **Hybrid symmetric encryption**: If desired, we can integrate first chachapoly encryption, then over the chachapoly encrypted test, perform entropic encryption. For decrypting, inverse process.

## Notes
- **The code is integrated with chachapoly encryption algorithm. It is also quantum-resistant, but much easier to work with than AES (at least in code).**
- Extensive logging has been added to facilitate debugging and confirm where encryption and decryption operations occur in the code.
- Running this implementation in Docker might require additional setup steps; adapt these commands as needed.
- Previous instructions on OpenSSL are now added in file `README_old.md`. This makes this readme file clearer.
