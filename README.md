Welcome to the OpenSSL Project with hybrid symmetric encryption
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

Workflow for installing openssl - WSL
```console
git clone https://github.com/rubiogarcia465179/TLS-GF2X.git
cd TLS-GF2X/
./Configure
make clean
make
make install
```

Workflow for installing openssl and gf2x - Dockerilfe: Installing openssl does not work because gf2x is not recognized. Added comments on Openssl build commands for debugging.
```console
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
RUN make install
RUN ldconfig
WORKDIR /home
RUN git clone -b master https://github.com/rubiogarcia465179/TLS-GF2X.git
#RUN cd TLS-GF2X/
WORKDIR /home/TLS-GF2X
RUN pwd
RUN apt-get install -y autoconf
#RUN ./Configure
#RUN make clean
#RUN make

```

### Install OpenSSL with reference to libraries GF2X and OpenMP

After some reserach, we found out that by executing this, we can link all of OpenSSL with GF2X and OpenMP. Use `unset CFLAGS LDFLAGS EX_LIBS` unset if you have set the variables before.

```console
make clean
#unset CFLAGS LDFLAGS EX_LIBS
export CFLAGS="-fopenmp -I/usr/local/include"
export LDFLAGS="-L/usr/local/lib"
export EX_LIBS="-lgf2x"
./Configure <your-target-options>
make
```

`-L/usr/local/lib` is where the binaries for Gf2x are included. See below:

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

Nonetheless, I see the following problem. Things do not compile. 

**I have checked, and after I hit configure, a Makefile is created on the root folder of Openssl. If I enter with nano and search (control + W) "-lssl -lcrypto" it shows me the part of the makefile that gives error. I have added manually -lgf2x there.** - This approach works!!!!

second option: Add ./Conifgure EX_LIBS=-lgf2x

third option: Change where BIN_EX_LIBS is defined and add lgf2x

```console

BIN_EX_LIBS = $(EX_LIBS).....

to

BIN_EX_LIBS = $(EX_LIBS) -lgf2x

```




```console
     rm -f apps/openssl
        $${LDCMD:-$(CC)} $(BIN_CFLAGS) -L. $(BIN_LDFLAGS) \
                -o apps/openssl \
                apps/lib/openssl-bin-cmp_mock_srv.o \
                apps/openssl-bin-asn1parse.o apps/openssl-bin-ca.o \
                apps/openssl-bin-ciphers.o apps/openssl-bin-cmp.o \
                apps/openssl-bin-cms.o apps/openssl-bin-crl.o \
                apps/openssl-bin-crl2pkcs7.o apps/openssl-bin-dgst.o \
                apps/openssl-bin-dhparam.o apps/openssl-bin-dsa.o \
                apps/openssl-bin-dsaparam.o apps/openssl-bin-ec.o \
                apps/openssl-bin-ecparam.o apps/openssl-bin-enc.o \
                apps/openssl-bin-engine.o apps/openssl-bin-errstr.o \
                apps/openssl-bin-fipsinstall.o apps/openssl-bin-gendsa.o \
                apps/openssl-bin-genpkey.o apps/openssl-bin-genrsa.o \
                apps/openssl-bin-info.o apps/openssl-bin-kdf.o \
                apps/openssl-bin-list.o apps/openssl-bin-mac.o \
                apps/openssl-bin-nseq.o apps/openssl-bin-ocsp.o \
                apps/openssl-bin-openssl.o apps/openssl-bin-passwd.o \
                apps/openssl-bin-pkcs12.o apps/openssl-bin-pkcs7.o \
                apps/openssl-bin-pkcs8.o apps/openssl-bin-pkey.o \
                apps/openssl-bin-pkeyparam.o apps/openssl-bin-pkeyutl.o \
                apps/openssl-bin-prime.o apps/openssl-bin-progs.o \
                apps/openssl-bin-rand.o apps/openssl-bin-rehash.o \
                apps/openssl-bin-req.o apps/openssl-bin-rsa.o \
                apps/openssl-bin-rsautl.o apps/openssl-bin-s_client.o \
                apps/openssl-bin-s_server.o apps/openssl-bin-s_time.o \
                apps/openssl-bin-sess_id.o apps/openssl-bin-smime.o \
                apps/openssl-bin-speed.o apps/openssl-bin-spkac.o \
                apps/openssl-bin-srp.o apps/openssl-bin-storeutl.o \
                apps/openssl-bin-ts.o apps/openssl-bin-verify.o \
                apps/openssl-bin-version.o apps/openssl-bin-x509.o \
                apps/libapps.a -lssl -lcrypto -lgf2x $(BIN_EX_LIBS)
apps/lib/openssl-bin-cmp_mock_srv.o: apps/lib/cmp_mock_srv.c apps/progs.h
        $(CC)  -Iapps -I. -Iinclude -Iapps/include  $(BIN_CFLAGS) $(BIN_CPPFLAGS) -MMD -MF apps/lib/openssl-bin-cmp_mock_srv.d.tmp -c -o $@ apps/lib/cmp_mock_srv.c
        @touch apps/lib/openssl-bin-cmp_mock_srv.d.tmp
        @if cmp apps/lib/openssl-bin-cmp_mock_srv.d.tmp apps/lib/openssl-bin-cmp_mock_srv.d > /dev/null 2> /dev/null; then \
                rm -f apps/lib/openssl-bin-cmp_mock_srv.d.tmp; \
        else \
                mv apps/lib/openssl-bin-cmp_mock_srv.d.tmp apps/lib/openssl-bin-cmp_mock_srv.d; \
        fi
apps/progs.h: apps/progs.pl apps/progs.c

```

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
- Previous instructions on OpenSSL are now added in file `README_old.md`. This makes this readme file clearer.

### Current error status code

Now, gf2x_mul is recognized. Following error still showing when compiling: Where is **xor3_range_v2** defined?

```console

${LDCMD:-gcc} -pthread -m64 -Wa,--noexecstack -fopenmp -I/usr/local/include -L.  -L/usr/local/lib \
        -o apps/openssl \
        apps/lib/openssl-bin-cmp_mock_srv.o \
        apps/openssl-bin-asn1parse.o apps/openssl-bin-ca.o \
        apps/openssl-bin-ciphers.o apps/openssl-bin-cmp.o \
        apps/openssl-bin-cms.o apps/openssl-bin-crl.o \
        apps/openssl-bin-crl2pkcs7.o apps/openssl-bin-dgst.o \
        apps/openssl-bin-dhparam.o apps/openssl-bin-dsa.o \
        apps/openssl-bin-dsaparam.o apps/openssl-bin-ec.o \
        apps/openssl-bin-ecparam.o apps/openssl-bin-enc.o \
        apps/openssl-bin-engine.o apps/openssl-bin-errstr.o \
        apps/openssl-bin-fipsinstall.o apps/openssl-bin-gendsa.o \
        apps/openssl-bin-genpkey.o apps/openssl-bin-genrsa.o \
        apps/openssl-bin-info.o apps/openssl-bin-kdf.o \
        apps/openssl-bin-list.o apps/openssl-bin-mac.o \
        apps/openssl-bin-nseq.o apps/openssl-bin-ocsp.o \
        apps/openssl-bin-openssl.o apps/openssl-bin-passwd.o \
        apps/openssl-bin-pkcs12.o apps/openssl-bin-pkcs7.o \
        apps/openssl-bin-pkcs8.o apps/openssl-bin-pkey.o \
        apps/openssl-bin-pkeyparam.o apps/openssl-bin-pkeyutl.o \
        apps/openssl-bin-prime.o apps/openssl-bin-progs.o \
        apps/openssl-bin-rand.o apps/openssl-bin-rehash.o \
        apps/openssl-bin-req.o apps/openssl-bin-rsa.o \
        apps/openssl-bin-rsautl.o apps/openssl-bin-s_client.o \
        apps/openssl-bin-s_server.o apps/openssl-bin-s_time.o \
        apps/openssl-bin-sess_id.o apps/openssl-bin-smime.o \
        apps/openssl-bin-speed.o apps/openssl-bin-spkac.o \
        apps/openssl-bin-srp.o apps/openssl-bin-storeutl.o \
        apps/openssl-bin-ts.o apps/openssl-bin-verify.o \
        apps/openssl-bin-version.o apps/openssl-bin-x509.o \
        apps/libapps.a -lssl -lcrypto -lgf2x -ldl -pthread
/usr/bin/ld: ./libcrypto.so: undefined reference to `xor3_range_v2'
/usr/bin/ld: ./libcrypto.so: undefined reference to `xor3_single'
/usr/bin/ld: ./libcrypto.so: undefined reference to `xor_range_v2'
/usr/bin/ld: ./libcrypto.so: undefined reference to `xor_range_v1'
/usr/bin/ld: ./libcrypto.so: undefined reference to `xor3_range_v1'
collect2: error: ld returned 1 exit status
make[1]: *** [Makefile:24724: apps/openssl] Error 1
make[1]: Leaving directory '/home/TLS-GF2X'
make: *** [Makefile:3719: build_sw] Error 2
root@62a07dd4fc73:/home/TLS-GF2X# eco5admin@ths-storage:~$

```