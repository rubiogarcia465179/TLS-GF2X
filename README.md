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