/*
Copyright (c) 2008 Thomas Dixon

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

#define volatile 

#ifdef FORTUNA_USE_THREADS

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <pthread.h>

#define FORTUNA_MUTEX_TYPE(x) pthread_mutex_t x
#define FORTUNA_MUTEX_LOCK(x) pthread_mutex_lock(x)
#define FORTUNA_MUTEX_UNLOCK(x) pthread_mutex_unlock(x)

#else

#define FORTUNA_MUTEX_TYPE(x)
#define FORTUNA_MUTEX_LOCK(x)
#define FORTUNA_MUTEX_UNLOCK(x)

#endif

#include <sys/time.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

/* Errors */
enum
{
    FORTUNA_NOT_SEEDED = -4,
    FORTUNA_OPENSSL_ERROR,
    FORTUNA_ILLEGAL_ARG,
    FORTUNA_ERROR,
    FORTUNA_OK
};

/* Other constants */
#define FORTUNA_AES_KEY_SIZE (AES_BLOCK_SIZE << 1) /* From OpenSSL */
#define FORTUNA_POOL_COUNT 32
#define FORTUNA_MIN_POOL_SIZE 64
#define FORTUNA_RESEED_INTERVAL 100 /* In milliseconds */
#define FORTUNA_OUTPUT_LIMIT (1 << 20) /* 1 MB limit per call of fortuna_read */

typedef struct fortuna_state
{
    SHA256_CTX pools[FORTUNA_POOL_COUNT];
    
    AES_KEY working_key;
    
    volatile unsigned char key[FORTUNA_AES_KEY_SIZE],
                           iv[AES_BLOCK_SIZE];
                  
    unsigned long pool_index,
                  pool0_len,
                  reseed_count;
                      
    time_t reseed_time;
    
    FORTUNA_MUTEX_TYPE(mutex);
} fortuna_state;

int fortuna_init(fortuna_state *fs);
int fortuna_end(fortuna_state *fs);
int fortuna_add_event(fortuna_state *fs, const void *in, unsigned long len);
int fortuna_read(fortuna_state *fs, void *out_, unsigned long len);
