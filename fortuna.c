/*
Copyright (c) 2009 Thomas Dixon

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

Big thanks to GNU Crypto, LibTomCrypt and Jean-Luc Cooke's kernel
patch for clearing up some implementation questions, and of course 
Ferguson and Schneier for designing Fortuna.
*/

#include "fortuna.h"

#include <stdlib.h>
#include <string.h>

void _fortuna_increment_iv(fortuna_state *fs)
{   
    int i;
    
    for (i = 0; i < AES_BLOCK_SIZE; i++)
        if (++fs->iv[i])
            break;
}

int _fortuna_is_seeded(fortuna_state *fs)
{
    int i;
    
    for (i = 0; i < AES_BLOCK_SIZE; i++)
        if (fs->iv[i] > 0)
            return FORTUNA_OK;
            
    return FORTUNA_NOT_SEEDED;
}

inline time_t _get_time_in_ms()
{
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int _fortuna_reseed(fortuna_state *fs)
{   
    int i;
    volatile unsigned char temp[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    
    fs->reseed_count++;
    
    SHA256_Init(&ctx);
    
    /* include P_k every 2^k reseeds */ 
    for (i = 0; i < FORTUNA_POOL_COUNT; i++)
    {
        if (i == 0 || ((fs->reseed_count >> i) & 1) == 0)
        {
            SHA256_Final(temp, &fs->pools[i]);
            SHA256_Update(&ctx, temp, SHA256_DIGEST_LENGTH);
            SHA256_Init(&fs->pools[i]);
        }
        else
            break;
    }
    
    memset(temp, 0, SHA256_DIGEST_LENGTH);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        if (temp[i] != 0)
            return FORTUNA_ERROR;
        
    SHA256_Update(&ctx, fs->key, FORTUNA_AES_KEY_SIZE);
    SHA256_Final(fs->key, &ctx);
    if (AES_set_encrypt_key(fs->key, FORTUNA_AES_KEY_SIZE << 3,
                            &fs->working_key) != FORTUNA_OK)
        return FORTUNA_OPENSSL_ERROR;
    
    _fortuna_increment_iv(fs);
    
    fs->pool0_len = 0;
    fs->reseed_time = _get_time_in_ms();
    
    return FORTUNA_OK;
}

int fortuna_init(fortuna_state *fs)
{
    int i;
#ifdef FORTUNA_USE_THREADS
    pthread_mutexattr_t attr;
#endif
    
    for (i = 0; i < FORTUNA_POOL_COUNT; i++)
        SHA256_Init(&fs->pools[i]);
    
    fs->pool_index = fs->pool0_len = fs->reseed_count = fs->reseed_time = 0;

    memset(fs->iv, 0, AES_BLOCK_SIZE);   
    for (i = 0; i < AES_BLOCK_SIZE; i++)
        if (fs->iv[i] != 0)
            return FORTUNA_ERROR;

    memset(fs->key, 0, FORTUNA_AES_KEY_SIZE);    
    for (i = 0; i < FORTUNA_AES_KEY_SIZE; i++)
        if (fs->key[i] != 0)
            return FORTUNA_ERROR;

#ifdef FORTUNA_USE_THREADS
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&fs->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
#endif

    return FORTUNA_OK;
}

int fortuna_end(fortuna_state *fs)
{
    volatile unsigned char temp[SHA256_DIGEST_LENGTH];
    int i;
    
    FORTUNA_MUTEX_LOCK(&fs->mutex);
    
    for (i = 0; i < FORTUNA_POOL_COUNT; i++)
        SHA256_Final(temp, &fs->pools[i]);
    
    FORTUNA_MUTEX_UNLOCK(&fs->mutex);
    
    memset(temp, 0, SHA256_DIGEST_LENGTH);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        if (temp[i] != 0)
            return FORTUNA_ERROR;
            
    return FORTUNA_OK; 
}

int fortuna_add_event(fortuna_state *fs, const void *in, unsigned long len)
{
    int use;
    FORTUNA_MUTEX_LOCK(&fs->mutex);
  
    while(len) {
        SHA256_Update(&fs->pools[fs->pool_index], &len, sizeof(len));
        use = len > 32 ? 32 : len;
        SHA256_Update(&fs->pools[fs->pool_index], in, len);
        in += use;
        len -= use;
        if(fs->pool_index == 0) 
            fs->pool0_len += use;

        fortuna_read(fs, &fs->pool_index, sizeof(fs->pool_index));
        fs->pool_index = (fs->pool_index + 1) % FORTUNA_POOL_COUNT;
    }

    FORTUNA_MUTEX_UNLOCK(&fs->mutex);
    
    return FORTUNA_OK;
}

int fortuna_read(fortuna_state *fs, void *out_, unsigned long len)
{
    unsigned char *out,
                   temp[16];
    unsigned long temp_len;
    int error;
    
    FORTUNA_MUTEX_LOCK(&fs->mutex);
    
    out = (unsigned char *)out_;
    
    /* Or should we generate a FORTUNA_LIMIT_EXCEEDED error here? */
    len = (len > FORTUNA_OUTPUT_LIMIT) ? FORTUNA_OUTPUT_LIMIT : len;
    
    if (fs->pool0_len >= FORTUNA_MIN_POOL_SIZE 
        && (_get_time_in_ms() - fs->reseed_time) >= FORTUNA_RESEED_INTERVAL)
    {
        if ((error = _fortuna_reseed(fs)) != FORTUNA_OK)
        {
            FORTUNA_MUTEX_UNLOCK(&fs->mutex);
            return error;
        }
    }
    
    if ((error = _fortuna_is_seeded(fs)) != FORTUNA_OK)
    {
        FORTUNA_MUTEX_UNLOCK(&fs->mutex);
        return error;
    }

    temp_len = len;
    while (temp_len >= AES_BLOCK_SIZE)
    {
        AES_encrypt(fs->iv, out, &fs->working_key);
        out += AES_BLOCK_SIZE;
        temp_len -= AES_BLOCK_SIZE;
        _fortuna_increment_iv(fs);
    }
    
    if (temp_len > 0)
    {
        AES_encrypt(fs->iv, temp, &fs->working_key);
        memcpy(out, temp, temp_len);
        _fortuna_increment_iv(fs);
    }
    
    AES_encrypt(fs->iv, fs->key, &fs->working_key);
    _fortuna_increment_iv(fs);
    AES_encrypt(fs->iv, fs->key + 16, &fs->working_key);
    _fortuna_increment_iv(fs);
    
    if (AES_set_encrypt_key(fs->key, FORTUNA_AES_KEY_SIZE << 3, &
                            fs->working_key) != FORTUNA_OK)
    {
        FORTUNA_MUTEX_UNLOCK(&fs->mutex);
        return FORTUNA_OPENSSL_ERROR;
    }
    
    FORTUNA_MUTEX_UNLOCK(&fs->mutex);
    
    return len;
}

