/*
 * Copyright 2023 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "netty_jni_util.h"
#include "netty_incubator_codec_ohttp_hpke_boringssl.h"

#include <openssl/hpke.h>
#include <openssl/aead.h>
#include <openssl/hkdf.h>

// Add define if NETTY_OHTTP_HPKE_BORINGSSL_BUILD_STATIC is defined so it is picked up in netty_jni_util.c
#ifdef NETTY_OHTTP_HPKE_BORINGSSL_BUILD_STATIC
#define NETTY_JNI_UTIL_BUILD_STATIC
#endif

#define STATICALLY_CLASSNAME "io/netty/incubator/codec/hpke/boringssl/BoringSSLNativeStaticallyReferencedJniMethods"
#define BORINGSSL_CLASSNAME "io/netty/incubator/codec/hpke/boringssl/BoringSSL"
#define LIBRARYNAME "netty_incubator_codec_ohttp_hpke_boringssl"

static char const* staticPackagePrefix = NULL;

static jbyteArray to_byte_array(JNIEnv* env, int result, const uint8_t* data, size_t out_len) {
    if (result == 1) {
        jbyteArray array = (*env)->NewByteArray(env, out_len);
        (*env)->SetByteArrayRegion (env, array, 0, out_len, (jbyte *) data);
        return array;
    }
    return NULL;
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_x25519_hkdf_sha256(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_hpke_x25519_hkdf_sha256();
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_hkdf_sha256(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_hpke_hkdf_sha256();
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_aes_128_gcm(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_hpke_aes_128_gcm();
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_aes_256_gcm(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_hpke_aes_256_gcm();
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_chacha20_poly1305(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_hpke_chacha20_poly1305();
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_DEFAULT_TAG_LENGTH(JNIEnv* env, jclass clazz) {
    return (jint) EVP_AEAD_DEFAULT_TAG_LENGTH;
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_new(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_HPKE_CTX_new();
}

static void netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_cleanup(JNIEnv* env, jclass clazz, jlong ctx) {
    EVP_HPKE_CTX_cleanup((EVP_HPKE_CTX *) ctx);
}

static void netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_free(JNIEnv* env, jclass clazz, jlong ctx) {
    EVP_HPKE_CTX_free((EVP_HPKE_CTX *) ctx);
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_setup_sender(
        JNIEnv* env, jclass clazz, jlong ctx, jlong kem, jlong kdf, jlong aead,
        jbyteArray peer_public_key_bytes, jbyteArray info_bytes) {
    uint8_t out_enc[EVP_HPKE_MAX_ENC_LENGTH];
    size_t out_enc_len;

    size_t peer_public_key_len = (size_t) (*env)->GetArrayLength(env, peer_public_key_bytes);
    const uint8_t *peer_public_key = (const uint8_t*) (*env)->GetByteArrayElements(env, peer_public_key_bytes, 0);

    size_t info_len = (size_t) (*env)->GetArrayLength(env, info_bytes);
    const uint8_t *info = (const uint8_t*) (*env)->GetByteArrayElements(env, info_bytes, 0);

    int result = EVP_HPKE_CTX_setup_sender((EVP_HPKE_CTX *) ctx, (uint8_t *) out_enc, &out_enc_len, EVP_HPKE_MAX_ENC_LENGTH,
                                           (const EVP_HPKE_KEM *) kem, (const EVP_HPKE_KDF *) kdf,  (const EVP_HPKE_AEAD *) aead,
                                           peer_public_key, peer_public_key_len, info, info_len);

    (*env)->ReleaseByteArrayElements(env, peer_public_key_bytes, (jbyte *) peer_public_key, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, info_bytes, (jbyte *) info, JNI_ABORT);

    return to_byte_array(env, result, (const uint8_t *) out_enc, out_enc_len);
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
        JNIEnv* env, jclass clazz, jlong ctx, jlong kem, jlong kdf, jlong aead,
        jbyteArray peer_public_key_bytes, jbyteArray info_bytes, jbyteArray seed_bytes) {
    uint8_t out_enc[EVP_HPKE_MAX_ENC_LENGTH];
    size_t out_enc_len;

    size_t peer_public_key_len = (size_t) (*env)->GetArrayLength(env, peer_public_key_bytes);
    const uint8_t *peer_public_key = (const uint8_t*) (*env)->GetByteArrayElements(env, peer_public_key_bytes, 0);

    size_t info_len = (size_t) (*env)->GetArrayLength(env, info_bytes);
    const uint8_t *info = (const uint8_t*) (*env)->GetByteArrayElements(env, info_bytes, 0);

    size_t seed_len = (size_t) (*env)->GetArrayLength(env, seed_bytes);
    const uint8_t *seed = (const uint8_t*) (*env)->GetByteArrayElements(env, seed_bytes, 0);

    int result = EVP_HPKE_CTX_setup_sender_with_seed_for_testing((EVP_HPKE_CTX *) ctx,  (uint8_t *) out_enc, &out_enc_len, EVP_HPKE_MAX_ENC_LENGTH,
                                           (const EVP_HPKE_KEM *) kem, (const EVP_HPKE_KDF *) kdf,  (const EVP_HPKE_AEAD *) aead,
                                           (const uint8_t *) peer_public_key, (size_t) peer_public_key_len, (const uint8_t *) info, (size_t) info_len,
                                           (const uint8_t *) seed, (size_t) seed_len);

    (*env)->ReleaseByteArrayElements(env, peer_public_key_bytes, (jbyte *) peer_public_key, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, info_bytes, (jbyte *) info, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, seed_bytes, (jbyte *) seed, JNI_ABORT);

    return to_byte_array(env, result, (const uint8_t *) out_enc, out_enc_len);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_setup_recipient(
        JNIEnv* env, jclass clazz, jlong ctx, jlong key, jlong kdf,
                                                    jlong aead, jbyteArray enc_bytes,
                                                    jbyteArray info_bytes) {
    size_t enc_len = (size_t) (*env)->GetArrayLength(env, enc_bytes);
    const uint8_t *enc = (const uint8_t*) (*env)->GetByteArrayElements(env, enc_bytes, 0);
    size_t info_len = (size_t) (*env)->GetArrayLength(env, enc_bytes);
    const uint8_t *info = (const uint8_t*) (*env)->GetByteArrayElements(env, info_bytes, 0);

    int result = EVP_HPKE_CTX_setup_recipient((EVP_HPKE_CTX *) ctx, (const EVP_HPKE_KEY *) key, (const EVP_HPKE_KDF *)kdf,
                                               (const EVP_HPKE_AEAD *) aead, enc, enc_len, info, info_len);

    (*env)->ReleaseByteArrayElements(env, enc_bytes, (jbyte *) enc, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, info_bytes, (jbyte *) info, JNI_ABORT);

    return result;
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_open(
        JNIEnv* env, jclass clazz, jlong ctx, jlong out,
        jint max_out_len, jlong in, jint in_len, jlong ad, jint ad_len) {
    size_t out_len;

    int result = EVP_HPKE_CTX_open((EVP_HPKE_CTX *) ctx, (uint8_t *) out, &out_len, (size_t) max_out_len,
                                   (const uint8_t *) in, (size_t) in_len, (const uint8_t *) ad, (size_t) ad_len);
    return result == 1 ? (jint) out_len : -1;
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_seal(
        JNIEnv* env, jclass clazz, jlong ctx, jlong out,
        jint max_out_len, jlong in, jint in_len, jlong ad, jint ad_len) {
    size_t out_len;

    int result = EVP_HPKE_CTX_seal((EVP_HPKE_CTX *) ctx, (uint8_t *) out, &out_len, (size_t) max_out_len,
                                   (const uint8_t *) in, (size_t) in_len, (const uint8_t *) ad, (size_t) ad_len);

    return result == 1 ? (jint) out_len : -1;
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_export(
        JNIEnv* env, jclass clazz, jlong ctx,
        jint secret_len, jbyteArray context_array) {
    size_t context_len = (size_t) (*env)->GetArrayLength(env, context_array);
    const uint8_t *context = (const uint8_t*) (*env)->GetByteArrayElements(env, context_array, 0);
    jbyteArray out_array = (*env)->NewByteArray(env, secret_len);
    uint8_t* out = (uint8_t*) (*env)->GetByteArrayElements(env, out_array, NULL);

    int result = EVP_HPKE_CTX_export((const EVP_HPKE_CTX *) ctx, out, (size_t) secret_len, context, context_len);

    (*env)->ReleaseByteArrayElements(env, context_array, (jbyte *) context, JNI_ABORT);

    if (result == 1) {
        // Copy back changes
        (*env)->ReleaseByteArrayElements(env, out_array, (jbyte *) out, 0);
        return out_array;
    } else {
        // No need to copy back changes.
        (*env)->ReleaseByteArrayElements(env, out_array, (jbyte *) out, JNI_ABORT);
        return NULL;
    }
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_kdf(JNIEnv* env, jclass clazz, jlong ctx) {
    return (jlong) EVP_HPKE_CTX_kdf((const EVP_HPKE_CTX *) ctx);
}


static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_max_overhead(JNIEnv* env, jclass clazz, jlong ctx) {
    return (jint) EVP_HPKE_CTX_max_overhead((EVP_HPKE_CTX *) ctx);
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_new(JNIEnv* env, jclass clazz) {
    return (jlong) EVP_HPKE_KEY_new();
}

static void netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_free(JNIEnv* env, jclass clazz, jlong key) {
    EVP_HPKE_KEY_free((EVP_HPKE_KEY *) key);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_init(JNIEnv* env, jclass clazz, jlong key, jlong kem, jbyteArray priv_key_array) {
    size_t priv_key_len = (size_t)(*env)->GetArrayLength(env, priv_key_array);
    const uint8_t *priv_key = (const uint8_t*) (*env)->GetByteArrayElements(env, priv_key_array, 0);

    int result = EVP_HPKE_KEY_init((EVP_HPKE_KEY *) key, (const EVP_HPKE_KEM *) kem, priv_key, priv_key_len);

    (*env)->ReleaseByteArrayElements(env, priv_key_array, (jbyte *) priv_key, JNI_ABORT);
    return (jint) result;
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_public_key(JNIEnv* env, jclass clazz, jlong key) {
    uint8_t out[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH];
    size_t out_len;

    int result = EVP_HPKE_KEY_public_key((const EVP_HPKE_KEY *) key,  (uint8_t *) out, &out_len, EVP_HPKE_MAX_PUBLIC_KEY_LENGTH);
    return to_byte_array(env, result, (const uint8_t *) out, out_len);
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_private_key(JNIEnv* env, jclass clazz, jlong key) {
    uint8_t out[EVP_HPKE_MAX_PRIVATE_KEY_LENGTH];
    size_t out_len;

    int result = EVP_HPKE_KEY_private_key((const EVP_HPKE_KEY *) key, (uint8_t *) out, &out_len, EVP_HPKE_MAX_PRIVATE_KEY_LENGTH);
    return to_byte_array(env, result, (const uint8_t *) out, out_len);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEM_public_key_len(JNIEnv* env, jclass clazz, jlong kem) {
    return (jint) EVP_HPKE_KEM_public_key_len((EVP_HPKE_KEM *) kem);
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_memory_address(JNIEnv* env, jclass clazz, jobject buffer) {
    return (jlong) (*env)->GetDirectBufferAddress(env, buffer);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_key_length(JNIEnv* env, jclass clazz, jlong aead) {
    return (jint) EVP_AEAD_key_length((EVP_AEAD *) aead);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_nonce_length(JNIEnv* env, jclass clazz, jlong aead) {
    return (jint) EVP_AEAD_nonce_length((EVP_AEAD *) aead);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_max_overhead(JNIEnv* env, jclass clazz, jlong aead) {
    return (jint) EVP_AEAD_max_overhead((EVP_AEAD *) aead);
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_new(JNIEnv* env, jclass clazz, jlong aead, jbyteArray key_array, jint tag_len) {
    size_t key_len = (size_t)(*env)->GetArrayLength(env, key_array);
    const uint8_t *key = (const uint8_t*) (*env)->GetByteArrayElements(env, key_array, 0);

    EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new((const EVP_AEAD *) aead, key, key_len, (size_t) tag_len);

    (*env)->ReleaseByteArrayElements(env, key_array, (jbyte *) key, JNI_ABORT);
    return (jlong) ctx;
}

static void netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_cleanup(JNIEnv* env, jclass clazz, jlong ctx) {
    EVP_AEAD_CTX_cleanup((EVP_AEAD_CTX *) ctx);
}

static void netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_free(JNIEnv* env, jclass clazz, jlong ctx) {
    EVP_AEAD_CTX_free((EVP_AEAD_CTX *) ctx);
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_seal(JNIEnv* env, jclass clazz, jlong ctx,
                                                                         jlong out, jint max_out_len, jlong nonce, jint nonce_len,
                                                                         jlong in, jint in_len, jlong ad, jint ad_len) {

    size_t out_len;
    int result = EVP_AEAD_CTX_seal((const EVP_AEAD_CTX *) ctx, (uint8_t *) out, &out_len, (size_t) max_out_len,
                                   (const uint8_t *) nonce, (size_t) nonce_len,
                                   (const uint8_t *) in, (size_t) in_len,
                                   (const uint8_t *) ad, (size_t) ad_len);

    return result == 1 ? (jint) out_len : -1;
}

static jint netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_open(JNIEnv* env, jclass clazz, jlong ctx,
                                                                         jlong out, jint max_out_len, jlong nonce, jint nonce_len,
                                                                         jlong in, jint in_len, jlong ad, jint ad_len) {

    size_t out_len;
    int result = EVP_AEAD_CTX_open((const EVP_AEAD_CTX *) ctx, (uint8_t *) out,  &out_len, (size_t) max_out_len,
                                   (const uint8_t *) nonce, (size_t) nonce_len,
                                   (const uint8_t *) in, (size_t) in_len,
                                   (const uint8_t *) ad, (size_t) ad_len);

    return result == 1 ? (jint) out_len : -1;
}

static jlong netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KDF_hkdf_md(JNIEnv* env, jclass clazz, jlong kdf) {
    return (jlong) EVP_HPKE_KDF_hkdf_md((const EVP_HPKE_KDF *) kdf);
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_HKDF_extract(JNIEnv* env, jclass clazz, jlong digest, jbyteArray secret_array, jbyteArray salt_array) {
    uint8_t out_key[EVP_MAX_MD_SIZE];
    size_t out_len;

    size_t secret_len = (size_t)(*env)->GetArrayLength(env, secret_array);
    const uint8_t *secret = (const uint8_t*) (*env)->GetByteArrayElements(env, secret_array, 0);
    size_t salt_len = (size_t)(*env)->GetArrayLength(env, salt_array);
    const uint8_t *salt = (const uint8_t*) (*env)->GetByteArrayElements(env, salt_array, 0);

    int result = HKDF_extract(out_key, &out_len, (const EVP_MD *) digest, secret, secret_len, salt, salt_len);

    (*env)->ReleaseByteArrayElements(env, secret_array, (jbyte *) secret, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, salt_array, (jbyte *) salt, JNI_ABORT);

    return to_byte_array(env, result, (const uint8_t *) out_key, out_len);
}

static jbyteArray netty_incubator_codec_ohttp_hpke_boringssl_HKDF_expand(JNIEnv* env, jclass clazz, jlong digest, jint out_len, jbyteArray prk_array, jbyteArray info_array) {
    size_t prk_len = (size_t) (*env)->GetArrayLength(env, prk_array);
    const uint8_t *prk = (const uint8_t*) (*env)->GetByteArrayElements(env, prk_array, 0);
    size_t info_len = (size_t) (*env)->GetArrayLength(env, info_array);
    const uint8_t *info = (const uint8_t*) (*env)->GetByteArrayElements(env, info_array, 0);
    jbyteArray out_array = (*env)->NewByteArray(env, out_len);
    uint8_t* out = (uint8_t*) (*env)->GetByteArrayElements(env, out_array, NULL);

    int result = HKDF_expand(out, out_len, (const EVP_MD *) digest, prk, prk_len, info, info_len);

    (*env)->ReleaseByteArrayElements(env, prk_array, (jbyte *) prk, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, info_array, (jbyte *) info, JNI_ABORT);

    if (result == 1) {
        // Copy back changes
        (*env)->ReleaseByteArrayElements(env, out_array, (jbyte *) out, 0);
        return out_array;
    } else {
        // No need to copy back changes.
        (*env)->ReleaseByteArrayElements(env, out_array, (jbyte *) out, JNI_ABORT);
        return NULL;
    }
}
// JNI Registered Methods End

// JNI Method Registration Table Begin
static const JNINativeMethod statically_referenced_fixed_method_table[] = {
  { "EVP_hpke_x25519_hkdf_sha256", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_x25519_hkdf_sha256 },
  { "EVP_hpke_hkdf_sha256", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_hkdf_sha256 },
  { "EVP_hpke_aes_128_gcm", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_aes_128_gcm },
  { "EVP_hpke_aes_256_gcm", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_aes_256_gcm },
  { "EVP_hpke_chacha20_poly1305", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_hpke_chacha20_poly1305 },
  { "EVP_AEAD_DEFAULT_TAG_LENGTH", "()I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_DEFAULT_TAG_LENGTH }
};

static const jint statically_referenced_fixed_method_table_size = sizeof(statically_referenced_fixed_method_table) / sizeof(statically_referenced_fixed_method_table[0]);
static const JNINativeMethod fixed_method_table[] = {
  { "EVP_HPKE_CTX_new", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_new },
  { "EVP_HPKE_CTX_cleanup", "(J)V", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_cleanup },
  { "EVP_HPKE_CTX_free", "(J)V", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_free },
  { "EVP_HPKE_CTX_setup_sender", "(JJJJ[B[B)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_setup_sender },
  { "EVP_HPKE_CTX_setup_sender_with_seed_for_testing", "(JJJJ[B[B[B)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_setup_sender_with_seed_for_testing },
  { "EVP_HPKE_CTX_setup_recipient", "(JJJJ[B[B)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_setup_recipient },
  { "EVP_HPKE_CTX_open", "(JJIJIJI)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_open },
  { "EVP_HPKE_CTX_seal", "(JJIJIJI)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_seal },
  { "EVP_HPKE_CTX_export", "(JI[B)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_export },
  { "EVP_HPKE_CTX_kdf", "(J)J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_kdf },
  { "EVP_HPKE_CTX_max_overhead", "(J)I", (void * ) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_CTX_max_overhead },
  { "EVP_HPKE_KEY_new", "()J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_new },
  { "EVP_HPKE_KEY_free", "(J)V", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_free },
  { "EVP_HPKE_KEY_init", "(JJ[B)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_init },
  { "EVP_HPKE_KEY_public_key", "(J)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_public_key },
  { "EVP_HPKE_KEY_private_key", "(J)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEY_private_key },
  { "EVP_HPKE_KEM_public_key_len", "(J)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KEM_public_key_len },
  { "memory_address", "(Ljava/nio/ByteBuffer;)J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_memory_address },

  { "EVP_AEAD_key_length", "(J)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_key_length },
  { "EVP_AEAD_nonce_length", "(J)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_nonce_length },
  { "EVP_AEAD_max_overhead", "(J)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_max_overhead },

  { "EVP_AEAD_CTX_new", "(J[BI)J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_new },
  { "EVP_AEAD_CTX_cleanup", "(J)V", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_cleanup },
  { "EVP_AEAD_CTX_free", "(J)V", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_free },
  { "EVP_AEAD_CTX_seal", "(JJIJIJIJI)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_seal },
  { "EVP_AEAD_CTX_open", "(JJIJIJIJI)I", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_AEAD_CTX_open },

  { "EVP_HPKE_KDF_hkdf_md", "(J)J", (void *) netty_incubator_codec_ohttp_hpke_boringssl_EVP_HPKE_KDF_hkdf_md },
  { "HKDF_extract", "(J[B[B)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_HKDF_extract },
  { "HKDF_expand", "(JI[B[B)[B", (void *) netty_incubator_codec_ohttp_hpke_boringssl_HKDF_expand }
};

static const jint fixed_method_table_size = sizeof(fixed_method_table) / sizeof(fixed_method_table[0]);

// JNI Method Registration Table End

// IMPORTANT: If you add any NETTY_JNI_UTIL_LOAD_CLASS or NETTY_JNI_UTIL_FIND_CLASS calls you also need to update
//            Quiche to reflect that.
static jint netty_incubator_codec_ohttp_hpke_boringssl_JNI_OnLoad(JNIEnv* env, char const* packagePrefix) {
    int ret = JNI_ERR;
    int staticallyRegistered = 0;
    int nativeRegistered = 0;

    // We must register the statically referenced methods first!
    if (netty_jni_util_register_natives(env,
            packagePrefix,
            STATICALLY_CLASSNAME,
            statically_referenced_fixed_method_table,
            statically_referenced_fixed_method_table_size) != 0) {
        goto done;
    }
    staticallyRegistered = 1;

    if (netty_jni_util_register_natives(env,
            packagePrefix,
            BORINGSSL_CLASSNAME,
            fixed_method_table,
            fixed_method_table_size) != 0) {
        goto done;
    }
    nativeRegistered = 1;

    // Initialize this module

    staticPackagePrefix = packagePrefix;

    ret = NETTY_JNI_UTIL_JNI_VERSION;
done:
    if (ret == JNI_ERR) {
        if (staticallyRegistered == 1) {
            netty_jni_util_unregister_natives(env, packagePrefix, STATICALLY_CLASSNAME);
        }
        if (nativeRegistered == 1) {
            netty_jni_util_unregister_natives(env, packagePrefix, BORINGSSL_CLASSNAME);
        }
    }
    return ret;
}

static void netty_incubator_codec_ohttp_hpke_boringssl_JNI_OnUnload(JNIEnv* env) {
    netty_jni_util_unregister_natives(env, staticPackagePrefix, STATICALLY_CLASSNAME);
    netty_jni_util_unregister_natives(env, staticPackagePrefix, BORINGSSL_CLASSNAME);
    free((void*) staticPackagePrefix);
    staticPackagePrefix = NULL;
}

// Invoked by the JVM when statically linked

// We build with -fvisibility=hidden so ensure we mark everything that needs to be visible with JNIEXPORT
// https://mail.openjdk.java.net/pipermail/core-libs-dev/2013-February/014549.html

// Invoked by the JVM when statically linked
JNIEXPORT jint JNI_OnLoad_netty_incubator_codec_ohttp_hpke_boringssl(JavaVM* vm, void* reserved) {
    return netty_jni_util_JNI_OnLoad(vm, reserved, LIBRARYNAME, netty_incubator_codec_ohttp_hpke_boringssl_JNI_OnLoad);
}

// Invoked by the JVM when statically linked
JNIEXPORT void JNI_OnUnload_netty_incubator_codec_ohttp_hpke_boringssl(JavaVM* vm, void* reserved) {
    netty_jni_util_JNI_OnUnload(vm, reserved, netty_incubator_codec_ohttp_hpke_boringssl_JNI_OnUnload);
}

#ifndef NETTY_OHTTP_HPKE_BORINGSSL_BUILD_STATIC
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    return netty_jni_util_JNI_OnLoad(vm, reserved, LIBRARYNAME, netty_incubator_codec_ohttp_hpke_boringssl_JNI_OnLoad);
}

JNIEXPORT void JNI_OnUnload(JavaVM* vm, void* reserved) {
    netty_jni_util_JNI_OnUnload(vm, reserved, netty_incubator_codec_ohttp_hpke_boringssl_JNI_OnUnload);
}
#endif /* NETTY_OHTTP_HPKE_BORINGSSL_BUILD_STATIC */
