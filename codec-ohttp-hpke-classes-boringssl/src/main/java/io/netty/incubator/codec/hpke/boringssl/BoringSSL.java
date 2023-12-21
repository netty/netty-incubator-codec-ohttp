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
package io.netty.incubator.codec.hpke.boringssl;

import io.netty.buffer.ByteBuf;
import io.netty.util.internal.ClassInitializerUtil;
import io.netty.util.internal.NativeLibraryLoader;
import io.netty.util.internal.PlatformDependent;

import java.nio.ByteBuffer;
import java.util.Arrays;

final class BoringSSL {

    static {
        // Preload all classes that will be used in the OnLoad(...) function of JNI to eliminate the possiblity of a
        // class-loader deadlock. This is a workaround for https://github.com/netty/netty/issues/11209.

        // This needs to match all the classes that are loaded via NETTY_JNI_UTIL_LOAD_CLASS or looked up via
        // NETTY_JNI_UTIL_FIND_CLASS.
        ClassInitializerUtil.tryLoadClasses(BoringSSL.class);

        try {
            // First, try calling a side-effect free JNI method to see if the library was already
            // loaded by the application.
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_hpke_x25519_hkdf_sha256();
        } catch (UnsatisfiedLinkError ignore) {
            // The library was not previously loaded, load it now.
            loadNativeLibrary();
        }
    }

    private static void loadNativeLibrary() {
        // This needs to be kept in sync with what is defined in netty_incubator_codec_ohttp_hpke_boringssl.c
        String libName = "netty_incubator_codec_ohttp_hpke_boringssl";
        ClassLoader cl = PlatformDependent.getClassLoader(BoringSSL.class);

        if (!PlatformDependent.isAndroid()) {
            libName += '_' + PlatformDependent.normalizedOs()
                    + '_' + PlatformDependent.normalizedArch();
        }

        try {
            NativeLibraryLoader.load(libName, cl);
        } catch (UnsatisfiedLinkError e) {
            throw e;
        }
    }

    static final long EVP_hpke_x25519_hkdf_sha256 =
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_hpke_x25519_hkdf_sha256();
    static final long EVP_hpke_hkdf_sha256 =
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_hpke_hkdf_sha256();
    static final long EVP_hpke_aes_128_gcm =
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_hpke_aes_128_gcm();
    static final long EVP_hpke_aes_256_gcm =
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_hpke_aes_256_gcm();
    static final long EVP_hpke_chacha20_poly1305 =
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_hpke_chacha20_poly1305();

    static final int EVP_AEAD_DEFAULT_TAG_LENGTH =
            BoringSSLNativeStaticallyReferencedJniMethods.EVP_AEAD_DEFAULT_TAG_LENGTH();

    static native long EVP_HPKE_CTX_new();
    static native void EVP_HPKE_CTX_cleanup(long ctx);
    static native void EVP_HPKE_CTX_free(long ctx);

    // TODO: Do we also need the auth methods ?
    static native byte[] EVP_HPKE_CTX_setup_sender(
            long ctx, long kem, long kdf, long aead, byte[] peer_public_key, byte[] info);
    static native byte[] EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
            long ctx, long kem, long kdf, long aead, byte[] peer_public_key, byte[] info, byte[] seed);
    static native int EVP_HPKE_CTX_setup_recipient(
            long ctx, long key, long kdf, long aead, byte[] enc, byte[] info);

    static native int EVP_HPKE_CTX_open(
            long ctx, long out, int max_out_len, long in, int in_len, long ad, int ad_len);
    static native int EVP_HPKE_CTX_seal(
            long ctx, long out, int max_out_len, long in, int in_len, long ad, int ad_len);
    static native int EVP_HPKE_CTX_export(
            long ctx, long out, int secret_len, long context, int context_len);

    static native int EVP_HPKE_CTX_max_overhead(long ctx);

    static native long EVP_HPKE_KEY_new();
    static native void EVP_HPKE_KEY_free(long key);
    static native void EVP_HPKE_KEY_cleanup(long key);

    static native int EVP_HPKE_KEY_init(long key, long kem, byte[] priv_key);
    static native byte[] EVP_HPKE_KEY_public_key(long key);
    static native byte[] EVP_HPKE_KEY_private_key(long key);

    static native int EVP_HPKE_KEM_public_key_len(long kem);

    static native long memory_address(ByteBuffer buffer);

    static native int EVP_AEAD_key_length(long aead);
    static native int EVP_AEAD_nonce_length(long aead);
    static native int EVP_AEAD_max_overhead(long aead);

    static native long EVP_AEAD_CTX_new(long aead, byte[] key, int tag_len);
    static native void EVP_AEAD_CTX_cleanup(long ctx);
    static native void EVP_AEAD_CTX_free(long ctx);

    static native int EVP_AEAD_CTX_seal(
            long ctx, long out, int max_out_len, long nonce, int nonce_len, long in, int in_len, long ad, int ad_len);

    static native int EVP_AEAD_CTX_open(
            long ctx, long out, int max_out_len, long nonce, int nonce_len, long in, int in_len, long ad, int ad_len);

    static long memory_address(ByteBuf buffer) {
        if (buffer.hasMemoryAddress()) {
            return buffer.memoryAddress();
        }
        return memory_address(buffer.internalNioBuffer(0, buffer.capacity()));
    }

    static long EVP_HPKE_CTX_new_or_throw() {
        long ctx = BoringSSL.EVP_HPKE_CTX_new();
        if (ctx == -1) {
            throw new IllegalStateException("Unable to allocate EVP_HPKE_CTX");
        }
        return ctx;
    }

    static void EVP_HPKE_CTX_cleanup_and_free(long ctx) {
        if (ctx != -1) {
            BoringSSL.EVP_HPKE_CTX_cleanup(ctx);
            BoringSSL.EVP_HPKE_CTX_free(ctx);
        }
    }

    static long EVP_HPKE_KEY_new_or_throw() {
        long key = BoringSSL.EVP_HPKE_KEY_new();
        if (key == -1) {
            throw new IllegalStateException("Unable to allocate EVP_HPKE_KEY");
        }
        return key;
    }

    static long EVP_HPKE_KEY_new_and_init_or_throw(long kem, byte[] privateKeyBytes) {
        long key = EVP_HPKE_KEY_new_or_throw();
        EVP_HPKE_KEY_init_or_throw(key, kem, privateKeyBytes);
        return key;
    }

    static void EVP_HPKE_KEY_init_or_throw(long key, long kem, byte[] privateKeyBytes) {
        if (BoringSSL.EVP_HPKE_KEY_init(key, kem, privateKeyBytes) != 1) {
            throw new IllegalArgumentException(
                    "privateKeyBytes does not contain a valid private key: " + Arrays.toString(privateKeyBytes));
        }
    }

    static void EVP_HPKE_KEY_cleanup_and_free(long key) {
        if (key != -1) {
            BoringSSL.EVP_HPKE_KEY_cleanup(key);
            BoringSSL.EVP_HPKE_KEY_free(key);
        }
    }

    static long EVP_AEAD_CTX_new_or_throw(long aead, byte[] key, int tagLen) {
        long ctx = BoringSSL.EVP_AEAD_CTX_new(aead, key, tagLen);
        if (ctx == -1) {
            throw new IllegalStateException("Unable to allocate EVP_AEAD_CTX");
        }
        return ctx;
    }

    static void EVP_AEAD_CTX_cleanup_and_free(long ctx) {
        if (ctx != -1) {
            BoringSSL.EVP_AEAD_CTX_cleanup(ctx);
            BoringSSL.EVP_AEAD_CTX_free(ctx);
        }
    }
}


