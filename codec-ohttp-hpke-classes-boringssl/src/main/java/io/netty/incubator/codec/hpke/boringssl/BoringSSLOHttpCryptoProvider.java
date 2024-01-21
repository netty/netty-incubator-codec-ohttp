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


import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.HPKERecipientContext;
import io.netty.incubator.codec.hpke.HPKESenderContext;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Arrays;

/**
 * BoringSSL based {@link OHttpCryptoProvider}. {@link BoringSSLHPKE#ensureAvailability()} or
 * {@link BoringSSLHPKE#isAvailable()} should be used before accessing {@link #INSTANCE} to ensure
 * the native library can be loaded on the used platform.
 */
public final class BoringSSLOHttpCryptoProvider implements OHttpCryptoProvider {

    private final ReferenceQueue<BoringSSLAsymmetricCipherKeyPair> keyPairRefQueue = new ReferenceQueue<>();
    private static final class EVP_HPKE_KEY_PhantomRef extends PhantomReference<BoringSSLAsymmetricCipherKeyPair> {
        private final long key;
        EVP_HPKE_KEY_PhantomRef(BoringSSLAsymmetricCipherKeyPair referent,
                                       ReferenceQueue<BoringSSLAsymmetricCipherKeyPair> q) {
            super(referent, q);
            this.key = referent.key;
        }
    }

    /**
     * {@link BoringSSLOHttpCryptoProvider} instance.
     */
    public static final BoringSSLOHttpCryptoProvider INSTANCE = new BoringSSLOHttpCryptoProvider();

    private BoringSSLOHttpCryptoProvider() {
    }

    @Override
    public AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
        long boringSSLAead = boringSSLAEAD(aead);
        int keyLength = BoringSSL.EVP_AEAD_key_length(boringSSLAead);
        if (keyLength != key.length) {
            throw new IllegalArgumentException("key length must be " + keyLength + ": " + key.length);
        }
        int nounceLength = BoringSSL.EVP_AEAD_nonce_length(boringSSLAead);
        if (nounceLength != baseNonce.length) {
            throw new IllegalArgumentException("baseNonce length must be " + nounceLength + ": " + baseNonce.length);
        }

        int maxOverhead = BoringSSL.EVP_AEAD_max_overhead(boringSSLAead);
        long ctx = BoringSSL.EVP_AEAD_CTX_new_or_throw(boringSSLAead, key, BoringSSL.EVP_AEAD_DEFAULT_TAG_LENGTH);
        try {
            BoringSSLAEADContext aeadCtx = new BoringSSLAEADContext(this, ctx, maxOverhead, baseNonce);
            ctx = -1;
            return aeadCtx;
        } finally {
            if (ctx != -1) {
                BoringSSL.EVP_AEAD_CTX_cleanup_and_free(ctx);
            }
        }
    }

    private static long boringSSLAEAD(AEAD aead) {
        switch (aead) {
            case AES_GCM128:
                return BoringSSL.EVP_aead_aes_128_gcm;
            case AES_GCM256:
                return BoringSSL.EVP_aead_aes_256_gcm;
            case CHACHA20_POLY1305:
                return BoringSSL.EVP_aead_chacha20_poly1305;
            default:
                throw new IllegalArgumentException("AEAD not supported: " + aead);
        }
    }

    private static long boringSSLKDF(KDF kdf) {
        if (kdf != KDF.HKDF_SHA256) {
            throw new IllegalArgumentException("KDF not supported: " + kdf);
        }
        return BoringSSL.EVP_hpke_hkdf_sha256;
    }

    private static long boringSSLKEM(KEM kem) {
        if (kem != KEM.X25519_SHA256) {
            throw new IllegalArgumentException("KEM not supported: " + kem);
        }
        return BoringSSL.EVP_hpke_x25519_hkdf_sha256;
    }

    private static long boringSSLHPKEAEAD(AEAD aead) {
        switch (aead) {
            case AES_GCM128:
                return BoringSSL.EVP_hpke_aes_128_gcm;
            case AES_GCM256:
                return BoringSSL.EVP_hpke_aes_256_gcm;
            case CHACHA20_POLY1305:
                return BoringSSL.EVP_hpke_chacha20_poly1305;
            default:
                throw new IllegalArgumentException("AEAD not supported: " + aead);
        }
    }

    @Override
    public HPKESenderContext setupHPKEBaseS(KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR,
            byte[] info, AsymmetricCipherKeyPair kpE) {
        long boringSSLKem = boringSSLKEM(kem);
        long boringSSLKdf = boringSSLKDF(kdf);
        long boringSSLAead = boringSSLHPKEAEAD(aead);
        final byte[] pkRBytes = encodedAsymmetricKeyParameter(pkR);
        final byte[] encapsulation;
        long ctx = BoringSSL.EVP_HPKE_CTX_new_or_throw();
        try {
            if (kpE == null) {
                encapsulation = BoringSSL.EVP_HPKE_CTX_setup_sender(
                        ctx, boringSSLKem, boringSSLKdf, boringSSLAead, pkRBytes, info);
            } else {
                encapsulation = BoringSSL.EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                        ctx, boringSSLKem, boringSSLKdf, boringSSLAead, pkRBytes, info,
                        // As we only support X25519 it is the right thing to just use the private key as seed.
                        // See https://github.com/google/boringssl/blob/master/include/openssl/hpke.h#L235C44-L235C50
                        encodedAsymmetricKeyParameter(kpE.privateParameters()));
            }
            if (encapsulation == null) {
                throw new IllegalStateException("Unable to setup EVP_HPKE_CTX");
            }
            BoringSSLHPKESenderContext hpkeCtx =
                    new BoringSSLHPKESenderContext(this, ctx, encapsulation);
            ctx = -1;
            return hpkeCtx;
        } finally {
            if (ctx != -1) {
                BoringSSL.EVP_HPKE_CTX_cleanup_and_free(ctx);
            }
        }
    }

    private static byte[] encodedAsymmetricKeyParameter(AsymmetricKeyParameter parameter) {
        if (parameter instanceof BoringSSLAsymmetricKeyParameter) {
            // No copy needed.
            return ((BoringSSLAsymmetricKeyParameter) parameter).bytes;
        }
        return parameter.encoded();
    }

    @Override
    public HPKERecipientContext setupHPKEBaseR(KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                               AsymmetricCipherKeyPair skR, byte[] info) {
        // Validate that KEM is supported by BoringSSL
        long boringSSLKem = boringSSLKEM(kem);
        long boringSSLKdf = boringSSLKDF(kdf);
        long boringSSLAead = boringSSLHPKEAEAD(aead);

        long ctx = -1;
        long key = -1;
        boolean freeKey = true;
        try {
            if (skR instanceof BoringSSLAsymmetricCipherKeyPair) {
                key = ((BoringSSLAsymmetricCipherKeyPair) skR).key;
                freeKey = false;
            } else {
                byte[] privateKeyBytes = encodedAsymmetricKeyParameter(skR.privateParameters());
                key = BoringSSL.EVP_HPKE_KEY_new_and_init_or_throw(boringSSLKem, privateKeyBytes);
            }

            ctx = BoringSSL.EVP_HPKE_CTX_new_or_throw();
            if (BoringSSL.EVP_HPKE_CTX_setup_recipient(ctx, key, boringSSLKdf, boringSSLAead, enc, info) != 1) {
                throw new IllegalStateException("Unable to setup EVP_HPKE_CTX");
            }

            // Store a reference to the keyPair so we are sure it will only be GCed once the context is collected as
            // well. This ensures the key is not added to the reference queue before the context is destroyed as well.
            BoringSSLHPKERecipientContext hpkeCtx = new BoringSSLHPKERecipientContext(this, ctx, skR);
            ctx = -1;
            return hpkeCtx;
        } finally {
            if (freeKey && key != -1) {
                BoringSSL.EVP_HPKE_KEY_cleanup_and_free(key);
            }
            if (ctx != -1) {
                BoringSSL.EVP_HPKE_CTX_cleanup_and_free(ctx);
            }
        }
    }

    @Override
    public AsymmetricCipherKeyPair deserializePrivateKey(KEM kem, byte[] privateKeyBytes, byte[] publicKeyBytes) {
        // Validate that KEM is supported by BoringSSL
        long boringSSLKem = boringSSLKEM(kem);

        long key = -1;
        try {
            key = BoringSSL.EVP_HPKE_KEY_new_and_init_or_throw(boringSSLKem, privateKeyBytes);
            byte[] extractedPublicKey = BoringSSL.EVP_HPKE_KEY_public_key(key);
            if (!Arrays.equals(publicKeyBytes, extractedPublicKey)) {
                throw new IllegalArgumentException(
                        "publicKeyBytes does not contain a valid public key: " + Arrays.toString(publicKeyBytes));
            }
            // No need to clone extractedPublicKey as it was returned by our native call.
            BoringSSLAsymmetricCipherKeyPair pair =
                    new BoringSSLAsymmetricCipherKeyPair(key, privateKeyBytes.clone(), extractedPublicKey);
            new EVP_HPKE_KEY_PhantomRef(pair, keyPairRefQueue);
            key = -1;
            return pair;
        } finally {
            if (key != -1) {
                BoringSSL.EVP_HPKE_KEY_cleanup_and_free(key);
            }
        }
    }

    @Override
    public AsymmetricKeyParameter deserializePublicKey(KEM kem, byte[] publicKeyBytes) {
        // Validate that KEM is supported by BoringSSL.
        long boringSSLKem = boringSSLKEM(kem);
        // The best we can do is to check if the length is correct.
        if (BoringSSL.EVP_HPKE_KEM_public_key_len(boringSSLKem) != publicKeyBytes.length) {
            throw new IllegalArgumentException(
                    "publicKeyBytes does not contain a valid public key: " + Arrays.toString(publicKeyBytes));
        }
        return new BoringSSLAsymmetricKeyParameter(publicKeyBytes.clone(), false);
    }

    @Override
    public AsymmetricCipherKeyPair newRandomPrivateKey(KEM kem) {
        // Validate that KEM is supported by BoringSSL.
        long boringSSLKem = boringSSLKEM(kem);

        long key = BoringSSL.EVP_HPKE_KEY_new_and_generate_or_throw(boringSSLKem);
        try {
            byte[] privateKeyBytes = BoringSSL.EVP_HPKE_KEY_private_key(key);
            byte[] publicKeyBytes = BoringSSL.EVP_HPKE_KEY_public_key(key);
            if (privateKeyBytes == null || publicKeyBytes == null) {
                throw new IllegalStateException("Unable to generate random key");
            }
            BoringSSLAsymmetricCipherKeyPair pair =
                    new BoringSSLAsymmetricCipherKeyPair(key, privateKeyBytes, publicKeyBytes);
            key = -1;
            return pair;
        } finally {
            BoringSSL.EVP_HPKE_KEY_cleanup_and_free(key);
        }
    }

    @Override
    public boolean isSupported(AEAD aead) {
        if (aead == null) {
            return false;
        }
        switch (aead) {
            case AES_GCM128:
            case AES_GCM256:
            case CHACHA20_POLY1305:
                return true;
            default:
                return false;
        }
    }

    @Override
    public boolean isSupported(KEM kem) {
        return kem == KEM.X25519_SHA256;
    }

    @Override
    public boolean isSupported(KDF kdf) {
        return kdf == KDF.HKDF_SHA256;
    }

    /**
     * Try to free enqueued {@code EVP_HPKE_KEY}s.
     */
    void free_EVP_HPKE_KEYS() {
        for (;;) {
            EVP_HPKE_KEY_PhantomRef ref = (EVP_HPKE_KEY_PhantomRef) keyPairRefQueue.poll();
            if (ref == null) {
                return;
            }
            BoringSSL.EVP_HPKE_KEY_cleanup_and_free(ref.key);
        }
    }
}

