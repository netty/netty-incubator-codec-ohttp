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


import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.HPKERecipientContext;
import io.netty.incubator.codec.hpke.HPKESenderContext;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * BoringSSL based {@link OHttpCryptoProvider}. {@link BoringSSLHPKE#ensureAvailability()} or
 * {@link BoringSSLHPKE#isAvailable()} should be used before accessing {@link #INSTANCE} to ensure
 * the native library can be loaded on the used platform.
 */
public final class BoringSSLOHttpCryptoProvider implements OHttpCryptoProvider {

    private static final List<AEAD> SUPPORTED_AEAD_LIST = Collections.unmodifiableList(Arrays.asList(AEAD.values()));
    private static final List<Mode> SUPPORTED_MODE_LIST = Collections.singletonList(Mode.Base);
    private static final List<KEM> SUPPORTED_KEM_LIST = Collections.singletonList(KEM.X25519_SHA256);
    private static final List<KDF> SUPPORTED_KDF_LIST = Collections.singletonList(KDF.HKDF_SHA256);

    /**
     * {@link BoringSSLOHttpCryptoProvider} instance.
     */
    public static final BoringSSLOHttpCryptoProvider INSTANCE = new BoringSSLOHttpCryptoProvider();

    private BoringSSLOHttpCryptoProvider() { }

    @Override
    public AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
        long boringSSLAead = boringSSLAEAD(aead);
        int keyLength = BoringSSL.EVP_AEAD_key_length(boringSSLAead);
        if (keyLength != key.length) {
            throw new IllegalArgumentException("key length must be: " + keyLength);
        }
        int nounceLength = BoringSSL.EVP_AEAD_nonce_length(boringSSLAead);
        if (nounceLength != baseNonce.length) {
            throw new IllegalArgumentException("baseNonce length must be: " + nounceLength);
        }

        int maxOverhead = BoringSSL.EVP_AEAD_max_overhead(boringSSLAead);
        long ctx = BoringSSL.EVP_AEAD_CTX_new_or_throw(boringSSLAead, key, BoringSSL.EVP_AEAD_DEFAULT_TAG_LENGTH);
        try {
            BoringSSLAEADContext aeadCtx = new BoringSSLAEADContext(ctx, maxOverhead, baseNonce);
            ctx = -1;
            return aeadCtx;
        } finally {
            if (ctx != -1) {
                BoringSSL.EVP_AEAD_CTX_cleanup_and_free(ctx);
            }
        }
    }

    private static long boringSSLKDF(KDF kdf) {
        if (kdf != KDF.HKDF_SHA256) {
            throw new IllegalArgumentException("KDF not supported: "+ kdf);
        }
        return BoringSSL.EVP_hpke_hkdf_sha256;
    }

    private static long boringSSLKEM(KEM kem) {
        if (kem != KEM.X25519_SHA256) {
            throw new IllegalArgumentException("KEM not supported: "+ kem);
        }
        return BoringSSL.EVP_hpke_x25519_hkdf_sha256;
    }

    private static long boringSSLAEAD(AEAD aead) {
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

    private static void validateMode(Mode mode) {
        // TODO: Also support AUTH
        if (mode != Mode.Base) {
            throw new IllegalArgumentException("Mode not supported: " + mode);
        }
    }

    @Override
    public HPKESenderContext setupHPKEBaseS(
            Mode mode, KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR,
            byte[] info, AsymmetricCipherKeyPair kpE) {
        validateMode(mode);
        long boringSSLKem = boringSSLKEM(kem);
        long boringSSLKdf = boringSSLKDF(kdf);
        long boringSSLAead = boringSSLAEAD(aead);
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
                    new BoringSSLHPKESenderContext(ctx, encapsulation);
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
    public HPKERecipientContext setupHPKEBaseR(Mode mode, KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                               AsymmetricCipherKeyPair skR, byte[] info) {
        validateMode(mode);
        // Validate that KEM is supported by BoringSSL
        long boringSSLKem = boringSSLKEM(kem);
        long boringSSLKdf = boringSSLKDF(kdf);
        long boringSSLAead = boringSSLAEAD(aead);

        long ctx = -1;
        long key = -1;
        try {
            byte[] privateKeyBytes = encodedAsymmetricKeyParameter(skR.privateParameters());
            key = BoringSSL.EVP_HPKE_KEY_new_and_init_or_throw(boringSSLKem, privateKeyBytes);
            ctx = BoringSSL.EVP_HPKE_CTX_new_or_throw();
            if (BoringSSL.EVP_HPKE_CTX_setup_recipient(ctx, key, boringSSLKdf, boringSSLAead, enc, info) != -1) {
                throw new IllegalStateException("Unable to setup EVP_HPKE_CTX");
            }

            BoringSSLHPKERecipientContext hpkeCtx = new BoringSSLHPKERecipientContext(ctx);
            ctx = -1;
            return hpkeCtx;
        } finally {
            BoringSSL.EVP_HPKE_KEY_cleanup_and_free(key);
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
            return new BoringSSLAsymmetricCipherKeyPair(privateKeyBytes.clone(), extractedPublicKey);
        } finally {
            BoringSSL.EVP_HPKE_KEY_cleanup_and_free(key);
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
    public List<AEAD> supportedAEAD() {
        return SUPPORTED_AEAD_LIST;
    }

    @Override
    public List<KEM> supportedKEM() {
        return SUPPORTED_KEM_LIST;
    }

    @Override
    public List<KDF> supportedKDF() {
        return SUPPORTED_KDF_LIST;
    }

    @Override
    public List<Mode> supportedMode() {
        return SUPPORTED_MODE_LIST;
    }
}
