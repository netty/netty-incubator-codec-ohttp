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
package io.netty.incubator.codec.hpke.bouncycastle;

import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.HPKERecipientContext;
import io.netty.incubator.codec.hpke.HPKESenderContext;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * {@link OHttpCryptoProvider} implementation based on BouncyCastle.
 */
public final class BouncyCastleOHttpCryptoProvider implements OHttpCryptoProvider {
    public static final BouncyCastleOHttpCryptoProvider INSTANCE = new BouncyCastleOHttpCryptoProvider();
    private static final byte MODE_BASE = (byte) 0x00;
    private static final ECDomainParameters P256_PARAMS = new ECDomainParameters(NISTNamedCurves.getByName("P-256"));
    private static final ECDomainParameters P384_PARAMS = new ECDomainParameters(NISTNamedCurves.getByName("P-384"));
    private static final ECDomainParameters P521_PARAMS = new ECDomainParameters(NISTNamedCurves.getByName("P-521"));
    private final SecureRandom random = new SecureRandom();

    private BouncyCastleOHttpCryptoProvider() { }

    @Override
    public AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
        return new BouncyCastleAEADCryptoContext(new org.bouncycastle.crypto.hpke.AEAD(aead.id(), key, baseNonce));
    }

    private static BouncyCastleAsymmetricKeyParameter castOrThrow(AsymmetricKeyParameter param) {
        if (!(param instanceof BouncyCastleAsymmetricKeyParameter)) {
            throw new IllegalArgumentException(
                    "param must be of type " + BouncyCastleAsymmetricKeyParameter.class + ": " + param);
        }
        return (BouncyCastleAsymmetricKeyParameter) param;
    }

    private static BouncyCastleAsymmetricCipherKeyPair castOrThrow(AsymmetricCipherKeyPair pair) {
        if (!(pair instanceof BouncyCastleAsymmetricCipherKeyPair)) {
            throw new IllegalArgumentException(
                    "pair must be of type " + BouncyCastleAsymmetricCipherKeyPair.class + ": " + pair);
        }
        return (BouncyCastleAsymmetricCipherKeyPair) pair;
    }

    @Override
    public HPKESenderContext setupHPKEBaseS(KEM kem, KDF kdf, AEAD aead,
                                            AsymmetricKeyParameter pkR, byte[] info,
                                            AsymmetricCipherKeyPair kpE) {
        org.bouncycastle.crypto.hpke.HPKE hpke =
                new org.bouncycastle.crypto.hpke.HPKE(MODE_BASE, kem.id(), kdf.id(), aead.id());
        final org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation ctx;
        if (kpE == null) {
            ctx = hpke.setupBaseS(castOrThrow(pkR).param, info);
        } else {
            ctx = hpke.setupBaseS(castOrThrow(pkR).param, info, castOrThrow(kpE).pair);
        }
        return new BouncyCastleHPKESenderContext(ctx);
    }

    @Override
    public HPKERecipientContext setupHPKEBaseR(KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                               AsymmetricCipherKeyPair skR, byte[] info) {
        org.bouncycastle.crypto.hpke.HPKE hpke =
                new org.bouncycastle.crypto.hpke.HPKE(MODE_BASE, kem.id(), kdf.id(), aead.id());
        return new BouncyCastleHPKERecipientContext(hpke.setupBaseR(enc, castOrThrow(skR).pair, info));
    }

    @Override
    public AsymmetricCipherKeyPair deserializePrivateKey(KEM kem, byte[] privateKeyBytes, byte[] publicKeyBytes) {
        return new BouncyCastleAsymmetricCipherKeyPair(
                deserializePrivateKeyBouncyCastle(kem, privateKeyBytes, publicKeyBytes));
    }

    private static org.bouncycastle.crypto.AsymmetricCipherKeyPair deserializePrivateKeyBouncyCastle(
            KEM kem, byte[] privateKeyBytes, byte[] publicKeyBytes) {
        // See https://github.com/bcgit/bc-java/blob/
        // f1367f0b89962b29460eea381a12063fa7cd2428/core/src/main/java/org/bouncycastle/crypto/hpke/DHKEM.java#L204
        org.bouncycastle.crypto.params.AsymmetricKeyParameter publicKey =
                deserializePublicKeyBouncyCastle(kem, publicKeyBytes);
        switch (kem) {
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
                BigInteger bigInt = new BigInteger(1, privateKeyBytes);
                return new org.bouncycastle.crypto.AsymmetricCipherKeyPair(publicKey,
                        new ECPrivateKeyParameters(bigInt, ((ECPublicKeyParameters) publicKey).getParameters()));
            case X25519_SHA256:
                return new org.bouncycastle.crypto.AsymmetricCipherKeyPair(publicKey,
                        new X25519PrivateKeyParameters(privateKeyBytes));
            case X448_SHA512:
                return new org.bouncycastle.crypto.AsymmetricCipherKeyPair(publicKey,
                        new X448PrivateKeyParameters(privateKeyBytes));
            default:
                throw new IllegalArgumentException("invalid kem: " + kem);
        }
    }

    @Override
    public AsymmetricKeyParameter deserializePublicKey(KEM kem, byte[] publicKeyBytes) {
        return new BouncyCastleAsymmetricKeyParameter(deserializePublicKeyBouncyCastle(kem, publicKeyBytes));
    }

    private static org.bouncycastle.crypto.params.AsymmetricKeyParameter deserializePublicKeyBouncyCastle(
            KEM kem, byte[] publicKeyBytes) {
        // See https://github.com/bcgit/bc-java/blob/
        // f1367f0b89962b29460eea381a12063fa7cd2428/core/src/main/java/org/bouncycastle/crypto/hpke/DHKEM.java#L186
        switch (kem) {
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
                ECDomainParameters parameters = ecDomainParameters(kem);
                ECPoint decoded = parameters.getCurve().decodePoint(publicKeyBytes);
                return new ECPublicKeyParameters(decoded, parameters);
            case X25519_SHA256:
                return new X25519PublicKeyParameters(publicKeyBytes);
            case X448_SHA512:
                return new X448PublicKeyParameters(publicKeyBytes);
            default:
                throw new IllegalArgumentException("invalid kem: " + kem);
        }
    }

    private static ECDomainParameters ecDomainParameters(KEM kem) {
        switch (kem) {
            case P256_SHA256:
                return P256_PARAMS;
            case P384_SHA348:
                return P384_PARAMS;
            case P521_SHA512:
                return P521_PARAMS;
            default:
                throw new IllegalArgumentException("invalid kem: " + kem);
        }
    }

    @Override
    public AsymmetricCipherKeyPair newRandomPrivateKey(KEM kem) {
        return new BouncyCastleAsymmetricCipherKeyPair(newRandomPair(kem, random));
    }

    private static org.bouncycastle.crypto.AsymmetricCipherKeyPair newRandomPair(KEM kem, SecureRandom random) {
        switch (kem) {
            case X25519_SHA256:
                X25519PrivateKeyParameters x25519PrivateKey = new X25519PrivateKeyParameters(random);
                return new org.bouncycastle.crypto.AsymmetricCipherKeyPair(
                        x25519PrivateKey.generatePublicKey(), x25519PrivateKey);
            case X448_SHA512:
                X448PrivateKeyParameters x448PrivateKey = new X448PrivateKeyParameters(random);
                return new org.bouncycastle.crypto.AsymmetricCipherKeyPair(
                        x448PrivateKey.generatePublicKey(), x448PrivateKey);
            default:
                throw new UnsupportedOperationException("Can't generate random key for kem: " + kem);
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
        if (kem == null) {
            return false;
        }
        switch (kem) {
            case X25519_SHA256:
            case P256_SHA256:
            case P384_SHA348:
            case P521_SHA512:
            case X448_SHA512:
                return true;
            default:
                return false;
        }
    }

    @Override
    public boolean isSupported(KDF kdf) {
        if (kdf == null) {
            return false;
        }
        switch (kdf) {
            case HKDF_SHA256:
            case HKDF_SHA384:
            case HKDF_SHA512:
                return true;
            default:
                return false;
        }
    }
}
