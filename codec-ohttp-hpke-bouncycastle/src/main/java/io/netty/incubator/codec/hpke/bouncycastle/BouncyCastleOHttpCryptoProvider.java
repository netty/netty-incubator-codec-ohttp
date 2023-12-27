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
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class BouncyCastleOHttpCryptoProvider implements OHttpCryptoProvider {
    public static final BouncyCastleOHttpCryptoProvider INSTANCE = new BouncyCastleOHttpCryptoProvider();
    private final SecureRandom random = new SecureRandom();
    private static final byte MODE_BASE = (byte) 0x00;

    private BouncyCastleOHttpCryptoProvider() { }

    @Override
    public AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
        return new BouncyCastleAEADCryptoContext(new org.bouncycastle.crypto.hpke.AEAD(aead.id(), key, baseNonce));
    }

    private static BouncyCastleAsymmetricKeyParameter castOrThrow(AsymmetricKeyParameter param) {
        if (!(param instanceof BouncyCastleAsymmetricKeyParameter)) {
            throw new IllegalArgumentException("param must be of type " + BouncyCastleAsymmetricKeyParameter.class + ": " + param);
        }
        return (BouncyCastleAsymmetricKeyParameter) param;
    }

    private static BouncyCastleAsymmetricCipherKeyPair castOrThrow(AsymmetricCipherKeyPair pair) {
        if (!(pair instanceof BouncyCastleAsymmetricCipherKeyPair)) {
            throw new IllegalArgumentException("pair must be of type " + BouncyCastleAsymmetricCipherKeyPair.class + ": " + pair);
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
        // See https://github.com/bcgit/bc-java/blob/f1367f0b89962b29460eea381a12063fa7cd2428/core/src/main/java/org/bouncycastle/crypto/hpke/DHKEM.java#L204
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
        // See https://github.com/bcgit/bc-java/blob/f1367f0b89962b29460eea381a12063fa7cd2428/core/src/main/java/org/bouncycastle/crypto/hpke/DHKEM.java#L186
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

    // See https://github.com/bcgit/bc-java/blob/f1367f0b89962b29460eea381a12063fa7cd2428/core/src/main/java/org/bouncycastle/crypto/hpke/DHKEM.java#L59
    private static ECDomainParameters ecDomainParameters(KEM kem) {
        switch (kem) {
            case P256_SHA256:
                SecP256R1Curve p256R1Curve = new SecP256R1Curve();
                return new ECDomainParameters(
                        p256R1Curve,
                        p256R1Curve.createPoint(
                                new BigInteger(1, Hex.decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")),
                                new BigInteger(1, Hex.decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
                        ),
                        p256R1Curve.getOrder(),
                        p256R1Curve.getCofactor(),
                        Hex.decode("c49d360886e704936a6678e1139d26b7819f7e90")
                );
            case P384_SHA348:
                SecP384R1Curve p384R1Curve = new SecP384R1Curve();
                return new ECDomainParameters(
                        p384R1Curve,
                        p384R1Curve.createPoint(
                                new BigInteger(1, Hex.decode("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")),
                                new BigInteger(1, Hex.decode("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"))
                        ),
                        p384R1Curve.getOrder(),
                        p384R1Curve.getCofactor(),
                        Hex.decode("a335926aa319a27a1d00896a6773a4827acdac73")
                );
            case P521_SHA512:
                SecP521R1Curve p521R1Curve = new SecP521R1Curve();
                return new ECDomainParameters(
                        p521R1Curve,
                        p521R1Curve.createPoint(
                                new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
                                new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)
                        ),
                        p521R1Curve.getOrder(),
                        p521R1Curve.getCofactor(),
                        Hex.decode("d09e8800291cb85396cc6717393284aaa0da64ba")
                );
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
