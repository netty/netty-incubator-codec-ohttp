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

import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.CryptoOperations;
import io.netty.incubator.codec.hpke.HPKE;
import io.netty.incubator.codec.hpke.HybridPublicKeyEncryption;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.security.SecureRandom;

public final class BouncyCastleHybridPublicKeyEncryption implements HybridPublicKeyEncryption {

    public static final BouncyCastleHybridPublicKeyEncryption INSTANCE = new BouncyCastleHybridPublicKeyEncryption();

    private BouncyCastleHybridPublicKeyEncryption() { }

    @Override
    public CryptoOperations newAEADCryptoOperations(AEAD aead, byte[] key, byte[] baseNonce) {
        return new BouncyCastleAEADCryptoOperations(new org.bouncycastle.crypto.hpke.AEAD(aead.id(), key, baseNonce));
    }

    @Override
    public HPKE newHPKE(Mode mode, KEM kem, KDF kdf, AEAD aead) {
        return new BouncyCastleHPKE(new org.bouncycastle.crypto.hpke.HPKE(mode.value(), kem.id(), kdf.id(), aead.id()));
    }

    /**
     * Returns a new {@link AsymmetricCipherKeyPair} from the given {@link X25519PrivateKeyParameters}.
     *
     * @param privateKey    the key.
     * @return              a new pair.
     */
    public static AsymmetricCipherKeyPair newKeyPair(X25519PrivateKeyParameters privateKey) {
        X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new BouncyCastleAsymmetricCipherKeyPair(
                new org.bouncycastle.crypto.AsymmetricCipherKeyPair(publicKey, privateKey));
    }
}
