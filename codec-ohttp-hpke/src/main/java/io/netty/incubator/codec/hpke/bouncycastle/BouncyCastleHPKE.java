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
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.HPKE;
import io.netty.incubator.codec.hpke.HPKEContext;
import io.netty.incubator.codec.hpke.HPKEContextWithEncapsulation;

class BouncyCastleHPKE implements HPKE {

    private final org.bouncycastle.crypto.hpke.HPKE hpke;

    BouncyCastleHPKE(org.bouncycastle.crypto.hpke.HPKE hpke) {
        this.hpke = hpke;
    }

    @Override
    public AsymmetricKeyParameter deserializePublicKey(byte[] pkEncoded) {
        return new BouncyCastleAsymmetricKeyParameter(hpke.deserializePublicKey(pkEncoded));
    }

    @Override
    public AsymmetricCipherKeyPair deserializePrivateKey(byte[] skEncoded, byte[] pkEncoded) {
        return new BouncyCastleAsymmetricCipherKeyPair(hpke.deserializePrivateKey(skEncoded, pkEncoded));
    }

    private static BouncyCastleAsymmetricKeyParameter castOrThrow(AsymmetricKeyParameter param) {
        if (!(param instanceof BouncyCastleAsymmetricKeyParameter)) {
            throw new IllegalArgumentException("param must be of type " + BouncyCastleAsymmetricKeyParameter.class);
        }
        return (BouncyCastleAsymmetricKeyParameter) param;
    }

    private static BouncyCastleAsymmetricCipherKeyPair castOrThrow(AsymmetricCipherKeyPair pair) {
        if (!(pair instanceof BouncyCastleAsymmetricCipherKeyPair)) {
            throw new IllegalArgumentException("pair must be of type " + BouncyCastleAsymmetricCipherKeyPair.class);
        }
        return (BouncyCastleAsymmetricCipherKeyPair) pair;
    }

    @Override
    public byte[] serializePublicKey(AsymmetricKeyParameter pk) {
        return hpke.serializePublicKey(castOrThrow(pk).param);
    }

    @Override
    public byte[] serializePrivateKey(AsymmetricKeyParameter sk) {
        return hpke.serializePrivateKey(castOrThrow(sk).param);
    }

    @Override
    public HPKEContextWithEncapsulation setupBaseS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE) {
        final org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation ctx;
        if (kpE == null) {
            ctx = hpke.setupBaseS(castOrThrow(pkR).param, info);
        } else {
            ctx = hpke.setupBaseS(castOrThrow(pkR).param, info, castOrThrow(kpE).pair);
        }
        return new BouncyCastleHPKEContextWithEncapsulation(ctx);
    }

    @Override
    public HPKEContext setupBaseR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info) {
        return new BouncyCastleHPKEContext(hpke.setupBaseR(enc, castOrThrow(skR).pair, info));
    }
}
