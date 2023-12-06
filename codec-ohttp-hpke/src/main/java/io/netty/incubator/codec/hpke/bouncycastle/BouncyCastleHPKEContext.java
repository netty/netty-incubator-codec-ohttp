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

import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKEContext;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.nio.ByteBuffer;

class BouncyCastleHPKEContext implements HPKEContext {
    protected final org.bouncycastle.crypto.hpke.HPKEContext context;
    private final BouncyCastleCryptoOperation seal;
    private final BouncyCastleCryptoOperation open;

    BouncyCastleHPKEContext(org.bouncycastle.crypto.hpke.HPKEContext context) {
        this.context = context;
        this.seal = new BouncyCastleCryptoOperation() {
            @Override
            protected byte[] execute(byte[] arg1, byte[] arg2, int offset2, int length2) throws InvalidCipherTextException {
                return context.seal(arg1, arg2, offset2, length2);
            }
        };
        this.open = new BouncyCastleCryptoOperation() {
            @Override
            protected byte[] execute(byte[] arg1, byte[] arg2, int offset2, int length2) throws InvalidCipherTextException {
                return context.open(arg1, arg2, offset2, length2);
            }
        };
    }

    @Override
    public byte[] export(byte[] exportContext, int length) {
        return context.export(exportContext, length);
    }

    @Override
    public byte[] extract(byte[] salt, byte[] ikm) {
        return context.extract(salt, ikm);
    }

    @Override
    public byte[] expand(byte[] prk, byte[] info, int length) {
        return context.expand(prk, info, length);
    }

    @Override
    public ByteBuffer seal(ByteBuffer aad, ByteBuffer pt) throws CryptoException {
        return seal.execute(aad, pt);
    }

    @Override
    public ByteBuffer open(ByteBuffer aad, ByteBuffer ct) throws CryptoException {
        return open.execute(aad, ct);
    }
}
