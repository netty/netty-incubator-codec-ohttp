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

import io.netty.buffer.ByteBuf;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKESenderContext;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;

final class BouncyCastleHPKESenderContext extends BouncyCastleHPKEContext implements HPKESenderContext {

    private final BouncyCastleCryptoOperation seal;
    public BouncyCastleHPKESenderContext(HPKEContextWithEncapsulation context) {
        super(context);
        this.seal = new BouncyCastleCryptoOperation() {
            @Override
            protected byte[] execute(byte[] arg1, byte[] arg2, int offset2, int length2)
                    throws InvalidCipherTextException {
                return context.seal(arg1, arg2, offset2, length2);
            }
        };
    }

    @Override
    public byte[] encapsulation() {
        return ((HPKEContextWithEncapsulation) context).getEncapsulation();
    }

    @Override
    public void seal(ByteBuf aad, ByteBuf pt, ByteBuf out) throws CryptoException {
        checkClosed();
        seal.execute(aad, pt, out);
    }
}
