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
import io.netty.buffer.ByteBufAllocator;
import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.AEAD;

final class BouncyCastleAEADCryptoContext implements AEADContext {

    private final BouncyCastleCryptoOperation open;
    private final BouncyCastleCryptoOperation seal;
    private boolean closed;

    BouncyCastleAEADCryptoContext(AEAD aead) {
        this.open = new BouncyCastleCryptoOperation() {
            @Override
            protected byte[] execute(byte[] aad, byte[] in, int inOffset, int inLength)
                    throws InvalidCipherTextException {
                return aead.open(aad, in, inOffset, inLength);
            }
        };
        this.seal = new BouncyCastleCryptoOperation() {
            @Override
            protected byte[] execute(byte[] aad, byte[] in, int inOffset, int inLength)
                    throws InvalidCipherTextException {
                return aead.seal(aad, in, inOffset, inLength);
            }
        };
    }

    @Override
    public void seal(ByteBufAllocator alloc, ByteBuf aad, ByteBuf pt, ByteBuf out) throws CryptoException {
        checkClosed();
        seal.execute(aad, pt, out);
    }

    @Override
    public void open(ByteBufAllocator alloc, ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException {
        checkClosed();
        open.execute(aad, ct, out);
    }

    private void checkClosed() {
        if (closed) {
            throw new IllegalStateException("AEADContext closed");
        }
    }

    @Override
    public boolean isDirectBufferPreferred() {
        return false;
    }

    @Override
    public void close() {
        closed = true;
    }
}
