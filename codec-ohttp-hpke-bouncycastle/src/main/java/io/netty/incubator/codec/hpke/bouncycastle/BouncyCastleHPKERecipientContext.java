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
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKERecipientContext;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKEContext;

final class BouncyCastleHPKERecipientContext extends BouncyCastleHPKEContext implements HPKERecipientContext {
    private final BouncyCastleCryptoOperation open;

    BouncyCastleHPKERecipientContext(HPKEContext context) {
        super(context);
        open = new BouncyCastleCryptoOperation() {
            @Override
            protected byte[] execute(byte[] aad, byte[] in, int inOffset, int inLength)
                    throws InvalidCipherTextException {
                return context.open(aad, in, inOffset, inLength);
            }
        };
    }

    @Override
    public void open(ByteBufAllocator alloc, ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException {
        checkClosed();
        open.execute(aad, ct, out);
    }

    @Override
    public boolean isDirectBufferPreferred() {
        return false;
    }
}
