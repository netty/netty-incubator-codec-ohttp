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
import io.netty.buffer.ByteBufUtil;
import io.netty.incubator.codec.hpke.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.nio.ByteBuffer;

abstract class BouncyCastleCryptoOperation {

    final void execute(ByteBuf aad, ByteBuf in, ByteBuf out) throws CryptoException {
        final int aadLength = aad.readableBytes();
        final byte[] aadArray = ByteBufUtil.getBytes(aad, aad.readerIndex(), aad.readableBytes(), false);
        final byte[] inArray;
        final int inLength = in.readableBytes();
        final int inOffset;

        if (in.hasArray()) {
            // This is backed by a bytearray, just use it as input to reduce memory copies.
            inArray = in.array();
            inOffset = in.arrayOffset() + in.readerIndex();
        } else {
            inArray = new byte[inLength];
            in.getBytes(in.readerIndex(), inArray);
            inOffset = 0;
        }
        try {
            byte[] result = execute(aadArray, inArray, inOffset, inLength);
            aad.skipBytes(aadLength);
            in.skipBytes(inLength);
            out.writeBytes(result);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }
    }

   protected abstract byte[] execute(byte[] aad, byte[] in, int inOffset, int inLength)
            throws InvalidCipherTextException;
}
