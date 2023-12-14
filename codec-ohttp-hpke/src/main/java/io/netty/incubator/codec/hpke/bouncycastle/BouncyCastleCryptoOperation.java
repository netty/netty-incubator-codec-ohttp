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

    final void execute(ByteBuf arg1, ByteBuf arg2, ByteBuf out) throws CryptoException {
        final int length1 = arg1.readableBytes();
        final byte[] array1 = ByteBufUtil.getBytes(arg1, arg1.readerIndex(), arg1.readableBytes(), false);
        final byte[] array2;
        final int length2 = arg2.readableBytes();
        final int offset2;

        if (arg2.hasArray()) {
            // This is backed by a bytearray, just use it as input to reduce memory copies.
            array2 = arg2.array();
            offset2 = arg2.arrayOffset() + arg2.readerIndex();
        } else {
            array2 = new byte[length2];
            arg2.getBytes(arg2.readerIndex(), array2);
            offset2 = 0;
        }
        try {
            byte[] result = execute(array1, array2, offset2, length2);
            arg1.skipBytes(length1);
            arg2.skipBytes(length2);
            out.writeBytes(result);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }
    }

   protected abstract byte[] execute(byte[] arg1, byte[] arg2, int offset2, int length2)
            throws InvalidCipherTextException;
}
