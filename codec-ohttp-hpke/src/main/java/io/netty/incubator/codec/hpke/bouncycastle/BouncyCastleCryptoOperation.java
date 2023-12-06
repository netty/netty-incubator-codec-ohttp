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
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.nio.ByteBuffer;

abstract class BouncyCastleCryptoOperation {

    final ByteBuffer execute(ByteBuffer arg1, ByteBuffer arg2) throws CryptoException {
        final byte[] array1;
        if (arg1.hasArray() && arg1.position() == 0 && arg1.arrayOffset() == 0) {
            // No need to copy we can just unwrap the array
            array1 = arg1.array();
        } else {
            array1 = new byte[arg1.remaining()];
            int savePosition = arg1.position();
            arg1.get(array1);
            arg1.position(savePosition);
        }

        final byte[] array2;
        final int offset2;
        final int length2;
        if (arg2.hasArray()) {
            // This is backed by a bytearray, just use it as input to reduce memory copies.
            array2 = arg2.array();
            offset2 = arg2.arrayOffset() + arg2.position();
            length2 = arg2.remaining();
        } else {
            array2 = new byte[arg2.remaining()];
            int savePosition = arg2.position();
            arg2.get(array2);
            arg2.position(savePosition);
            offset2 = 0;
            length2 = array2.length;
        }
        try {
            byte[] result = execute(array1, array2, offset2, length2);
            arg1.position(arg1.limit());
            arg2.position(arg2.limit());
            return ByteBuffer.wrap(result);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException(e);
        }
    }

   protected abstract byte[] execute(byte[] arg1, byte[] arg2, int offset2, int length2)
            throws InvalidCipherTextException;
}
