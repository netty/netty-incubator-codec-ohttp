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
package io.netty.incubator.codec.hpke.boringssl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.incubator.codec.hpke.CryptoException;

/**
 * Abstract base class to perform native crypto operations via BoringSSL.
 */
abstract class BoringSSLCryptoOperation {

    /**
     * Executes a crypto related function and returns {@code true} if successful, {@code false} otherwise.
     * If successfully the {@link ByteBuf#readerIndex()} and {@link ByteBuf#writerIndex()} will be adjusted
     * accordingly.
     *
     * @param ctx   the native {@code *_CTX} pointer.
     * @param alloc {@link ByteBufAllocator} which might be used to do extra allocations.
     * @param aad   the AAD buffer.
     * @param in    the input data.
     * @param out   the buffer for writing into.
     * @return      {@code true} if successful, {@code false} otherwise.
     */
    final boolean execute(long ctx, ByteBufAllocator alloc, ByteBuf aad, ByteBuf in, ByteBuf out)
            throws CryptoException {
        ByteBuf directAad = null;
        ByteBuf directIn = null;
        ByteBuf directOut = null;
        try {
            directAad = directReadable(alloc, aad);
            directIn = directReadable(alloc, in);

            int maxOutLen = maxOutLen(ctx, in.readableBytes());
            directOut = directWritable(alloc, out, maxOutLen);

            long directAadAddress = BoringSSL.memory_address(directAad) + directAad.readerIndex();
            int directAddReadableBytes = directAad.readableBytes();
            long directInAddress = BoringSSL.memory_address(directIn) + directIn.readerIndex();
            int directInReadableBytes = directIn.readableBytes();
            long directOutAddress = BoringSSL.memory_address(directOut) + directOut.writerIndex();
            int directOutWritableBytes = directOut.writableBytes();
            int result = execute(ctx, alloc, directAadAddress, directAddReadableBytes,
                    directInAddress, directInReadableBytes,
                    directOutAddress, directOutWritableBytes);
            if (result < 0) {
                return false;
            }
            aad.skipBytes(directAddReadableBytes);
            in.skipBytes(directInReadableBytes);
            // Move the writerIndex.
            directOut.writerIndex(directOut.writerIndex() + result);
            if (out != directOut) {
                // If we allocated a temporary buffer we need to also copy over the result.
                out.writeBytes(directOut);
            }
            return true;
        } finally {
            // Release temporary copies if any.
            releaseIfNotTheSameInstance(aad, directAad);
            releaseIfNotTheSameInstance(in, directIn);
            releaseIfNotTheSameInstance(out, directOut);
        }
    }

    abstract int maxOutLen(long ctx, int inReadable);

    abstract int execute(long ctx, ByteBufAllocator alloc,
                         long ad, int adLen, long in, int inLen, long out, int outLen) throws CryptoException;

    private static ByteBuf directReadable(ByteBufAllocator alloc, ByteBuf in) {
        if (in.isDirect()) {
            return in;
        }
        ByteBuf directIn = alloc.directBuffer(in.readableBytes());
        directIn.writeBytes(in, in.readerIndex(), in.readableBytes());
        return directIn;
    }

    private static ByteBuf directWritable(ByteBufAllocator alloc, ByteBuf out, int minWritable) {
        if (out.isDirect()) {
            out.ensureWritable(minWritable);
            return out;
        }
        return alloc.directBuffer(minWritable);
    }

    private static void releaseIfNotTheSameInstance(ByteBuf buf, ByteBuf maybeOther) {
        if (maybeOther != null && maybeOther != buf) {
            maybeOther.release();
        }
    }
}
