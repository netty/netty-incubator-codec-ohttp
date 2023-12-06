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
package io.netty.incubator.codec.ohttp;

import io.netty.incubator.codec.bhttp.BinaryHttpSerializer;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.LastHttpContent;

/**
 * Serializer that serializes {@link HttpObject}s to {@link ByteBuf} that can be used as OHTTP message content.
 */
abstract class OHttpContentSerializer {

    private final OHttpChunkFramer<HttpObject> framer;

    private final ContentEncoder contentEncoder = new ContentEncoder();

    OHttpContentSerializer(OHttpChunkFramer<HttpObject> framer) {
        this.framer = framer;
    }

    /**
     * Serialize a {@link HttpObject} into a {@link ByteBuf}.
     * @param msg {@link HttpObject} to serialize.
     * @param out {@link ByteBuf} that serialized bytes are appended to.
     */
    public final void serialize(HttpObject msg, ByteBuf out) throws CryptoException {
        framer.serialize(msg, contentEncoder, out);
    }

    /**
     * Encrypt a chunk.
     * @param chunk {@link ByteBuf} to encrypt. The function increases the reader index by chunkLength.
     * @param chunkLength length of chunk.
     * @param isFinal true if this is the last chunk.
     * @param out {@link ByteBuf} into which the encrypted bytes are written.
     * @throws CryptoException if the encryption fails.
     */
    protected abstract void encryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out)
            throws CryptoException;

    /**
     * Encode the beginning of the HTTP content body.
     * @param out buffer to write the bytes.
     * @throws CryptoException if the prefix cannot be encoded.
     */
    protected abstract void encodePrefixNow(ByteBuf out) throws CryptoException;

    private class ContentEncoder implements OHttpChunkFramer.Encoder<HttpObject> {

        private final BinaryHttpSerializer binaryHttpSerializer = new BinaryHttpSerializer();

        private boolean encodedPrefix;

        @Override
        public final boolean isPrefixNeeded() {
            return !encodedPrefix;
        }

        @Override
        public final void encodeChunk(HttpObject msg, ByteBuf out) throws CryptoException {
            ByteBuf binaryHttpBytes = out.alloc().buffer();
            try {
                boolean isFinal = msg instanceof LastHttpContent;
                binaryHttpSerializer.serialize(msg, binaryHttpBytes);
                encryptChunk(binaryHttpBytes, binaryHttpBytes.readableBytes(), isFinal, out);
            } finally {
                binaryHttpBytes.release();
            }
        }

        @Override
        public final void encodePrefix(ByteBuf out) throws CryptoException {
            if (encodedPrefix) {
                throw new IllegalStateException("Prefix already encoded");
            }
            encodePrefixNow(out);
            encodedPrefix = true;
        }
    }
}
