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

import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.http.HttpContent;
import io.netty.incubator.codec.bhttp.BinaryHttpParser;
import io.netty.incubator.codec.bhttp.BinaryHttpSerializer;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.LastHttpContent;

import java.util.List;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;

/**
 * Handler that parses and serializes {@link HttpObject}s to {@link ByteBuf} that can be used as OHTTP message content
 * during a request-response cycle.
 */
abstract class OHttpRequestResponseContext {
    private final OHttpVersion version;
    private final ContentEncoder contentEncoder = new ContentEncoder();
    private ContentDecoder decoder = new ContentDecoder();

    OHttpRequestResponseContext(OHttpVersion version) {
        this.version = version;
    }

    final OHttpVersion version() {
        return version;
    }

    /**
     * Serialize a {@link HttpObject} into a {@link ByteBuf}.
     * @param msg {@link HttpObject} to serialize.
     * @param out {@link ByteBuf} that serialized bytes are appended to.
     */
    final void serialize(HttpObject msg, ByteBuf out) throws CryptoException {
        version.serialize(msg, contentEncoder, out);
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
    protected abstract void encodePrefix(ByteBuf out) throws CryptoException;

    private final class ContentEncoder implements OHttpChunkFramer.Encoder<HttpObject> {

        private final BinaryHttpSerializer binaryHttpSerializer = new BinaryHttpSerializer();

        private boolean encodedPrefix;

        @Override
        public boolean isPrefixNeeded() {
            return !encodedPrefix;
        }

        @Override
        public void encodeChunk(HttpObject msg, ByteBuf out) throws CryptoException {
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
        public void encodePrefix(ByteBuf out) throws CryptoException {
            if (encodedPrefix) {
                throw new IllegalStateException("Prefix already encoded");
            }
            OHttpRequestResponseContext.this.encodePrefix(out);
            encodedPrefix = true;
        }
    }


    /**
     * Parse OHTTP-encoded HTTP content bytes.
     * <br>
     * If the input is coming from {@link HttpContent}, the caller is responsible for maintaining
     * a cumulation buffer since this function might not consume all the bytes from the input.
     * <br>
     * @param in HTTP content bytes. Consumed bytes are removed from the {@link ByteBuf}.
     * @param completeBodyReceived true if there are no more bytes following in.
     * @param out List that produced {@link HttpObject} are appended to.
     */
    final void parse(ByteBuf in, boolean completeBodyReceived, List<Object> out) throws CryptoException {
        if (decoder == null) {
            throw new IllegalStateException("Already destroyed");
        }

        version.parse(in, completeBodyReceived, decoder, out);

        if (completeBodyReceived && in.isReadable()) {
            throw new CorruptedFrameException("OHTTP stream has extra bytes");
        }
    }

    /**
     * Decode the initial bytes of the HTTP content.
     * @return true on success, on false if more bytes are needed.
     */
    protected abstract boolean decodePrefix(ByteBuf in);

    /**
     * Decrypt a chunk.
     * @param chunk {@link ByteBuf} to decrypt. The function increases the reader index by chunkLength.
     * @param chunkLength length of chunk.
     * @param isFinal true if this is the last chunk.
     * @param out the {@link ByteBuf} into which the decrypted bytes are written.
     * @throws CryptoException if the decryption fails.
     */
    protected abstract void decryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out) throws CryptoException;

    /**
     * Must be called once the {@link OHttpRequestResponseContext} will not be used anymore.
     */
    final void destroy() {
        if (decoder != null) {
            decoder.destroy();
            decoder = null;
        }
        destroyCrypto();
    }

    abstract void destroyCrypto();

    private final class ContentDecoder implements OHttpChunkFramer.Decoder {

        // Allow up to 8kb for the field-section.
        private final BinaryHttpParser binaryHttpParser = new BinaryHttpParser(8 * 1024);

        // Cumulation buffer with plaintext binary HTTP bytes, which are coming from decrypted type 0 chunks.
        private ByteBuf binaryHttpCumulation = Unpooled.EMPTY_BUFFER;

        private boolean decodedPrefix;

        @Override
        public boolean isPrefixNeeded() {
            return !decodedPrefix;
        }

        @Override
        public boolean decodePrefix(ByteBuf in) {
            if (decodedPrefix) {
                throw new IllegalStateException("Prefix already decoded");
            }
            if (OHttpRequestResponseContext.this.decodePrefix(in)) {
                decodedPrefix = true;
                return true;
            }
            return false;
        }

        @Override
        public void decodeChunk(ByteBuf chunk, int chunkLength, boolean completeBodyReceived, List<Object> out)
                throws CryptoException {
            ByteBuf decryptedChunk = chunk.alloc().buffer();
            decryptChunk(chunk, chunkLength, completeBodyReceived, decryptedChunk);
            binaryHttpCumulation = MERGE_CUMULATOR.cumulate(chunk.alloc(), binaryHttpCumulation, decryptedChunk);
            for (;;) {
                HttpObject msg = binaryHttpParser.parse(binaryHttpCumulation, completeBodyReceived);
                if (msg == null) {
                    return;
                }
                out.add(msg);
            }
        }

        void destroy() {
            binaryHttpCumulation.release();
            binaryHttpCumulation = Unpooled.EMPTY_BUFFER;
        }
    }
}
