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

import io.netty.incubator.codec.bhttp.BinaryHttpParser;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpObject;

import java.util.List;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;

/**
 * Parser that parses {@link ByteBuf}s coming from the content of a OHTTP-encoded message
 * into {@link HttpObject}s.
 */
abstract class OHttpContentParser {

    private final OHttpChunkFramer<HttpObject> framer;

    private ContentDecoder decoder = new ContentDecoder();

    OHttpContentParser(OHttpChunkFramer<HttpObject> framer) {
        this.framer = framer;
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
    public final void parse(ByteBuf in, boolean completeBodyReceived, List<Object> out) throws CryptoException {
        if (decoder == null) {
            throw new IllegalStateException("Already destroyed");
        }

        framer.parse(in, completeBodyReceived, decoder, out);

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
     * Must be called once the {@link OHttpContentParser} will not be used anymore.
     */
    public void destroy() {
        if (decoder != null) {
            decoder.destroy();
            decoder = null;
        }
    }

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
            if (OHttpContentParser.this.decodePrefix(in)) {
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
