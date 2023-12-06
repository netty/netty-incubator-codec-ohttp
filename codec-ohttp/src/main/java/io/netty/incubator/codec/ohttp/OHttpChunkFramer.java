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

import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;

import java.util.List;

/**
 * Interface that defines how an Oblivious HTTP implementation handles the framing of chunks.
 * <br>
 * Instances of {@link OHttpChunkFramer} are stateless. The state management and encryption is delegated to
 * the {@link Decoder} and {@link Encoder} interfaces, which are typically implemented by
 * {@link OHttpContentParser} and {@link OHttpContentSerializer}, respectively.
 */
public interface OHttpChunkFramer<T> {

    /**
     * Parse a buffer that contains bytes of HTTP content that are encoded using Oblivious HTTP.
     *
     * @param in {@link ByteBuf} with HTTP content. Bytes that are consumed are removed.
     * @param completeBodyReceived true if no more input bytes are expected.
     * @param decoder {@link Decoder} that handles the decoding of the prefix and chunks.
     * @param out {@link List} of {@link Object}s that are produced from the input.
     * @throws CryptoException if the prefix is invalid or a chunk cannot be decrypted.
     */
    void parse(ByteBuf in, boolean completeBodyReceived, Decoder decoder, List<Object> out) throws CryptoException;

    /**
     * {@link Decoder} handles decryption when parsing HTTP content.
     */
    interface Decoder {
        /**
         * Decode the initial bytes of the HTTP content.
         * @return true on success, on false if more bytes are needed.
         */
        boolean decodePrefix(ByteBuf in);

        /**
         * @return true if the prefix has not been decoded yet.
         */
        boolean isPrefixNeeded();

        /**
         * Decode an encrypted chunk.
         *
         * @param chunk {@link ByteBuf} with encrypted chunk.
         * @param chunkLength Length of the encrypted chunk.
         * @param completeBodyReceived true if no more input bytes are expected.
         * @param out {@link List} of {@link Object}s that are produced from the chunk.
         * @throws CryptoException if the chunk cannot be decrypted.
         */
        void decodeChunk(ByteBuf chunk, int chunkLength, boolean completeBodyReceived, List<Object> out) throws CryptoException;
    }

    /**
     * Serialize an object into HTTP content bytes that are encoded using Oblivious HTTP.
     *
     * @param msg Object to serialize.
     * @param encoder {@link Encoder} that handles the encoding of prefix and chunks.
     * @param out {@link ByteBuf} that produced HTTP content bytes are appended to.
     * @throws CryptoException if the chunk cannot be encrypted.
     */
    void serialize(T msg, Encoder<T> encoder, ByteBuf out) throws CryptoException;

    /**
     * {@link Encoder} handles encryption when serializing objects into HTTP content.
     */
    interface Encoder<T> {
        /**
         * Encode the beginning of the HTTP content body.
         * @param out buffer to write the bytes.
         * @throws CryptoException if the prefix cannot be encoded.
         */
        void encodePrefix(ByteBuf out) throws CryptoException;

        /**
         * @return true if the prefix has not been encoded yet.
         */
        boolean isPrefixNeeded();

        /**
         * Encode an object into a chunk.
         *
         * @param msg object to encode.
         * @param out the {@link ByteBuf} into which the chunk is encoded.
         * @throws CryptoException if the chunk cannot be encrypted.
         */
        void encodeChunk(T msg, ByteBuf out) throws CryptoException;
    }
}
