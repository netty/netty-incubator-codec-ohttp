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

import io.netty.buffer.ByteBufAllocator;
import io.netty.incubator.codec.bhttp.VarIntCodecUtils;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.AsciiString;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static io.netty.incubator.codec.ohttp.OHttpConstants.MAX_CHUNK_SIZE;

/**
 * Implementation of
 * <a href="https://www.ietf.org/archive/id/draft-ohai-chunked-ohttp-00.html">Chunked Oblivious HTTP Messages</a>.
 *
 * <pre>
 * Chunked Chunks {
 *   Non-Final Chunk (..) ...,
 *   Final Chunk(..)
 * }
 *
 * Non-Final Chunk {
 *   Chunk Length (i) = 1..,
 *   Protected Chunk Content (..)
 * }
 *
 * Final Chunk {
 *   Chunk Length (i) = 0,
 *   Protected Chunk Content (..)
 * }
 * </pre>
 */
public final class OHttpVersionChunkDraft implements OHttpVersion {

    public static final OHttpVersion INSTANCE = new OHttpVersionChunkDraft();

    private static final byte[] CHUNKED_REQUEST_EXPORT_CONTEXT =
            "message/bhttp chunked request".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CHUNKED_RESPONSE_EXPORT_CONTEXT =
            "message/bhttp chunked response".getBytes(StandardCharsets.US_ASCII);

    private OHttpVersionChunkDraft() {
    }

    @Override
    public byte[] requestExportContext() {
        return CHUNKED_REQUEST_EXPORT_CONTEXT.clone();
    }

    @Override
    public byte[] responseExportContext() {
        return CHUNKED_RESPONSE_EXPORT_CONTEXT.clone();
    }

    @Override
    public boolean useFinalAad() {
        return true;
    }

    @Override
    public AsciiString requestContentType() {
        return OHttpConstants.CHUNKED_REQUEST_CONTENT_TYPE;
    }

    @Override
    public AsciiString responseContentType() {
        return OHttpConstants.CHUNKED_RESPONSE_CONTENT_TYPE;
    }

    static final class ChunkInfo {
        final int length; // Content length
        final boolean isFinal;

        private ChunkInfo(int length, boolean isFinal) {
            this.length = length;
            this.isFinal = isFinal;
        }
    }

    static ChunkInfo parseNextChunk(ByteBuf in, boolean isLast) {
        if (!in.isReadable()) {
            return null;
        }
        final int initialReaderIndex = in.readerIndex();
        ChunkInfo info = null;
        try {
            byte firstByte = in.getByte(initialReaderIndex);
            int lengthNumBytes = VarIntCodecUtils.numBytesForVariableLengthIntegerFromByte(firstByte);
            if (in.readableBytes() < lengthNumBytes) {
                return null;
            }
            long contentLength = VarIntCodecUtils.readVariableLengthInteger(in, lengthNumBytes);
            if (contentLength > MAX_CHUNK_SIZE) {
                throw new TooLongFrameException("Chunk is too large: " + contentLength + " > " + MAX_CHUNK_SIZE);
            }
            if (contentLength > 0) {
                // Non-Final chunk
                if (in.readableBytes() < contentLength) {
                    return null;
                }
                info = new ChunkInfo((int) contentLength, false);
            } else {
                // Final chunk
                if (!isLast) {
                    return null;
                }
                info = new ChunkInfo(in.readableBytes(), true);
            }
            return info;
        } finally {
            if (info == null) {
                // Restore the reader index in case of incomplete read or exception.
                in.readerIndex(initialReaderIndex);
            }
        }
    }

    static void serializeChunk(ByteBuf content, boolean isFinal, ByteBuf out) {
        if (content.readableBytes() > MAX_CHUNK_SIZE) {
            throw new EncoderException("Chunk is too large to be serialized");
        }
        if (!content.isReadable()) {
            throw new EncoderException("Empty chunks cannot be serialized");
        }
        if (isFinal) {
            out.writeByte(0);
        } else {
            VarIntCodecUtils.writeVariableLengthInteger(out, content.readableBytes());
        }
        out.writeBytes(content);
    }

    @Override
    public void parse(ByteBufAllocator alloc, ByteBuf in, boolean completeBodyReceived,
                      Decoder decoder, List<Object> out) throws CryptoException {
        if (decoder.isPrefixNeeded()) {
            if (!decoder.decodePrefix(alloc, in)) {
                if (completeBodyReceived) {
                    throw new CorruptedFrameException("Prefix is truncated");
                }
                return;
            }
        }
        while (in.isReadable()) {
            ChunkInfo chunkInfo = parseNextChunk(in, completeBodyReceived);
            if (chunkInfo == null) {
                break;
            }
            decoder.decodeChunk(alloc, in, chunkInfo.length, chunkInfo.isFinal, out);
        }
    }

    @Override
    public void serialize(ByteBufAllocator alloc, HttpObject msg, Encoder<HttpObject> encoder, ByteBuf out)
            throws CryptoException {
        if (encoder.isPrefixNeeded()) {
            encoder.encodePrefix(alloc, out);
        }
        boolean isFinal = msg instanceof LastHttpContent;

        ByteBuf encryptedBytes = alloc.buffer();
        try {
            encoder.encodeChunk(alloc, msg, encryptedBytes);
            serializeChunk(encryptedBytes, isFinal, out);
        } finally {
            encryptedBytes.release();
        }
    }
}
