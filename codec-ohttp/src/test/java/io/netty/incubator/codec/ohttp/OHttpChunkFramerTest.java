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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.TooLongFrameException;
import org.junit.jupiter.api.Test;

import static io.netty.incubator.codec.ohttp.OHttpConstants.MAX_CHUNK_SIZE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OHttpChunkFramerTest {

    private static ByteBuf bytesFromHex(String hex) {
        return Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(hex));
    }

    // =================== SERIALIZATION TESTS ==================== //

    private static void serializeHelper(String chunkHex, boolean isFinal, String expectedEncodedHex) {
        ByteBuf out = Unpooled.buffer();
        try {
            ByteBuf in = bytesFromHex(chunkHex);
            try {
                OHttpVersionChunkDraft.serializeChunk(in, isFinal, out, MAX_CHUNK_SIZE);
                assertEquals(expectedEncodedHex, ByteBufUtil.hexDump(out));
            } finally {
                in.release();
            }
        } finally {
            out.release();
        }
    }

    private static <T extends Throwable> void serializeThrowsHelper(
            String chunkHex, boolean isFinal, Class<T> exception) {
        ByteBuf out = Unpooled.buffer();
        try {
            ByteBuf in = bytesFromHex(chunkHex);
            try {
                assertThrows(exception, () -> OHttpVersionChunkDraft.serializeChunk(in, isFinal, out, MAX_CHUNK_SIZE));
            } finally {
                in.release();
            }
        } finally {
            out.release();
        }
    }

    @Test
    public void serialize() {
        serializeHelper("112233", false, "03112233");
        serializeHelper("112233", true, "00112233");
    }

    @Test
    public void serializeEmpty() {
        serializeThrowsHelper("", false, EncoderException.class);
        serializeThrowsHelper("", true, EncoderException.class);
    }

    @Test
    public void serializeLarge() {
        ByteBuf out = Unpooled.buffer();
        try {
            ByteBuf in = Unpooled.buffer().writeBytes(new byte[MAX_CHUNK_SIZE]);
            try {
                OHttpVersionChunkDraft.serializeChunk(in, false, out, MAX_CHUNK_SIZE);
            } finally {
                in.release();
            }
            assertEquals(out.readableBytes(), MAX_CHUNK_SIZE + 4); // Extra bytes: 4 for length

            ByteBuf in2 = Unpooled.buffer().writeBytes(new byte[MAX_CHUNK_SIZE + 1]);
            try {
                assertThrows(EncoderException.class,
                        () -> OHttpVersionChunkDraft.serializeChunk(in2, false, out, MAX_CHUNK_SIZE));
            } finally {
                in2.release();
            }
        } finally {
            out.release();
        }
    }

    // =================== DESERIALIZATION TESTS ==================== //

    private static void parseHelper(String dataHex,
                                    boolean isLast, long expectedLength,
                                    boolean expectedIsFinal, long expectedReaderOffset) {
        ByteBuf in = bytesFromHex(dataHex);
        try {
            // Check that all substrings yield no chunk
            if (!isLast) {
                for (int i = 0; i < in.readableBytes(); i++) {
                    assertNull(OHttpVersionChunkDraft.parseNextChunk(in.slice(0, i), isLast, MAX_CHUNK_SIZE));
                }
            }

            OHttpVersionChunkDraft.ChunkInfo chunkInfo =
                    OHttpVersionChunkDraft.parseNextChunk(in, isLast, MAX_CHUNK_SIZE);
            assertNotNull(chunkInfo);
            assertEquals(expectedLength, chunkInfo.length);
            assertEquals(expectedIsFinal, chunkInfo.isFinal);
            assertEquals(expectedReaderOffset, in.readerIndex());
        } finally {
            in.release();
        }
    }

    private static void parseNullHelper(String dataHex, boolean isLast) {
        ByteBuf in = bytesFromHex(dataHex);
        try {
            OHttpVersionChunkDraft.ChunkInfo chunkInfo =
                    OHttpVersionChunkDraft.parseNextChunk(in, isLast, MAX_CHUNK_SIZE);
            assertNull(chunkInfo);
            assertEquals(0, in.readerIndex());
        } finally {
            in.release();
        }
    }

    private static <T extends Throwable> void parseThrowsHelper(String dataHex, boolean isLast, Class<T> exception) {
        ByteBuf in = bytesFromHex(dataHex);
        try {
            assertThrows(exception, () -> OHttpVersionChunkDraft.parseNextChunk(in, isLast, MAX_CHUNK_SIZE));
            assertEquals(0, in.readerIndex());
        } finally {
            in.release();
        }
    }

    @Test
    public void parse() {
        parseHelper("03112233", false , 3, false, 1);
        parseHelper("03112233", true,  3, false, 1);
        parseHelper("00112233", true,  3, true, 1);
        parseNullHelper("00112233", false);
    }

    @Test
    public void parseNeedMoreData() {
        parseNullHelper("", false);
        parseNullHelper("", true);
        parseNullHelper("02", false);
        parseNullHelper("02", true);
    }

    @Test
    public void parseErrors() {
        parseThrowsHelper("ffffffffffffffff", true, TooLongFrameException.class);
    }
}
