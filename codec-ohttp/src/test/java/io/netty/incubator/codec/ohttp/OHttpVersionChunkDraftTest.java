/*
 * Copyright 2026 The Netty Project
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
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.incubator.codec.bhttp.VarIntCodecUtils;
import io.netty.incubator.codec.hpke.CryptoException;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class OHttpVersionChunkDraftTest {
    private static final OHttpChunkFramer.Decoder NOOP_DECODER = new OHttpChunkFramer.Decoder() {
        @Override
        public boolean decodePrefix(ByteBufAllocator alloc, ByteBuf in) {
            return false;
        }

        @Override
        public boolean isPrefixNeeded() {
            return false;
        }

        @Override
        public void decodeChunk(ByteBufAllocator alloc, ByteBuf chunk, int chunkLength,
                                boolean completeBodyReceived, List<Object> out) {
            // Noop.
        }
    };

    @Test
    public void testTruncation() {
        ByteBufAllocator alloc = UnpooledByteBufAllocator.DEFAULT;
        ByteBuf buf = alloc.buffer();
        try {
            List<Object> out = new ArrayList<>();
            VarIntCodecUtils.writeVariableLengthInteger(buf, 8);
            assertThrows(CorruptedFrameException.class, () -> OHttpVersionChunkDraft.INSTANCE.parse(
                    alloc, buf, true, NOOP_DECODER, out));
        } finally {
            buf.release();
        }
    }

    @Test
    public void testNoTruncation() throws CryptoException {
        ByteBufAllocator alloc = UnpooledByteBufAllocator.DEFAULT;
        ByteBuf buf = alloc.buffer();
        try {
            List<Object> out = new ArrayList<>();
            VarIntCodecUtils.writeVariableLengthInteger(buf, 0);
            OHttpVersionChunkDraft.INSTANCE.parse(
                    alloc, buf, true, NOOP_DECODER, out);
        } finally {
            buf.release();
        }
    }
}
