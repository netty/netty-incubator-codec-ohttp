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
package io.netty.incubator.codec.bhttp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.HttpObject;

import java.util.List;

/**
 * {@link ByteToMessageDecoder} that handles
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
final class BinaryHttpDecoder extends ByteToMessageDecoder {
    private final BinaryHttpParser parser;

    /**
     * Creates a new instance
     *
     * @param maxFieldSectionSize   the maximum size of the field-section (in bytes)
     */
    BinaryHttpDecoder(int maxFieldSectionSize) {
        this.parser = new BinaryHttpParser(maxFieldSectionSize);
    }

    @Override
    public boolean isSharable() {
        return false;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        decodeAll(in, out, false);
    }

    @Override
    protected void decodeLast(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        decodeAll(in, out, true);
    }

    private void decodeAll(ByteBuf in, List<Object> out, boolean completeBodyReceived) {
        for (;;) {
            HttpObject msg = parser.parse(in, completeBodyReceived);
            if (msg == null) {
                return;
            }
            out.add(msg);
        }
    }
}
