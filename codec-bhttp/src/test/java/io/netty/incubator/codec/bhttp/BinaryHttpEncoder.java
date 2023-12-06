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
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpObject;

/**
 * {@link MessageToByteEncoder} that handles
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
final class BinaryHttpEncoder extends MessageToByteEncoder<HttpObject> {

    private final BinaryHttpSerializer serializer = new BinaryHttpSerializer();

    @Override
    public boolean isSharable() {
        return false;
    }

    @Override
    public boolean acceptOutboundMessage(Object msg) {
        return msg instanceof BinaryHttpRequest || msg instanceof BinaryHttpResponse || msg instanceof HttpContent;
    }

    @Override
    protected void encode(ChannelHandlerContext channelHandlerContext, HttpObject msg, ByteBuf out) {
        serializer.serialize(msg, out);
    }
}
