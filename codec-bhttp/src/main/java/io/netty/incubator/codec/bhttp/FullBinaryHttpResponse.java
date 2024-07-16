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
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * {@link FullHttpResponse} for
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
public interface FullBinaryHttpResponse extends FullHttpResponse, BinaryHttpResponse {
    @Override
    FullBinaryHttpResponse copy();

    @Override
    FullBinaryHttpResponse duplicate();

    @Override
    FullBinaryHttpResponse retainedDuplicate();

    @Override
    FullBinaryHttpResponse replace(ByteBuf byteBuf);

    @Override
    FullBinaryHttpResponse retain(int i);

    @Override
    FullBinaryHttpResponse retain();

    @Override
    FullBinaryHttpResponse touch();

    @Override
    FullBinaryHttpResponse touch(Object o);

    @Override
    FullBinaryHttpResponse setProtocolVersion(HttpVersion httpVersion);

    @Override
    FullBinaryHttpResponse setStatus(HttpResponseStatus httpResponseStatus);
}
