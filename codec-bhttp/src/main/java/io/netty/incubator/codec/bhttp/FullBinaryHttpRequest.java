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
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;


/**
 * {@link FullHttpRequest} for
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
public interface FullBinaryHttpRequest extends FullHttpRequest, BinaryHttpRequest {

    @Override
    FullBinaryHttpRequest copy();

    @Override
    FullBinaryHttpRequest duplicate();

    @Override
    FullBinaryHttpRequest retainedDuplicate();

    @Override
    FullBinaryHttpRequest replace(ByteBuf byteBuf);

    @Override
    FullBinaryHttpRequest retain(int i);

    @Override
    FullBinaryHttpRequest retain();

    @Override
    FullBinaryHttpRequest touch();

    @Override
    FullBinaryHttpRequest touch(Object o);

    @Override
    FullBinaryHttpRequest setProtocolVersion(HttpVersion httpVersion);

    @Override
    FullBinaryHttpRequest setMethod(HttpMethod httpMethod);

    @Override
    FullBinaryHttpRequest setUri(String s);
}
