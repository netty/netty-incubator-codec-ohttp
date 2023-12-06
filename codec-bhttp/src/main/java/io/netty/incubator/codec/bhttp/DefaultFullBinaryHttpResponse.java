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
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * {@link DefaultFullHttpResponse} for
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
public final class DefaultFullBinaryHttpResponse extends DefaultFullHttpResponse implements FullBinaryHttpResponse {

    public DefaultFullBinaryHttpResponse(HttpVersion version, HttpResponseStatus status) {
        this(version, status, Unpooled.EMPTY_BUFFER);
    }

    public DefaultFullBinaryHttpResponse(HttpVersion version, HttpResponseStatus status, ByteBuf content) {
        this(version, status, content, true);
    }

    public DefaultFullBinaryHttpResponse(HttpVersion version, HttpResponseStatus status, boolean validateHeaders) {
        this(version, status, Unpooled.EMPTY_BUFFER, validateHeaders);
    }

    public DefaultFullBinaryHttpResponse(HttpVersion version, HttpResponseStatus status, ByteBuf content, boolean validateHeaders) {
        this(version, status, content, BinaryHttpHeaders.newHeaders(validateHeaders), BinaryHttpHeaders.newTrailers(validateHeaders));
    }

    private DefaultFullBinaryHttpResponse(HttpVersion version, HttpResponseStatus status, ByteBuf content,
                                  HttpHeaders headers, HttpHeaders trailingHeaders) {
        super(version, status, content, headers, trailingHeaders);
    }

    @Override
    public FullBinaryHttpResponse retain() {
        super.retain();
        return this;
    }

    @Override
    public FullBinaryHttpResponse retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public FullBinaryHttpResponse touch() {
        super.touch();
        return this;
    }

    @Override
    public FullBinaryHttpResponse touch(Object hint) {
        super.touch(hint);
        return this;
    }

    @Override
    public FullBinaryHttpResponse setProtocolVersion(HttpVersion version) {
        super.setProtocolVersion(version);
        return this;
    }

    @Override
    public FullBinaryHttpResponse setStatus(HttpResponseStatus status) {
        super.setStatus(status);
        return this;
    }

    @Override
    public FullBinaryHttpResponse copy() {
        return replace(content().copy());
    }

    @Override
    public FullBinaryHttpResponse duplicate() {
        return replace(content().duplicate());
    }

    @Override
    public FullBinaryHttpResponse retainedDuplicate() {
        return replace(content().retainedDuplicate());
    }

    @Override
    public FullBinaryHttpResponse replace(ByteBuf content) {
        FullBinaryHttpResponse response = new DefaultFullBinaryHttpResponse(protocolVersion(), status(), content,
                headers().copy(), trailingHeaders().copy());
        response.setDecoderResult(decoderResult());
        return response;
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        return super.equals(o);
    }
}
