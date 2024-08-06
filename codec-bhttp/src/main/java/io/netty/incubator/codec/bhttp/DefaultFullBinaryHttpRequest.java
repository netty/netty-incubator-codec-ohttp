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
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

import java.util.Objects;

/**
 * Default implementation of {@link FullBinaryHttpRequest}
 */
public final class DefaultFullBinaryHttpRequest extends DefaultFullHttpRequest implements FullBinaryHttpRequest {
    private final String scheme;
    private final String authority;

    /**
     * Creates a new instance.
     *
     * @param httpVersion {@link HttpVersion} to use
     * @param method      {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     */
    public DefaultFullBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                        String uri) {
        this(httpVersion, method, scheme, authority, uri, true);
    }

    /**
     * Creates a new instance.
     *
     * @param httpVersion {@link HttpVersion} to use
     * @param method      {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     * @param content     the payload of the request.
     */
    public DefaultFullBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                        String uri, ByteBuf content) {
        this(httpVersion, method, scheme, authority, uri, content, true);
    }

    /**
     * Creates a new instance.
     *
     * @param httpVersion       {@link HttpVersion} to use
     * @param method            {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     * @param content           the payload of the request.
     * @param validateHeaders   {@code true} if header validation should be done when add headers, {@code false}
     *                          otherwise.
     */
    public DefaultFullBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                        String uri, ByteBuf content, boolean validateHeaders) {
        this(httpVersion, method, scheme, authority, uri, content, BinaryHttpHeaders.newHeaders(validateHeaders),
                BinaryHttpHeaders.newTrailers(validateHeaders));
    }

    /**
     * Creates a new instance.
     *
     * @param httpVersion       {@link HttpVersion} to use
     * @param method            {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     * @param headers           the {@link BinaryHttpHeaders} of the request.
     * @param trailingHeader    the trailers of the request.
     */
    DefaultFullBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                 String uri, ByteBuf content, BinaryHttpHeaders headers,
                                 BinaryHttpHeaders trailingHeader) {
        super(httpVersion, method, uri, content, headers, trailingHeader);
        this.scheme = Objects.requireNonNull(scheme, "scheme");
        this.authority = authority;
    }

    /**
     * Creates a new instance.
     *
     * @param httpVersion       {@link HttpVersion} to use
     * @param method            {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     * @param validateHeaders   {@code true} if header validation should be done when add headers, {@code false}
     *                          otherwise.
     */
    public DefaultFullBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                        String uri, boolean validateHeaders) {
        this(httpVersion, method, scheme, authority, uri, Unpooled.EMPTY_BUFFER, validateHeaders);
    }

    @Override
    public String scheme() {
        return scheme;
    }

    @Override
    public String authority() {
        return authority;
    }

    @Override
    public FullBinaryHttpRequest retain() {
        super.retain();
        return this;
    }

    @Override
    public FullBinaryHttpRequest retain(int increment) {
        super.retain(increment);
        return this;
    }

    @Override
    public FullBinaryHttpRequest touch() {
        super.touch();
        return this;
    }

    @Override
    public FullBinaryHttpRequest touch(Object hint) {
        super.touch(hint);
        return this;
    }

    @Override
    public FullBinaryHttpRequest retainedDuplicate() {
        return replace(this.content().retainedDuplicate());
    }

    @Override
    public FullBinaryHttpRequest replace(ByteBuf content) {
        FullBinaryHttpRequest request = new DefaultFullBinaryHttpRequest(
                protocolVersion(), method(), scheme(), authority(), uri(), content,
                (BinaryHttpHeaders) headers().copy(), (BinaryHttpHeaders) trailingHeaders().copy());
        request.setDecoderResult(this.decoderResult());
        return request;
    }

    @Override
    public FullBinaryHttpRequest setProtocolVersion(HttpVersion version) {
        super.setProtocolVersion(version);
        return this;
    }

    @Override
    public FullBinaryHttpRequest setMethod(HttpMethod method) {
        super.setMethod(method);
        return this;
    }

    @Override
    public FullBinaryHttpRequest setUri(String uri) {
        super.setUri(uri);
        return this;
    }

    @Override
    public FullBinaryHttpRequest copy() {
        return (FullBinaryHttpRequest) super.copy();
    }

    @Override
    public FullBinaryHttpRequest duplicate() {
        return (FullBinaryHttpRequest) super.duplicate();
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (scheme != null ? scheme.hashCode() : 0);
        result = 31 * result + (authority != null ? authority.hashCode() : 0);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        DefaultFullBinaryHttpRequest other = (DefaultFullBinaryHttpRequest) o;
        return Objects.equals(scheme, ((DefaultFullBinaryHttpRequest) o).scheme) &&
                Objects.equals(authority, other.authority);
    }
}
