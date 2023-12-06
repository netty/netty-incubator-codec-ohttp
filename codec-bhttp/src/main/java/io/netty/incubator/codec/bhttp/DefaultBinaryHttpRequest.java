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

import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

import java.util.Objects;


/**
 * Default implementation of {@link BinaryHttpRequest}.
 */
public final class DefaultBinaryHttpRequest extends DefaultHttpRequest implements BinaryHttpRequest {
    private final String scheme;
    private final String authority;

    /**
     * Creates a new instance.
     *
     * @param httpVersion       {@link HttpVersion} to use
     * @param method            {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     */
    public DefaultBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                    String uri) {
        this(httpVersion, method, scheme, authority, uri, true);
    }

    /**
     * Creates a new instance.
     *
     * @param httpVersion       {@link HttpVersion} to use
     * @param method            {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     * @param validateHeaders   {@code true} if header validation should be done when add headers, {@code false} otherwise.
     */
    public DefaultBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                    String uri, boolean validateHeaders) {
        this(httpVersion, method, scheme, authority, uri, BinaryHttpHeaders.newHeaders(validateHeaders));
    }

    /**
     * Creates a new instance.
     *
     * @param httpVersion       {@link HttpVersion} to use
     * @param method            {@link HttpMethod} to use
     * @param scheme            the scheme to use.
     * @param authority         the authority to use.
     * @param uri               the uri / path to use
     * @param headers           {@link BinaryHttpHeaders} of the request.
     */
    DefaultBinaryHttpRequest(HttpVersion httpVersion, HttpMethod method, String scheme, String authority,
                                    String uri, BinaryHttpHeaders headers) {
        super(httpVersion, method, uri, headers);
        this.authority = authority;
        this.scheme = Objects.requireNonNull(scheme);
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
    public BinaryHttpRequest setMethod(HttpMethod method) {
        super.setMethod(method);
        return this;
    }

    @Override
    public BinaryHttpRequest setUri(String uri) {
        super.setUri(uri);
        return this;
    }

    @Override
    public BinaryHttpRequest setProtocolVersion(HttpVersion version) {
        super.setProtocolVersion(version);
        return this;
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

        DefaultBinaryHttpRequest other = (DefaultBinaryHttpRequest) o;

        return Objects.equals(scheme, other.scheme) && Objects.equals(authority, other.authority);
    }
}
