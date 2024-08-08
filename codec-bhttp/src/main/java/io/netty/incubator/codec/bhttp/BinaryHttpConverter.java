/*
 * Copyright 2024 The Netty Project
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

import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.AsciiString;

import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/**
 * Class which contains various methods to convert from regular HTTP1/x to
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>..
 */
public final class BinaryHttpConverter {

    private BinaryHttpConverter() { }

    /**
     * Creates a {@link BinaryHttpRequest} from the given {@link HttpRequest}, scheme and authority.
     * All {@link HttpHeaders} names of the {@link HttpRequest} will be changed to lowercase to be in line with
     * the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a> specification.
     *
     * @param request   the request.
     * @param scheme    the scheme
     * @param authority the authority.
     * @return          the created request.
     */
    public static BinaryHttpRequest convert(HttpRequest request, String scheme, String authority) {
        BinaryHttpHeaders headers = BinaryHttpHeaders.newHeaders(true);
        copyAndSanitize(request.headers(), headers);

        DefaultBinaryHttpRequest binaryHttpRequest = new DefaultBinaryHttpRequest(request.protocolVersion(),
                request.method(), scheme, authority, request.uri(), headers);
        binaryHttpRequest.setDecoderResult(request.decoderResult());
        return binaryHttpRequest;
    }

    /**
     * Creates a {@link FullBinaryHttpRequest} from the given {@link FullHttpRequest}, scheme and authority.
     * All {@link HttpHeaders} names of the {@link FullHttpRequest} will be changed to lowercase to be in line with
     * the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a> specification.
     * This method will take ownership of {@link FullBinaryHttpRequest} and so is responsible for releasing it.
     *
     * @param request   the request.
     * @param scheme    the scheme
     * @param authority the authority.
     * @return          the created request.
     */
    public static FullBinaryHttpRequest convert(FullHttpRequest request, String scheme, String authority) {
        BinaryHttpHeaders headers = BinaryHttpHeaders.newHeaders(true);
        copyAndSanitize(request.headers(), headers);

        BinaryHttpHeaders trailers = BinaryHttpHeaders.newTrailers(true);
        copyAndSanitize(request.trailingHeaders(), trailers);

        FullBinaryHttpRequest binaryHttpRequest =  new DefaultFullBinaryHttpRequest(request.protocolVersion(),
                request.method(), scheme, authority, request.uri(), request.content().retain(), headers, trailers);
        binaryHttpRequest.setDecoderResult(request.decoderResult());
        request.release();
        return binaryHttpRequest;
    }

    /**
     * Creates a {@link BinaryHttpResponse} from the given {@link HttpResponse}.
     * All {@link HttpHeaders} names of the {@link HttpResponse} will be changed to lowercase to be in line with
     * the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a> specification.
     *
     * @param response  the response.
     * @return          the created response.
     */
    public static BinaryHttpResponse convert(HttpResponse response) {
        BinaryHttpHeaders headers = BinaryHttpHeaders.newHeaders(true);
        copyAndSanitize(response.headers(), headers);

        BinaryHttpResponse binaryHttpResponse = new DefaultBinaryHttpResponse(
                response.protocolVersion(), response.status(), headers);
        binaryHttpResponse.setDecoderResult(response.decoderResult());
        return binaryHttpResponse;
    }

    /**
     * Creates a {@link FullBinaryHttpResponse} from the given {@link FullHttpResponse}.
     * All {@link HttpHeaders} names of the {@link FullHttpResponse} will be changed to lowercase to be in line with
     * the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a> specification.
     * This method will take ownership of {@link FullBinaryHttpResponse} and so is responsible for releasing it.
     *
     * @param response  the response.
     * @return          the created response.
     */
    public static FullBinaryHttpResponse convert(FullHttpResponse response) {
        BinaryHttpHeaders headers = BinaryHttpHeaders.newHeaders(true);
        copyAndSanitize(response.headers(), headers);

        BinaryHttpHeaders trailers = BinaryHttpHeaders.newTrailers(true);
        copyAndSanitize(response.trailingHeaders(), trailers);

        FullBinaryHttpResponse binaryHttpResponse =  new DefaultFullBinaryHttpResponse(response.protocolVersion(),
                response.status(), response.content().retain(), headers, trailers);
        binaryHttpResponse.setDecoderResult(response.decoderResult());
        response.release();
        return binaryHttpResponse;
    }

    /**
     * Creates a BHTTP compatible {@link LastHttpContent} from the given {@link LastHttpContent}.
     * All {@link HttpHeaders} names of the {@link LastHttpContent} will be changed to lowercase to be in line with
     * the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a> specification.
     * This method will take ownership of {@link LastHttpContent} and so is responsible for releasing it.

     * @param content   the last content..
     * @return          the created content.
     */
    public static LastHttpContent convert(LastHttpContent content) {
        BinaryHttpHeaders trailers = BinaryHttpHeaders.newTrailers(true);
        copyAndSanitize(content.trailingHeaders(), trailers);
        LastHttpContent binaryContent =  new DefaultLastHttpContent(content.content().retain(), trailers);
        content.release();
        return binaryContent;
    }

    /**
     * Copy the given {@link HttpHeaders} to another {@link HttpHeaders} instance that is compatible with
     * OHTTP.
     * All {@link HttpHeaders} names of the {@link HttpHeaders} will be changed to lowercase to be in line with
     * the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a> specification.
     *
     * @param in                the HTTP/1.x headers
     * @param out               the BHTTP headers.
     */
    public static void copyAndSanitize(HttpHeaders in, HttpHeaders out) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");

        for (Iterator<Map.Entry<CharSequence, CharSequence>> it = in.iteratorCharSequence(); it.hasNext();) {
            final Map.Entry<CharSequence, CharSequence> entry = it.next();
            final CharSequence name = entry.getKey();
            if (name instanceof AsciiString) {
                // Let's just convert to lowerCase() directly if needed, otherwise
                // this will just return the same instance.
                out.add(((AsciiString) name).toLowerCase(), entry.getValue());
            } else if (name instanceof String) {
                // Let's just convert to lowerCase() directly if needed, otherwise
                // this will just return the same instance.
                out.add(((String) name).toLowerCase(), entry.getValue());
            } else if (isAnyUpperCase(name)) {
                // Create a lowercase AsciiString, alternative we could also have a CharSequence that lowercase stuff
                // on the fly.
                out.add(new AsciiString(name).toLowerCase(), entry.getValue());
            } else {
                // No need to convert it as it is lowercase already.
                out.add(name, entry.getValue());
            }
        }
    }

    private static boolean isAnyUpperCase(CharSequence name) {
        int len = name.length();
        for (int i = 0; i < len; i++) {
            if (AsciiString.isUpperCase(name.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
