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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.util.AsciiString;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class BinaryHttpConverterTest {

    private static final String URI = "/somewhere";
    private static final String SCHEME = "https";
    private static final String AUTHORITY = "someone@something";

    @Test
    void testConvertResponse() {
        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_XHTML);
        response.headers().set("SomeHeader", "someValue");
        BinaryHttpResponse converted = BinaryHttpConverter.convert(response);
        assertEquals(HttpVersion.HTTP_1_1, converted.protocolVersion());
        assertEquals(HttpResponseStatus.OK, converted.status());
        assertEquals(response.decoderResult(), converted.decoderResult());

        assertHeaders(response.headers(), converted.headers());
    }

    @Test
    void testConvertFullResponse() {
        ByteBuf buffer = Unpooled.buffer().writeLong(1);
        FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, buffer);
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_XHTML);
        response.headers().set("SomeHeader", "someValue");
        response.trailingHeaders().set("SomeHeader", "someValue");

        FullBinaryHttpResponse converted = BinaryHttpConverter.convert(response);
        assertEquals(HttpVersion.HTTP_1_1, converted.protocolVersion());
        assertEquals(HttpResponseStatus.OK, converted.status());
        assertEquals(response.decoderResult(), converted.decoderResult());
        assertEquals(buffer, converted.content());

        assertHeaders(response.headers(), converted.headers());
        assertHeaders(response.trailingHeaders(), converted.trailingHeaders());
    }

    @Test
    void testConvertRequest() {
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, URI);
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_XHTML);
        request.headers().set("SomeHeader", "someValue");
        BinaryHttpRequest converted = BinaryHttpConverter.convert(request, SCHEME, AUTHORITY);
        assertEquals(HttpVersion.HTTP_1_1, converted.protocolVersion());
        assertEquals(HttpMethod.GET, converted.method());
        assertEquals(URI, converted.uri());
        assertEquals(SCHEME, converted.scheme());
        assertEquals(AUTHORITY, converted.authority());
        assertEquals(request.decoderResult(), converted.decoderResult());

        assertHeaders(request.headers(), converted.headers());
    }

    @Test
    void testConvertFullRequest() {
        ByteBuf buffer = Unpooled.buffer().writeLong(1);
        FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, URI, buffer);
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_XHTML);
        request.headers().set("SomeHeader", "someValue");
        request.trailingHeaders().set("SomeHeader", "someValue");

        FullBinaryHttpRequest converted = BinaryHttpConverter.convert(request, SCHEME, AUTHORITY);
        assertEquals(HttpVersion.HTTP_1_1, converted.protocolVersion());
        assertEquals(HttpMethod.GET, converted.method());
        assertEquals(URI, converted.uri());
        assertEquals(SCHEME, converted.scheme());
        assertEquals(AUTHORITY, converted.authority());
        assertEquals(request.decoderResult(), converted.decoderResult());
        assertEquals(buffer, converted.content());

        assertHeaders(request.headers(), converted.headers());
        assertHeaders(request.trailingHeaders(), converted.trailingHeaders());
        converted.release();
    }

    private static void assertHeaders(HttpHeaders headers, HttpHeaders binaryHeaders) {
        for (Iterator<Map.Entry<CharSequence, CharSequence>> it = binaryHeaders.iteratorCharSequence(); it.hasNext();) {
            Map.Entry<CharSequence, CharSequence> entry = it.next();
            CharSequence name = entry.getKey();
            for (int i = 0; i < name.length(); i++) {
                assertFalse(AsciiString.isUpperCase(name.charAt(i)));
            }
            assertEquals(headers.get(name), entry.getValue().toString());
        }
    }
}
