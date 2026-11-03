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
package io.netty.incubator.codec.bhttp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.UnsupportedMessageTypeException;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class BinaryHttpSerializerKnownLengthTest {

    // See https://www.rfc-editor.org/rfc/rfc9292.html#section-5.1 (Figure 8).
    private static final String RFC9292_KNOWN_LENGTH_REQUEST =
            "0003474554056874747073000a2f68656c6c6f2e747874406c0a757365722d61" +
            "67656e74346375726c2f372e31362e33206c69626375726c2f372e31362e3320" +
            "4f70656e53534c2f302e392e376c207a6c69622f312e322e3304686f73740f77" +
            "77772e6578616d706c652e636f6d0f6163636570742d6c616e67756167650665" +
            "6e2c206d690000";

    @Test
    public void testRfc9292KnownLengthRequestExample() {
        FullBinaryHttpRequest request = new DefaultFullBinaryHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.GET, "https", "", "/hello.txt");
        request.headers().add("user-agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3");
        request.headers().add("host", "www.example.com");
        request.headers().add("accept-language", "en, mi");

        ByteBuf out = Unpooled.buffer();
        try {
            new BinaryHttpSerializer(true).serialize(request, out);
            assertArrayEquals(ByteBufUtil.decodeHexDump(RFC9292_KNOWN_LENGTH_REQUEST), ByteBufUtil.getBytes(out));
        } finally {
            out.release();
            request.release();
        }
    }

    @ParameterizedTest
    @CsvSource({ "false, false", "false, true", "true, false", "true, true" })
    public void testKnownLengthRequestRoundTrip(boolean withContent, boolean withTrailers) {
        byte[] body = withContent ? "request body".getBytes(StandardCharsets.US_ASCII) : new byte[0];
        FullBinaryHttpRequest request = new DefaultFullBinaryHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.POST, "https", "example.com", "/test",
                Unpooled.wrappedBuffer(body));
        request.headers().add("x-header", "value");
        if (withTrailers) {
            request.trailingHeaders().add("x-trailer", "trailer-value");
        }

        List<HttpObject> parsed = serializeAndParse(request, 0x00);
        try {
            BinaryHttpRequest parsedRequest = assertInstanceOf(BinaryHttpRequest.class, parsed.get(0));
            assertEquals(HttpMethod.POST, parsedRequest.method());
            assertEquals("https", parsedRequest.scheme());
            assertEquals("example.com", parsedRequest.authority());
            assertEquals("/test", parsedRequest.uri());
            assertEquals("value", parsedRequest.headers().get("x-header"));
            assertContentAndTrailers(parsed, body, withTrailers);
        } finally {
            parsed.forEach(ReferenceCountUtil::release);
        }
    }

    @ParameterizedTest
    @CsvSource({ "false, false", "false, true", "true, false", "true, true" })
    public void testKnownLengthResponseRoundTrip(boolean withContent, boolean withTrailers) {
        byte[] body = withContent ? "response body".getBytes(StandardCharsets.US_ASCII) : new byte[0];
        FullBinaryHttpResponse response = new DefaultFullBinaryHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.CREATED, Unpooled.wrappedBuffer(body));
        response.headers().add("x-header", "value");
        if (withTrailers) {
            response.trailingHeaders().add("x-trailer", "trailer-value");
        }

        List<HttpObject> parsed = serializeAndParse(response, 0x01);
        try {
            BinaryHttpResponse parsedResponse = assertInstanceOf(BinaryHttpResponse.class, parsed.get(0));
            assertEquals(HttpResponseStatus.CREATED, parsedResponse.status());
            assertEquals("value", parsedResponse.headers().get("x-header"));
            assertContentAndTrailers(parsed, body, withTrailers);
        } finally {
            parsed.forEach(ReferenceCountUtil::release);
        }
    }

    @Test
    public void testKnownLengthRequiresFullMessage() {
        BinaryHttpSerializer serializer = new BinaryHttpSerializer(true);
        ByteBuf out = Unpooled.buffer();
        HttpContent content = new DefaultHttpContent(Unpooled.EMPTY_BUFFER);
        try {
            assertThrows(UnsupportedMessageTypeException.class, () -> serializer.serialize(
                    new DefaultBinaryHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "https", "", "/"), out));
            assertThrows(UnsupportedMessageTypeException.class, () -> serializer.serialize(
                    new DefaultBinaryHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK), out));
            assertThrows(UnsupportedMessageTypeException.class, () -> serializer.serialize(content, out));
            assertThrows(UnsupportedMessageTypeException.class, () -> serializer.serialize(
                    LastHttpContent.EMPTY_LAST_CONTENT, out));
            assertFalse(out.isReadable());
        } finally {
            out.release();
        }
    }

    @Test
    public void testKnownLengthRejectsInformationalResponse() {
        FullBinaryHttpResponse response = new DefaultFullBinaryHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE);
        ByteBuf out = Unpooled.buffer();
        try {
            assertThrows(IllegalArgumentException.class, () -> new BinaryHttpSerializer(true).serialize(response, out));
        } finally {
            out.release();
            response.release();
        }
    }

    @Test
    public void testDefaultUsesIndeterminateLength() {
        FullBinaryHttpRequest request = new DefaultFullBinaryHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.GET, "https", "", "/");
        FullBinaryHttpResponse response = new DefaultFullBinaryHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        ByteBuf out = Unpooled.buffer();
        try {
            new BinaryHttpSerializer().serialize(request, out);
            assertEquals(0x02, out.getByte(0));
            out.clear();
            new BinaryHttpSerializer().serialize(response, out);
            assertEquals(0x03, out.getByte(0));
        } finally {
            out.release();
            request.release();
            response.release();
        }
    }

    private static List<HttpObject> serializeAndParse(LastHttpContent message, int expectedFramingIndicator) {
        ByteBuf out = Unpooled.buffer();
        try {
            new BinaryHttpSerializer(true).serialize(message, out);
            assertEquals(expectedFramingIndicator, out.getByte(out.readerIndex()));

            BinaryHttpParser parser = new BinaryHttpParser(Integer.MAX_VALUE);
            List<HttpObject> parsed = new ArrayList<>();
            for (;;) {
                HttpObject msg = parser.parse(out, true);
                if (msg == null) {
                    break;
                }
                parsed.add(msg);
            }
            assertFalse(out.isReadable());
            return parsed;
        } finally {
            out.release();
            message.release();
        }
    }

    private static void assertContentAndTrailers(List<HttpObject> parsed, byte[] expectedBody,
                                                 boolean expectTrailers) {
        ByteBuf body = Unpooled.buffer();
        try {
            LastHttpContent last = null;
            for (int i = 1; i < parsed.size(); i++) {
                assertNull(last);
                HttpContent content = assertInstanceOf(HttpContent.class, parsed.get(i));
                body.writeBytes(content.content(), content.content().readerIndex(),
                        content.content().readableBytes());
                if (content instanceof LastHttpContent) {
                    last = (LastHttpContent) content;
                }
            }
            assertArrayEquals(expectedBody, ByteBufUtil.getBytes(body));
            assertEquals(expectTrailers ? "trailer-value" : null,
                    assertInstanceOf(LastHttpContent.class, last).trailingHeaders().get("x-trailer"));
        } finally {
            body.release();
        }
    }
}
