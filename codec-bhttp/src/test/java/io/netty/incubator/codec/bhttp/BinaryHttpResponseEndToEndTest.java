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
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BinaryHttpResponseEndToEndTest extends BinaryHttpMessageEndToEndTest<BinaryHttpResponse, FullBinaryHttpResponse> {
    @Override
    protected BinaryHttpResponse newHttpMessage() {
        return new DefaultBinaryHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
    }

    @Override
    protected FullBinaryHttpResponse newFullHttpMessage(ByteBuf content) {
        return new DefaultFullBinaryHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
    }

    @Override
    protected void assertHttpMessage(BinaryHttpResponse message) {
        assertEquals(HttpVersion.HTTP_1_1, message.protocolVersion());
        assertEquals(HttpResponseStatus.OK, message.status());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testInvalidStatus(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        HttpResponse message = newHttpMessage();
        message.setStatus(new HttpResponseStatus(99, "Invalid"));
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        DecoderException e = assertThrows(DecoderException.class, () -> transfer(writer, reader, fragmented));
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
        writer.finishAndReleaseAll();
        reader.finishAndReleaseAll();
    }
}
