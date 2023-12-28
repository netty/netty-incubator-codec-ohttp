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
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpMessage;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.LastHttpContent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class BinaryHttpMessageEndToEndTest<M extends HttpMessage, F extends FullHttpMessage> {

    protected static void transfer(EmbeddedChannel writer, EmbeddedChannel reader, boolean fragmented) {
        if (!fragmented) {
            for (;;) {
                ByteBuf buffer = writer.readOutbound();
                if (buffer == null) {
                    assertFalse(writer.finishAndReleaseAll());
                    break;
                }
                assertTrue(reader.writeInbound(buffer));
            }
        } else {
            for (;;) {
                ByteBuf buffer = writer.readOutbound();
                if (buffer == null) {
                    assertFalse(writer.finishAndReleaseAll());
                    break;
                }
                while (buffer.isReadable()) {
                    // Add some randomness to how we fragment the data.
                    int bound = buffer.readableBytes() + 1;
                    int numBytes = ThreadLocalRandom.current().nextInt(0, bound);
                    reader.writeInbound(buffer.readRetainedSlice(numBytes));
                }
                buffer.release();
            }
        }
    }

    protected abstract M newHttpMessage();

    protected abstract F newFullHttpMessage(ByteBuf content);

    protected abstract void assertHttpMessage(M message);

    protected static EmbeddedChannel newWriter() {
        return new EmbeddedChannel(new BinaryHttpEncoder());
    }

    protected static EmbeddedChannel newReader() {
        return new EmbeddedChannel(new BinaryHttpDecoder(Integer.MAX_VALUE));
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testMessageWithoutContentAndWithoutTrailers(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        HttpMessage message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));
        assertTrue(writer.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        LastHttpContent readLastContent = reader.readInbound();
        assertEquals(0, readLastContent.content().readableBytes());
        assertEquals(0,  readLastContent.trailingHeaders().size());
        readLastContent.release();
        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testMessageWithoutContentAndWithTrailers(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        LastHttpContent content = new DefaultLastHttpContent();
        content.trailingHeaders().set("x-test-trailer", "test-value");
        content.trailingHeaders().set("x-test-trailer2", "test-value2");
        assertTrue(writer.writeOutbound(content));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();
        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        LastHttpContent readLastContent = reader.readInbound();
        assertEquals(0, readLastContent.content().readableBytes());
        HttpHeaders readLastHeaders = readLastContent.trailingHeaders();
        assertEquals(2, readLastHeaders.size());
        assertEquals("test-value", readLastHeaders.get("x-test-trailer"));
        assertEquals("test-value2", readLastHeaders.get("x-test-trailer2"));
        readLastContent.release();
        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testMessageWithContentAndWithoutTrailers(boolean fragmented) throws IOException {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        byte[] bytes = new byte[512];
        ThreadLocalRandom.current().nextBytes(bytes);
        assertTrue(writer.writeOutbound(new DefaultLastHttpContent(Unpooled.wrappedBuffer(bytes))));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        assertContentWithoutTrailers(reader, bytes);

        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testMessageWithContentAndWithTrailers(boolean fragmented) throws IOException {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        byte[] bytes = new byte[512];
        ThreadLocalRandom.current().nextBytes(bytes);

        LastHttpContent content = new DefaultLastHttpContent(Unpooled.wrappedBuffer(bytes));
        content.trailingHeaders().set("x-test-trailer", "test-value");
        content.trailingHeaders().set("x-test-trailer2", "test-value2");
        assertTrue(writer.writeOutbound(content));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        try (ByteArrayOutputStream contentWriter = new ByteArrayOutputStream()) {
            for (;;) {
                HttpContent readContent = reader.readInbound();
                if (readContent == null) {
                    break;
                }
                readContent.content().readBytes(contentWriter, readContent.content().readableBytes());
                if (readContent instanceof LastHttpContent) {
                    HttpHeaders trailers = ((LastHttpContent) readContent).trailingHeaders();
                    assertEquals(2, trailers.size());
                    assertEquals("test-value", trailers.get("x-test-trailer"));
                    assertEquals("test-value2", trailers.get("x-test-trailer2"));

                    // There must be no other content after the LastHttpContent
                    assertNull(reader.readInbound());
                }
                readContent.release();
            }
            assertArrayEquals(bytes, contentWriter.toByteArray());
        }
        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testMessageShutdownInputAfterHead(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        assertNull(reader.readInbound());

        // Signal end of inbound.
        reader.pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);

        LastHttpContent readLastContent = reader.readInbound();
        assertEquals(0, readLastContent.content().readableBytes());
        assertEquals(0,  readLastContent.trailingHeaders().size());
        readLastContent.release();
        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testMessageShutdownInputAfterContent(boolean fragmented) throws Exception {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        byte[] bytes = new byte[512];
        ThreadLocalRandom.current().nextBytes(bytes);

        HttpContent content = new DefaultHttpContent(Unpooled.wrappedBuffer(bytes));
        assertTrue(writer.writeOutbound(content));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        try (ByteArrayOutputStream contentWriter = new ByteArrayOutputStream()) {
            for (;;) {
                HttpContent readContent = reader.readInbound();
                if (readContent == null) {
                    break;
                }
                readContent.content().readBytes(contentWriter, readContent.content().readableBytes());
                assertFalse(readContent instanceof LastHttpContent);
                readContent.release();
            }

            assertArrayEquals(bytes, contentWriter.toByteArray());
        }

        // Signal end of inbound.
        reader.pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);

        LastHttpContent readLastContent = reader.readInbound();
        assertEquals(0, readLastContent.content().readableBytes());
        assertEquals(0,  readLastContent.trailingHeaders().size());
        readLastContent.release();
        assertFalse(reader.finishAndReleaseAll());
    }

    @Test
    void testShutdownWhileDecodeContent() {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));
        ByteBuf encodedHead = writer.readOutbound();
        assertTrue(reader.writeInbound(encodedHead));

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));

        byte[] bytes = new byte[512];
        ThreadLocalRandom.current().nextBytes(bytes);

        HttpContent content = new DefaultHttpContent(Unpooled.wrappedBuffer(bytes));
        assertTrue(writer.writeOutbound(content));

        ByteBuf encodedContent = writer.readOutbound();

        assertTrue(reader.writeInbound(encodedContent.readSlice(encodedContent.readableBytes() / 2)));

        assertThrows(CorruptedFrameException.class, () -> {
            // Signal end of inbound while in the middle of decoding content.
            // This should throw.
            reader.pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);
            reader.checkException();
        });

        assertFalse(writer.finishAndReleaseAll());
        assertTrue(reader.finishAndReleaseAll());
    }

    @Test
    void testShutdownWhileDecodeHead() {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        ByteBuf buffer = transferIntoBuffer(writer);
        // Truncate
        buffer.writerIndex(buffer.writerIndex() - 1);
        assertFalse(reader.writeInbound(buffer));

        assertThrows(CorruptedFrameException.class, () -> {
            // Signal end of inbound while in the middle of decoding head
            reader.pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);
            reader.checkException();
        });

        assertFalse(writer.finishAndReleaseAll());
        assertFalse(reader.finishAndReleaseAll());
    }

    @Test
    void testShutdownWhileDecodeTrailers() {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        LastHttpContent content = new DefaultLastHttpContent();
        content.trailingHeaders().add("x-test-trailer", "test-value");
        assertTrue(writer.writeOutbound(content));

        ByteBuf buffer = transferIntoBuffer(writer);
        // Truncate
        buffer.writerIndex(buffer.writerIndex() - 1);
        // The head should still be produced.
        assertTrue(reader.writeInbound(buffer));

        assertThrows(CorruptedFrameException.class, () -> {
            // Signal end of inbound while in the middle of decoding head
            reader.pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);
            reader.checkException();
        });

        assertFalse(writer.finishAndReleaseAll());
        assertTrue(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testInvalidPadding(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));
        assertTrue(writer.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT));

        transfer(writer, reader, fragmented);
        assertInstanceOf(HttpMessage.class, reader.readInbound());

        LastHttpContent readLastContent = reader.readInbound();
        assertEquals(0, readLastContent.content().readableBytes());
        readLastContent.release();

        // Just write some valid padding bytes followed by some invalid padding bytes
        assertThrows(CorruptedFrameException.class,
                () -> reader.writeInbound(Unpooled.buffer().writeZero(16).writeInt(4)));

        assertFalse(writer.finishAndReleaseAll());
        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testValidPadding(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));
        assertTrue(writer.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT));

        transfer(writer, reader, fragmented);
        assertInstanceOf(HttpMessage.class, reader.readInbound());

        LastHttpContent readLastContent = reader.readInbound();
        assertEquals(0, readLastContent.content().readableBytes());
        readLastContent.release();

        // Just write some valid padding bytes.
        // These should be just consumed
        assertFalse(reader.writeInbound(Unpooled.buffer().writeZero(16)));

        assertFalse(writer.finishAndReleaseAll());
        assertFalse(reader.finishAndReleaseAll());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testPseudoHeaderInTrailers(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = new EmbeddedChannel(new BinaryHttpDecoder(Integer.MAX_VALUE));

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));
        LastHttpContent content = new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER, new DefaultHttpHeaders(false));
        content.trailingHeaders().set(":custom-pseudo-header", "OK");
        assertTrue(writer.writeOutbound(content));

        assertThrows(DecoderException.class, () -> transfer(writer, reader, fragmented));
        writer.finishAndReleaseAll();
        reader.finishAndReleaseAll();
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testCustomPseudoHeaders(boolean fragmented) {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = new EmbeddedChannel(new BinaryHttpDecoder(Integer.MAX_VALUE));

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        message.headers().set(":custom-pseudo-header", "OK");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));
        assertTrue(writer.writeOutbound(LastHttpContent.EMPTY_LAST_CONTENT));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();
        assertEquals(3, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));
        assertEquals("OK", readHeaders.get(":custom-pseudo-header"));

        LastHttpContent last = reader.readInbound();
        last.release();

        assertFalse(writer.finishAndReleaseAll());
        assertFalse(reader.finishAndReleaseAll());
    }

    @Test
    void testFieldSectionLimitInHeaders() {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = new EmbeddedChannel(new BinaryHttpDecoder(2));

        M message = newHttpMessage();
        message.headers().set("x-test-header", "test-value");
        assertTrue(writer.writeOutbound(message));
        ByteBuf encodedHead = writer.readOutbound();
        assertThrows(TooLongFrameException.class, () -> reader.writeInbound(encodedHead));
        writer.finishAndReleaseAll();
        reader.finishAndReleaseAll();
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void testFullMessageWithContentAndWithoutTrailers(boolean fragmented) throws IOException {
        EmbeddedChannel writer = newWriter();
        EmbeddedChannel reader = newReader();

        byte[] bytes = new byte[512];
        ThreadLocalRandom.current().nextBytes(bytes);
        F message = newFullHttpMessage(Unpooled.wrappedBuffer(bytes));
        message.headers().set("x-test-header", "test-value");
        message.headers().set("x-test-header2", "test-value2");
        assertTrue(writer.writeOutbound(message));

        transfer(writer, reader, fragmented);

        M readMessage = reader.readInbound();
        assertHttpMessage(readMessage);

        HttpHeaders readHeaders = readMessage.headers();

        assertEquals(2, readHeaders.size());
        assertEquals("test-value", readHeaders.get("x-test-header"));
        assertEquals("test-value2", readHeaders.get("x-test-header2"));
        assertContentWithoutTrailers(reader, bytes);

        assertFalse(reader.finishAndReleaseAll());
    }

    private static void assertContentWithoutTrailers(EmbeddedChannel reader, byte[] expectedContent)
            throws IOException {
        try (ByteArrayOutputStream contentWriter = new ByteArrayOutputStream()) {
            for (;;) {
                HttpContent readContent = reader.readInbound();
                if (readContent == null) {
                    break;
                }
                readContent.content().readBytes(contentWriter, readContent.content().readableBytes());
                if (readContent instanceof LastHttpContent) {
                    assertEquals(0,  ((LastHttpContent) readContent).trailingHeaders().size());
                    // There must be no other content after the LastHttpContent
                    assertNull(reader.readInbound());
                }
                readContent.release();
            }
            assertArrayEquals(expectedContent, contentWriter.toByteArray());
        }
    }

    protected static ByteBuf transferIntoBuffer(EmbeddedChannel writer) {
        ByteBuf aggregateBuffer = Unpooled.buffer();
        for (;;) {
            ByteBuf buffer = writer.readOutbound();
            if (buffer == null) {
                assertFalse(writer.finishAndReleaseAll());
                break;
            }
            aggregateBuffer.writeBytes(buffer);
            buffer.release();
        }
        return aggregateBuffer;
    }
}
