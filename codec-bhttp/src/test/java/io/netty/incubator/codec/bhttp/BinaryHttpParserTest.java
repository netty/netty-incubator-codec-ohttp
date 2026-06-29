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
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.util.CharsetUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class BinaryHttpParserTest {

    @Test
    void testExactBoundary() {
        ByteBuf buffer = Unpooled.buffer();
        VarIntCodecUtils.writeVariableLengthInteger(buffer, 0); // known-length request
        writeString(buffer, "GET");
        writeString(buffer, "https");
        writeString(buffer, "example.com");
        writeString(buffer, "/");
        VarIntCodecUtils.writeVariableLengthInteger(buffer, 4); // field section length
        writeString(buffer, "a");
        writeString(buffer, "b");
        BinaryHttpRequest parsed = (BinaryHttpRequest)
                new BinaryHttpParser(8192).parse(buffer, false);
        assertNotNull(parsed);
        assertEquals(HttpMethod.GET, parsed.method());
        assertEquals("https", parsed.scheme());
        assertEquals("example.com", parsed.authority());
        assertEquals("/", parsed.uri());
        assertEquals(1, parsed.headers().size());
        assertEquals("b", parsed.headers().get("a"));
        buffer.release();
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 2 })
    void testOverflow(int frameIndicator) {
        ByteBuf buffer = Unpooled.buffer();
        VarIntCodecUtils.writeVariableLengthInteger(buffer, frameIndicator);
        VarIntCodecUtils.writeVariableLengthInteger(buffer, (long) Integer.MAX_VALUE + 1);
        // write one byte so we continue process and should see a too large number that would overflow
        buffer.writeByte((byte) 'a');
        BinaryHttpParser parser = new BinaryHttpParser(8192);
        Assertions.assertThrows(TooLongFrameException.class, () -> parser.parse(buffer, false));
        buffer.release();
    }

    @ParameterizedTest
    @EnumSource(Part.class)
    void testInvalidInitialLineSize(Part part) {
        ByteBuf buffer = Unpooled.buffer();
        VarIntCodecUtils.writeVariableLengthInteger(buffer, 0);
        int methodIdx = buffer.writerIndex();
        writeString(buffer, "GET");
        int schemeIdx = buffer.writerIndex();
        writeString(buffer, "HTTPS");
        int authorityIdx = buffer.writerIndex();
        writeString(buffer, "something");
        int pathIdx = buffer.writerIndex();
        writeString(buffer, "/somepath");
        VarIntCodecUtils.writeVariableLengthInteger(buffer, 0);

        int limit = 0;
        switch (part) {
            case METHOD:
                limit = methodIdx - 1;
                break;
            case SCHEME:
                limit = schemeIdx - 1;
                break;
            case AUTHORITY:
                limit = authorityIdx - 1;
                break;
            case PATH:
                limit = pathIdx - 1;
                break;
            default:
                fail();
                break;
        }
        testInvalidHead(buffer, limit, TooLongFrameException.class);
    }

    @ParameterizedTest(name = "{index} => {0}, {1}, {2}")
    @MethodSource("invalidChars")
    void testInvalidMethodSuffix(Position p, Part part, String hexString, Character c) {
        ByteBuf buffer = Unpooled.buffer();
        VarIntCodecUtils.writeVariableLengthInteger(buffer, 0);

        writeString(Part.METHOD, "GET", buffer, p, part, c);
        writeString(Part.SCHEME, "HTTPS", buffer, p, part, c);
        writeString(Part.AUTHORITY, "something", buffer, p, part, c);
        writeString(Part.PATH, "/somepath", buffer, p, part, c);
        VarIntCodecUtils.writeVariableLengthInteger(buffer, 0);
        testInvalidHead(buffer, 256, IllegalArgumentException.class);
    }

    private void writeString(Part currentPart, String str, ByteBuf out, Position p, Part part, Character c) {
        if (currentPart == part) {
            switch (p) {
                case PREFIX:
                    writeString(out, c + str);
                    break;
                case SUFFIX:
                    writeString(out, str + c);
                    break;
                case MIDDLE:
                    writeString(out, str.substring(0, 1) + c + str.substring(1));
                    break;
            }
        } else {
            writeString(out, str);
        }
    }
    private static Stream<Arguments> invalidChars() {
        List<Arguments> invalid = new ArrayList<>();
        for (int i = Byte.MIN_VALUE; i < Byte.MAX_VALUE; i++) {
            char c = (char) i;
            if (Character.isWhitespace(c)) {
                for (Position p: Position.values()) {
                    for (Part part: Part.values()) {
                        invalid.add(Arguments.of(p, part, "0x" + Integer.toHexString(c), c));
                    }
                }
            }
        }
        return invalid.stream();
    }

    private static void writeString(ByteBuf out, String str) {
        byte[] bytes = str.getBytes(CharsetUtil.US_ASCII);
        VarIntCodecUtils.writeVariableLengthInteger(out, bytes.length);
        out.writeBytes(bytes);
    }

    private static void testInvalidHead(ByteBuf input, int maxInitialLineSize,
                                        Class<? extends Throwable> exceptionType) {
        BinaryHttpParser parser = new BinaryHttpParser(maxInitialLineSize, 8192);
        Assertions.assertThrows(exceptionType, () -> parser.parse(input, false));
        input.release();
    }

    private enum Position {
        PREFIX,
        MIDDLE,
        SUFFIX;
    }

    private enum Part {
        METHOD,
        SCHEME,
        AUTHORITY,
        PATH
    }
}
