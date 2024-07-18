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
import io.netty.util.CharsetUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class BinaryHttpParserTest {

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
        testInvalidHead(buffer);
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

    private static void testInvalidHead(ByteBuf input) {
        BinaryHttpParser parser = new BinaryHttpParser(8192);
        Assertions.assertThrows(IllegalArgumentException.class, () -> parser.parse(input, false));
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
