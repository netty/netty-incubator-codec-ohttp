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

public final class VarIntCodecUtils {

    private VarIntCodecUtils() { }

    /**
     * Returns the number of bytes needed to encode the
     * <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc">variable length integer</a>.
     */
    public static int numBytesForVariableLengthInteger(long value) {
        if (value <= 63) {
            return 1;
        }
        if (value <= 16383) {
            return 2;
        }
        if (value <= 1073741823) {
            return 4;
        }
        if (value <= 4611686018427387903L) {
            return 8;
        }
        throw new IllegalArgumentException("Value larger then 4611686018427387903: " + value);
    }

    /**
     * Returns the number of bytes needed to encode a
     * <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc">variable length integer</a>,
     * based on the initial encoded byte.
     */
    public static int numBytesForVariableLengthIntegerFromByte(byte value) {
        switch (value & 0xc0) {
            case 0x00:
                return 1;
            case 0x40:
                return 2;
            case 0x80:
                return 4;
            case 0xc0:
                return 8;
        }
        throw new IllegalArgumentException("Illegal byte value: " + String.format("%02X", value));
    }

    /**
     * Read the <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc">variable length integer</a>
     * from the {@link ByteBuf}.
     */
    public static long readVariableLengthInteger(ByteBuf in, int len) {
        long variableLength = getVariableLengthInteger(in, in.readerIndex(), len);
        in.skipBytes(len);
        return variableLength;
    }

    /**
     * Get the <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc">variable length integer</a>
     * from the {@link ByteBuf}.
     */
    public static long getVariableLengthInteger(ByteBuf in, int offset, int len) {
        switch (len) {
            case 1:
                return in.getUnsignedByte(offset);
            case 2:
                return in.getUnsignedShort(offset) & 0x3fff;
            case 4:
                return in.getUnsignedInt(offset) & 0x3fffffff;
            case 8:
                return in.getLong(offset) & 0x3fffffffffffffffL;
            default:
                throw new IllegalArgumentException("len must be either 1, 2, 4 or 8, but was " + len);
        }
    }

    /**
     * Write the <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc">variable length integer</a> into the {@link ByteBuf}.
     */
    public static void writeVariableLengthInteger(ByteBuf out, long value) {
        int numBytes = VarIntCodecUtils.numBytesForVariableLengthInteger(value);
        writeVariableLengthInteger(out, value, numBytes);
    }

    /**
     * Write the <a href="https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc">variable length integer</a> into the {@link ByteBuf}.
     */
    private static void writeVariableLengthInteger(ByteBuf out, long value, int numBytes) {
        int writerIndex = out.writerIndex();
        switch (numBytes) {
            case 1:
                out.writeByte((byte) value);
                break;
            case 2:
                out.writeShort((short) value);
                encodeLengthIntoBuffer(out, writerIndex, (byte) 0x40);
                break;
            case 4:
                out.writeInt((int) value);
                encodeLengthIntoBuffer(out, writerIndex, (byte) 0x80);
                break;
            case 8:
                out.writeLong(value);
                encodeLengthIntoBuffer(out, writerIndex, (byte) 0xc0);
                break;
            default:
                throw new IllegalArgumentException("numBytes must be either 1, 2, 4 or 8, but was " + numBytes);
        }
    }

    private static void encodeLengthIntoBuffer(ByteBuf out, int index, byte b) {
        out.setByte(index, out.getByte(index) | b);
    }
}
