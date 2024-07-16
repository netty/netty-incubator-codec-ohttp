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

import io.netty.handler.codec.DefaultHeaders;
import io.netty.handler.codec.UnsupportedValueConverter;
import io.netty.util.AsciiString;

/**
 * HTTP/2 (and HTTP/3) pseudo-headers names.
 */
enum PseudoHeaderName {
    /**
     * {@code :method}.
     */
    METHOD(":method"),

    /**
     * {@code :scheme}.
     */
    SCHEME(":scheme"),

    /**
     * {@code :authority}.
     */
    AUTHORITY(":authority"),

    /**
     * {@code :path}.
     */
    PATH(":path"),

    /**
     * {@code :status}.
     */
    STATUS(":status");

    private static final char PSEUDO_HEADER_PREFIX = ':';
    private static final byte PSEUDO_HEADER_PREFIX_BYTE = (byte) PSEUDO_HEADER_PREFIX;

    private final AsciiString value;
    private static final CharSequenceMap<PseudoHeaderName> PSEUDO_HEADERS = new CharSequenceMap<>();

    static {
        for (PseudoHeaderName pseudoHeader : PseudoHeaderName.values()) {
            PSEUDO_HEADERS.add(pseudoHeader.value(), pseudoHeader);
        }
    }

    PseudoHeaderName(String value) {
        this.value = AsciiString.cached(value);
    }

    public AsciiString value() {
        // Return a slice so that the buffer gets its own reader index.
        return value;
    }

    /**
     * Indicates whether the specified header follows the pseudo-header format (begins with ':' character)
     *
     * @param headerName    the header name to check.
     * @return              {@code true} if the header follow the pseudo-header format
     */
    public static boolean hasPseudoHeaderFormat(CharSequence headerName) {
        if (headerName.length() == 0) {
            return false;
        }
        if (headerName instanceof AsciiString) {
            return ((AsciiString) headerName).byteAt(0) == PSEUDO_HEADER_PREFIX_BYTE;
        }
        return isPseudoHeaderPrefix(headerName.charAt(0));
    }

    /**
     * Indicates whether the given header name is a valid HTTP/3 pseudo header.
     *
     * @param name  the header name.
     * @return      {@code true} if the given header name is a valid HTTP/3 pseudo header, {@code false} otherwise.
     */
    public static boolean isPseudoHeader(CharSequence name) {
        return PSEUDO_HEADERS.contains(name);
    }

    static boolean isPseudoHeaderPrefix(char c) {
        return PSEUDO_HEADER_PREFIX == c;
    }

    private static final class CharSequenceMap<V> extends DefaultHeaders<CharSequence, V, CharSequenceMap<V>> {
        CharSequenceMap() {
            super(AsciiString.CASE_SENSITIVE_HASHER, UnsupportedValueConverter.instance());
        }
    }
}
