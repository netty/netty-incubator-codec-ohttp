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
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaderValidationUtil;
import io.netty.util.AsciiString;
import io.netty.util.ByteProcessor;

import static io.netty.util.AsciiString.isUpperCase;

/**
 * {@link DefaultHttpHeaders} sub-type which allow to include custom
 * pseudo-headers.
 */
final class BinaryHttpHeaders extends DefaultHttpHeaders {

    static BinaryHttpHeaders newHeaders(boolean validate) {
        // For normal headers we need some special validator as we also need to support custom pseudo headers.
        return new BinaryHttpHeaders(validate, BINARY_HTTP_HEADERS_VALIDATOR);
    }

    static BinaryHttpHeaders newTrailers(boolean validate) {
        return new BinaryHttpHeaders(validate, BINARY_HTTP_TRAILERS_VALIDATOR);
    }

    private static final class BinaryHttpNameValidator implements DefaultHeaders.NameValidator<CharSequence> {

        private static final ByteProcessor BINARY_HTTP_NAME_VALIDATOR_PROCESSOR = new ByteProcessor() {
            @Override
            public boolean process(byte value) {
                return !isUpperCase(value);
            }
        };

        private final boolean trailers;

        BinaryHttpNameValidator(boolean trailers) {
            this.trailers = trailers;
        }

        private static int checkUppercase(CharSequence name) {
            if (name instanceof AsciiString) {
                try {
                    return ((AsciiString) name).forEachByte(BINARY_HTTP_NAME_VALIDATOR_PROCESSOR);
                } catch (Exception e) {
                    // Should never happen
                    throw new IllegalArgumentException("invalid header [" + name + ']', e);
                }
            } else {
                for (int i = 0; i < name.length(); ++i) {
                    if (isUpperCase(name.charAt(i))) {
                        return i;
                    }
                }
            }
            return -1;
        }

        @Override
        public void validateName(CharSequence name) {
            if (name != null && name.length() != 0) {
                int index = HttpHeaderValidationUtil.validateToken(name);
                if (index != -1) {
                    // If it's a pseudo-header the : will be on index 0.
                    // Pseudo headers are only allowed in headers but not in trailers.
                    if (trailers || index != 0 || !PseudoHeaderName.isPseudoHeaderPrefix(name.charAt(index))) {
                        throw new IllegalArgumentException("a header name can only contain \"token\" characters, "
                                + "but found invalid character 0x" + Integer.toHexString(name.charAt(index))
                                + " at index " + index + " of header '" + name + "'.");
                    }
                    if (PseudoHeaderName.isPseudoHeader(name)) {
                        throw new IllegalArgumentException("only custom pseudo-headers are allowed: '" + name + "'.");
                    }
                }
                // Check if the name contains uppercase chars as this is not allowed in HTTP2 and so not allowed in
                // Binary HTTP:
                // - https://www.rfc-editor.org/rfc/rfc9292.html#name-header-and-trailer-field-li
                index = checkUppercase(name);
                if (index != -1) {
                    throw new IllegalArgumentException("a header name can only contain \"lowercase\" characters, "
                            + "but found invalid character 0x" + Integer.toHexString(name.charAt(index))
                            + " at index " + index + " of header '" + name + "'.");
                }
            } else {
                throw new IllegalArgumentException("empty headers are not allowed [" + name + ']');
            }
        }
    }
    // See https://lists.w3.org/Archives/Public/ietf-http-wg/2023JulSep/0017.html
    private static final DefaultHeaders.NameValidator<CharSequence> BINARY_HTTP_HEADERS_VALIDATOR =
            new BinaryHttpNameValidator(false);
    private static final DefaultHeaders.NameValidator<CharSequence> BINARY_HTTP_TRAILERS_VALIDATOR =
            new BinaryHttpNameValidator(true);

    private BinaryHttpHeaders(boolean validate, DefaultHeaders.NameValidator<CharSequence> validator) {
        super(validate, validator);
    }
}
