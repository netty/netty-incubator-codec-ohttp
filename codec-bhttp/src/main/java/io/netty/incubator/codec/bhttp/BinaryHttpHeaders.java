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

/**
 * {@link DefaultHttpHeaders} sub-type which allow to include custom
 * pseudo-headers.
 */
final class BinaryHttpHeaders extends DefaultHttpHeaders {

    static BinaryHttpHeaders newHeaders(boolean validate) {
        // For normal headers we need some special validator as we also need to support custom pseudo headers.
        return new BinaryHttpHeaders(validate, BINARY_HTTP_VALIDATOR);
    }

    static BinaryHttpHeaders newTrailers(boolean validate) {
        return new BinaryHttpHeaders(validate);
    }

    // See https://lists.w3.org/Archives/Public/ietf-http-wg/2023JulSep/0017.html
    private static final DefaultHeaders.NameValidator<CharSequence> BINARY_HTTP_VALIDATOR =
            new DefaultHeaders.NameValidator<CharSequence>() {
        @Override
        public void validateName(CharSequence name) {
            if (name != null && name.length() != 0) {
                int index = HttpHeaderValidationUtil.validateToken(name);
                if (index != -1) {
                    // If it's a pseudo-header the : will be on index 0.
                    if (index != 0 || !PseudoHeaderName.isPseudoHeaderPrefix(name.charAt(index))) {
                        throw new IllegalArgumentException("a header name can only contain \"token\" characters, "
                                + "but found invalid character 0x" + Integer.toHexString(name.charAt(index))
                                + " at index " + index + " of header '" + name + "'.");
                    } else if (PseudoHeaderName.isPseudoHeader(name)) {
                        throw new IllegalArgumentException("only custom pseudo-headers are allowed: '" + name + "'.");
                    }
                }
            } else {
                throw new IllegalArgumentException("empty headers are not allowed [" + name + ']');
            }
        }
    };

    private BinaryHttpHeaders(boolean validate) {
        // See
        super(validate);
    }

    private BinaryHttpHeaders(boolean validate, DefaultHeaders.NameValidator<CharSequence> validator) {
        // See
        super(validate, validator);
    }
}
