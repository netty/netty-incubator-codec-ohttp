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
package io.netty.incubator.codec.ohttp;

import io.netty.handler.codec.EncoderException;

/**
 * Exception while encoding
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">Oblivious HTTP</a>.
 */
public class OHttpEncoderException extends EncoderException {

    /**
     * Create a new instance
     */
    public OHttpEncoderException() {
    }

    /**
     * Create a new instance.
     *
     * @param message   the message to use.
     * @param cause     the cause to use.
     */
    public OHttpEncoderException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Create a new instance.
     *
     * @param message   the message to use.
     */
    public OHttpEncoderException(String message) {
        super(message);
    }

    /**
     * Create a new instance.
     *
     * @param cause     the cause to use.
     */
    public OHttpEncoderException(Throwable cause) {
        super(cause);
    }
}
