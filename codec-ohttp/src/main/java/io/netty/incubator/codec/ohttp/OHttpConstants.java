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
package io.netty.incubator.codec.ohttp;

import io.netty.util.AsciiString;

public final class OHttpConstants {

    public static final int MAX_CHUNK_SIZE = 1024 * 1024;

    /**
     * <a href="https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#name-message-ohttp-req-media-typ">
     *     message/ohttp-req</a>
     */
    public static final AsciiString REQUEST_CONTENT_TYPE = AsciiString.cached("message/ohttp-req");

    /**
     * <a href="https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#name-message-ohttp-res-media-typ">
     *     message/ohttp-res</a>
     */
    public static final AsciiString RESPONSE_CONTENT_TYPE = AsciiString.cached("message/ohttp-res");

    /**
     * <a href="https://www.ietf.org/archive/id/draft-ohai-chunked-ohttp-00.html#name-message-ohttp-chunked-req-m">
     *     message/ohttp-chunked-req</a>
     */
    public static final AsciiString CHUNKED_REQUEST_CONTENT_TYPE = AsciiString.cached("message/ohttp-chunked-req");

    /**
     * <a href="https://www.ietf.org/archive/id/draft-ohai-chunked-ohttp-00.html#name-message-ohttp-chunked-res-m">
     *     message/ohttp-chunked-res</a>
     */
    public static final AsciiString CHUNKED_RESPONSE_CONTENT_TYPE = AsciiString.cached("message/ohttp-chunked-res");

    /**
     * <a href="https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#name-application-ohttp-keys-medi">
     *     application/ohttp-keys</a>
     */
    public static final AsciiString KEYS_CONTENT_TYPE = AsciiString.cached("application/ohttp-keys");

    private OHttpConstants() { }
}
