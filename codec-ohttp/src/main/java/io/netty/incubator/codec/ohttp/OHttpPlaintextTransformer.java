/*
 * Copyright 2026 The Netty Project
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

/**
 * Transforms the plaintext of an OHTTP message, which is the binary HTTP encoding of the encapsulated HTTP message.
 * <p>
 * Both methods are called once per OHTTP chunk, which means exactly once per message for versions that don't use
 * chunking.
 */
public interface OHttpPlaintextTransformer {

    /**
     * Transform a decrypted chunk before it is parsed as binary HTTP.
     *
     * @param alloc     {@link ByteBufAllocator} which might be used to do extra allocations.
     * @param in        the decrypted bytes.
     * @param isFinal   {@code true} if this is the final chunk of the message.
     * @param out       the {@link ByteBuf} into which the bytes that should be parsed as binary HTTP are written.
     */
    void decode(ByteBufAllocator alloc, ByteBuf in, boolean isFinal, ByteBuf out);

    /**
     * Transform a serialized binary HTTP chunk before it is encrypted.
     *
     * @param alloc     {@link ByteBufAllocator} which might be used to do extra allocations.
     * @param in        the serialized binary HTTP bytes.
     * @param isFinal   {@code true} if this is the final chunk of the message.
     * @param out       the {@link ByteBuf} into which the bytes that should be encrypted are written.
     */
    void encode(ByteBufAllocator alloc, ByteBuf in, boolean isFinal, ByteBuf out);
}
