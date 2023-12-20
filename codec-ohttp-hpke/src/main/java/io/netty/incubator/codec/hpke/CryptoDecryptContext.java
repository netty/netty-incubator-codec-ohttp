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
package io.netty.incubator.codec.hpke;

import io.netty.buffer.ByteBuf;

/**
 * {@link CryptoContext} that can be used for decryption.
 */
public interface CryptoDecryptContext extends CryptoContext {

    /**
     * Authenticate and decrypt data. The {@link ByteBuf#readerIndex()} will be increased by the amount of
     * data read and {@link ByteBuf#writerIndex()} by the bytes written.
     *
     * @param aad   the AAD buffer
     * @param ct    the data to decrypt
     * @param out   the buffer for writing into.
     * @throws      CryptoException in case of an error.
     */
    void open(ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException;
}
