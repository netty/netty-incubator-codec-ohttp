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

import java.nio.ByteBuffer;

/**
 * Cryptographic operations to encrypt and decrypt data.
 */
public interface CryptoOperations {

    /**
     * Authenticate and encrypt data. The {@link ByteBuffer#position()} will be increased by the amount of
     * data read.
     *
     * @param aad   the AAD buffer
     * @param pt    the data to encrypt.
     * @return      the encrypted data.
     * @throws      CryptoException in case of an error.
     */
    ByteBuffer seal(ByteBuffer aad, ByteBuffer pt) throws CryptoException;

    /**
     * Authenticate and decrypt data. The {@link ByteBuffer#position()} will be increased by the amount of
     * data read.
     *
     * @param aad   the AAD buffer
     * @param ct    the data to decrypt
     * @return      the decrypted data.
     * @throws      CryptoException in case of an error.
     */
    ByteBuffer open(ByteBuffer aad, ByteBuffer ct) throws CryptoException;
}
