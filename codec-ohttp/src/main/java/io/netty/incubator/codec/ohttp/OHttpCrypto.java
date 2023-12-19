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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.CryptoContext;

import java.nio.charset.StandardCharsets;

/**
 * Abstract base class for doing OHTTP related crypto operations.
 */
public abstract class OHttpCrypto {

    private static final byte[] AAD_FINAL = "final".getBytes(StandardCharsets.US_ASCII);

    // Package-private
    OHttpCrypto() { }

    private static ByteBuf aad(boolean isFinal) {
        // The caller might update the position of the ByteBuffer, so we create a new one each time.
        return isFinal ? Unpooled.wrappedBuffer(AAD_FINAL) : Unpooled.EMPTY_BUFFER;
    }

    protected abstract CryptoContext encryptCrypto();

    protected abstract CryptoContext decryptCrypto();

    protected abstract OHttpCryptoConfiguration configuration();

    /**
     * Encrypt a message of a given length and write the encrypted data to a buffer.
     *
     * @param message           the message
     * @param messageLength     the length of the message
     * @param isFinal           {@code true} if this is the final message.
     * @param out               {@link ByteBuf} into which the encrypted data is written.
     * @throws CryptoException  thrown when an error happens.
     */
    public final void encrypt(ByteBuf message, int messageLength, boolean isFinal, ByteBuf out) throws CryptoException {
        encryptCrypto().seal(aad(isFinal && configuration().useFinalAad()),
                message.slice(message.readerIndex(), messageLength), out);
        message.skipBytes(messageLength);
    }

    /**
     * Decrypt a message of a given length and write the decrypted data to a buffer.
     *
     * @param message           the message
     * @param messageLength     the length of the message
     * @param isFinal           {@code true} if this is the final message.
     * @param out               {@link ByteBuf} into which the decrypted data is written.
     * @throws CryptoException  thrown when an error happens.
     */
    public final void decrypt(ByteBuf message, int messageLength, boolean isFinal, ByteBuf out) throws CryptoException {
        decryptCrypto().open(
                aad(isFinal && configuration().useFinalAad()),
                message.slice(message.readerIndex(), messageLength), out);
        message.skipBytes(messageLength);
    }
}
