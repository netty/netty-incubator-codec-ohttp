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
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.CryptoOperations;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Abstract base class for doing OHTTP related crypto operations.
 */
public abstract class OHttpCrypto {

    private static final byte[] AAD_NONE = new byte[0];
    private static final byte[] AAD_FINAL = "final".getBytes(StandardCharsets.US_ASCII);

    // Package-private
    OHttpCrypto() { }

    private static ByteBuffer aad(boolean isFinal) {
        // The caller might update the position of the ByteBuffer, so we create a new one each time.
        return ByteBuffer.wrap(isFinal ? AAD_FINAL : AAD_NONE);
    }

    /**
     * Return readable part of the given {@link ByteBuf}.
     * This method might need to do a copy or not depending on the given {@link ByteBuf}.
     * <p>
     * <strong>Important:</strong> The returned {@link ByteBuffer} must be used directly and only in the scope
     * of the method that is calling it. This is needed as the returned {@link ByteBuffer} is not "stable", which means
     * it might be changed at any time.
     *
     * @param buf       the {@link ByteBuf}
     * @param length    the length of the readable part.
     * @return          the {@link ByteBuffer} that contains the readable part.
     */
    private static ByteBuffer readableTemporaryBuffer(ByteBuf buf, int length) {
        if (buf.nioBufferCount() == 1) {
            return buf.internalNioBuffer(buf.readerIndex(), length);
        }
        return buf.nioBuffer(buf.readerIndex(),  length);
    }

    protected abstract CryptoOperations encryptCrypto();

    protected abstract CryptoOperations decryptCrypto();

    protected abstract OHttpCryptoConfiguration configuration();

    /**
     * Encrypt a message of a given length and write the encrypted data to a buffer.
     *
     * @param message           the message
     * @param messageLength     the length to encrypt
     * @param isFinal           {@code true} if this is the final message.
     * @param out               {@link ByteBuf} into which the encrypted data is written.
     * @throws CryptoException  thrown when an error happens.
     */
    public final void encrypt(ByteBuf message, int messageLength, boolean isFinal, ByteBuf out) throws CryptoException {
        final ByteBuffer encrypted = encryptCrypto().seal(
                aad(isFinal && configuration().useFinalAad()),
                readableTemporaryBuffer(message, messageLength));
        message.skipBytes(messageLength);
        out.writeBytes(encrypted);
    }

    /**
     * Decrypt a message of a given length and write the decrypted data to a buffer.
     *
     * @param message           the message
     * @param messageLength     the length to decrypt
     * @param isFinal           {@code true} if this is the final message.
     * @param out               {@link ByteBuf} into which the decrypted data is written.
     * @throws CryptoException  thrown when an error happens.
     */
    public final void decrypt(ByteBuf message, int messageLength, boolean isFinal, ByteBuf out) throws CryptoException {
        final ByteBuffer decrypted = decryptCrypto().open(
                aad(isFinal && configuration().useFinalAad()),
                readableTemporaryBuffer(message, messageLength));
        message.skipBytes(messageLength);
        out.writeBytes(decrypted);
    }
}
