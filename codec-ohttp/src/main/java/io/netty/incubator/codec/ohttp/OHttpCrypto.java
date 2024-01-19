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
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.CryptoDecryptContext;
import io.netty.incubator.codec.hpke.CryptoEncryptContext;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKEContext;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import java.nio.charset.StandardCharsets;

/**
 * Abstract base class for doing OHTTP related crypto operations.
 */
public abstract class OHttpCrypto implements AutoCloseable {

    private static final ByteBuf EMPTY_HEAP = Unpooled.unreleasableBuffer(
            Unpooled.wrappedBuffer(new byte[0]).asReadOnly());
    private static final ByteBuf EMPTY_DIRECT = Unpooled.unreleasableBuffer(
            Unpooled.directBuffer().asReadOnly());
    private static final ByteBuf AAD_FINAL_HEAP = Unpooled.unreleasableBuffer(
            Unpooled.wrappedBuffer("final".getBytes(StandardCharsets.US_ASCII)).asReadOnly());
    private static final ByteBuf AAD_FINAL_DIRECT = Unpooled.unreleasableBuffer(
            Unpooled.directBuffer(5).writeBytes("final".getBytes(StandardCharsets.US_ASCII)).asReadOnly());

    // Package-private
    OHttpCrypto() { }

    private static ByteBuf aad(boolean isFinal, boolean preferDirect) {
        // The caller might update the position of the ByteBuf, duplicate it.
        if (isFinal) {
            return preferDirect ? AAD_FINAL_DIRECT.duplicate() : AAD_FINAL_HEAP.duplicate();
        }
        return preferDirect ? EMPTY_DIRECT.duplicate() : EMPTY_HEAP.duplicate();
    }

    private static final byte[] KEY_INFO  = "key".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NONCE_INFO  = "nonce".getBytes(StandardCharsets.US_ASCII);

    /*
     * See https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html#name-encapsulation-of-responses
     */
    static AEADContext createResponseAEAD(OHttpCryptoProvider provider, HPKEContext context, AEAD aead, byte[] enc,
                                   byte[] responseNonce, byte[] responseExportContext) {
        int secretLength = Math.max(aead.nk(), aead.nn());
        byte[] secret = context.export(responseExportContext, secretLength);
        byte[] salt = new byte[enc.length + responseNonce.length];
        System.arraycopy(enc, 0, salt, 0, enc.length);
        System.arraycopy(responseNonce, 0, salt, enc.length, responseNonce.length);
        byte[] prk = context.extract(salt, secret);
        byte[] aeadKey = context.expand(prk, KEY_INFO, aead.nk());
        byte[] aeadNonce = context.expand(prk, NONCE_INFO, aead.nn());
        return provider.setupAEAD(aead, aeadKey, aeadNonce);
    }

    /*
     * See https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html#section-4.3
     */
    static byte[] createInfo(OHttpCiphersuite ciphersuite, byte[] requestExportContext) {
        byte[] ret = new byte[requestExportContext.length + 1 + OHttpCiphersuite.ENCODED_LENGTH];
        ByteBuf buf = Unpooled.wrappedBuffer(ret);
        try {
            buf.writerIndex(0)
                    .writeBytes(requestExportContext)
                    .writeByte(0);
            ciphersuite.encode(buf);
            return ret;
        } finally {
            buf.release();
        }
    }

    protected abstract CryptoEncryptContext encryptCrypto();

    protected abstract CryptoDecryptContext decryptCrypto();

    protected abstract boolean useFinalAad();

    /**
     * Encrypt a message of a given length and write the encrypted data to a buffer.
     *
     * @param alloc             {@link ByteBufAllocator} which might be used to do extra allocations.
     * @param message           the message
     * @param messageLength     the length of the message
     * @param isFinal           {@code true} if this is the final message.
     * @param out               {@link ByteBuf} into which the encrypted data is written.
     * @throws CryptoException  thrown when an error happens.
     */
    public final void encrypt(ByteBufAllocator alloc, ByteBuf message, int messageLength, boolean isFinal, ByteBuf out)
            throws CryptoException {
        encryptCrypto().seal(alloc, aad(isFinal && useFinalAad(), encryptCrypto().isDirectBufferPreferred()),
                message.slice(message.readerIndex(), messageLength), out);
        message.skipBytes(messageLength);
    }

    /**
     * Decrypt a message of a given length and write the decrypted data to a buffer.
     *
     * @param alloc             {@link ByteBufAllocator} which might be used to do extra allocations.
     * @param message           the message
     * @param messageLength     the length of the message
     * @param isFinal           {@code true} if this is the final message.
     * @param out               {@link ByteBuf} into which the decrypted data is written.
     * @throws CryptoException  thrown when an error happens.
     */
    public final void decrypt(ByteBufAllocator alloc, ByteBuf message, int messageLength, boolean isFinal, ByteBuf out)
            throws CryptoException {
        decryptCrypto().open(alloc, aad(isFinal && useFinalAad(), decryptCrypto().isDirectBufferPreferred()),
                message.slice(message.readerIndex(), messageLength), out);
        message.skipBytes(messageLength);
    }

    @Override
    public void close()  {
        // Check for null as these could be null if the constructor did throw.
        CryptoEncryptContext encryptContext = encryptCrypto();
        if (encryptContext != null) {
            encryptContext.close();
        }
        CryptoDecryptContext decryptContext = decryptCrypto();
        if (decryptContext != null) {
            decryptContext.close();
        }
    }
}
