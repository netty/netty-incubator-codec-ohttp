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

import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.incubator.codec.hpke.HybridPublicKeyEncryption;

import static java.util.Objects.requireNonNull;

/**
 * Context for a OHTTP server.
 */
public final class OHttpServerContext {

    private final OHttpServerKeys serverKeys;
    private final OHttpVersion version;
    private final HybridPublicKeyEncryption encryption;
    private OHttpCryptoReceiver receiver;

    /**
     * @return {@link OHttpVersion}.
     */
    OHttpVersion version() {
        return version;
    }

    private void checkPrefixDecoded()throws CryptoException {
        if (receiver == null) {
            throw new CryptoException("Prefix was not decoded yet");
        }
    }

    /**
     * Create {@link OHttpContentParser} for the {@link OHttpServerContext}.
     * @return {@link OHttpContentParser}.
     */
    OHttpContentParser newContentParser() {
        return new OHttpContentParser(version) {

            @Override
            public boolean decodePrefix(ByteBuf in) {
                final int initialReaderIndex = in.readerIndex();
                final OHttpCiphersuite ciphersuite = OHttpCiphersuite.decode(in);
                if (ciphersuite == null) {
                    return false;
                }
                final int encapsulatedKeyLength = ciphersuite.encapsulatedKeyLength();
                if (in.readableBytes() < encapsulatedKeyLength) {
                    in.readerIndex(initialReaderIndex);
                    return false;
                }
                final byte[] encapsulatedKey = new byte[encapsulatedKeyLength];
                in.readBytes(encapsulatedKey);
                receiver = OHttpCryptoReceiver.newBuilder()
                        .setHybridPublicKeyEncryption(encryption)
                        .setConfiguration(version)
                        .setServerKeys(serverKeys)
                        .setCiphersuite(ciphersuite)
                        .setEncapsulatedKey(encapsulatedKey)
                        .build();
                return true;
            }

            @Override
            protected void decryptChunk(ByteBuf chunk, int chunkSize, boolean isFinal, ByteBuf out)
                    throws CryptoException {
                checkPrefixDecoded();
                receiver.decrypt(chunk, chunkSize, isFinal, out);
            }
        };
    }

    /**
     * Create {@link OHttpContentSerializer} for the {@link OHttpServerContext}.
     * @return {@link OHttpContentSerializer}.
     */
    OHttpContentSerializer newContentSerializer() {
        return new OHttpContentSerializer(version) {

            @Override
            public void encodePrefixNow(ByteBuf out) throws CryptoException {
                checkPrefixDecoded();
                out.writeBytes(receiver.responseNonce());
            }

            @Override
            protected void encryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out)
                    throws CryptoException {
                checkPrefixDecoded();
                receiver.encrypt(chunk, chunkLength, isFinal, out);
            }
        };
    }

    /**
     * @param serverKeys set of key private keys and supported crypto algorithms.
     * @param version {@link OHttpVersion}.
     */
    public OHttpServerContext(OHttpServerKeys serverKeys, OHttpVersion version, HybridPublicKeyEncryption encryption) {
        this.serverKeys = requireNonNull(serverKeys, "serverKeys");
        this.version = requireNonNull(version,"version");
        this.encryption = requireNonNull(encryption, "encryption");
    }
}
