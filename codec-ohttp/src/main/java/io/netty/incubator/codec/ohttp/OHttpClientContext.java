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
 * Context for a OHTTP client.
 */
public final class OHttpClientContext {

    private final OHttpVersion version;
    private final OHttpCryptoSender sender;

    /**
     * @return {@link OHttpVersion}.
     */
    OHttpVersion version() {
        return version;
    }

    /**
     * Create {@link OHttpContentParser} for the {@link OHttpClientContext}.
     * @return {@link OHttpContentParser}.
     */
    OHttpContentParser newContentParser() {
        return new OHttpContentParser(version) {

            @Override
            public boolean decodePrefix(ByteBuf in) {
                if (in.readableBytes() < sender.ciphersuite().responseNonceLength()) {
                    return false;
                }
                byte[] responseNonce = new byte[sender.ciphersuite().responseNonceLength()];
                in.readBytes(responseNonce);
                sender.setResponseNonce(responseNonce);
                return true;
            }

            @Override
            protected void decryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out)
                    throws CryptoException {
                sender.decrypt(chunk, chunkLength, isFinal, out);
            }
        };
    }

    /**
     * Create {@link OHttpContentSerializer} for the {@link OHttpClientContext}.
     * @return {@link OHttpContentSerializer}.
     */
    OHttpContentSerializer newContentSerializer() {
        return new OHttpContentSerializer(version) {

            @Override
            public void encodePrefixNow(ByteBuf out) {
                out.writeBytes(sender.header());
            }

            @Override
            protected void encryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out)
                    throws CryptoException {
                sender.encrypt(chunk, chunkLength, isFinal, out);
            }
        };
    }

    public OHttpClientContext(OHttpVersion version, OHttpCiphersuite ciphersuite, byte[] serverPublickKeyBytes,
                              HybridPublicKeyEncryption encryption) {
        this.version = requireNonNull(version,"version");
        this.sender = OHttpCryptoSender.newBuilder()
                .setHybridPublicKeyEncryption(encryption)
                .setConfiguration(version)
                .setCiphersuite(requireNonNull(ciphersuite, "ciphersuite"))
                .setReceiverPublicKeyBytes(requireNonNull(serverPublickKeyBytes, "serverPublicKeyBytes"))
                .build();
    }
}
