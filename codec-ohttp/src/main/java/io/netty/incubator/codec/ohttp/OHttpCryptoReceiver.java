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

import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.CryptoOperations;
import io.netty.incubator.codec.hpke.HPKE;
import io.netty.incubator.codec.hpke.HPKEContext;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.DecoderException;
import io.netty.incubator.codec.hpke.HybridPublicKeyEncryption;

import java.nio.ByteBuffer;

import static io.netty.incubator.codec.ohttp.OHttpCryptoUtils.aad;
import static io.netty.incubator.codec.ohttp.OHttpCryptoUtils.readableTemporaryBuffer;
import static java.util.Objects.requireNonNull;

/**
 * {@link OHttpCryptoReceiver} handles all the server-side crypto for an OHTTP request/response.
 * It is used internally by {@link OHttpServerContext}.
 */
public final class OHttpCryptoReceiver {
    private final OHttpCryptoConfiguration configuration;
    private final HPKEContext context;
    private final byte[] responseNonce;
    private final CryptoOperations aead;

    public final static class Builder {
        private HybridPublicKeyEncryption encryption;
        private OHttpCryptoConfiguration configuration;
        private OHttpServerKeys serverKeys;
        private OHttpCiphersuite ciphersuite;
        private byte[] encapsulatedKey;
        private byte[] forcedResponseNonce; // for testing only!

        public Builder setHybridPublicKeyEncryption(HybridPublicKeyEncryption encryption) {
            this.encryption = encryption;
            return this;
        }

        public Builder setConfiguration(OHttpCryptoConfiguration configuration) {
            this.configuration = configuration;
            return this;
        }

        public Builder setServerKeys(OHttpServerKeys value) {
            this.serverKeys = value;
            return this;
        }

        public Builder setCiphersuite(OHttpCiphersuite value) {
            this.ciphersuite = value;
            return this;
        }

        public Builder setEncapsulatedKey(byte[] value) {
            this.encapsulatedKey = value;
            return this;
        }

        public Builder setForcedResponseNonce(byte[] value) {
            this.forcedResponseNonce = value;
            return this;
        }

        public OHttpCryptoReceiver build() {
            return new OHttpCryptoReceiver(this);
        }

        private Builder() {
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    private OHttpCryptoReceiver(Builder builder) {
        this.configuration = requireNonNull(builder.configuration, "configuration");
        requireNonNull(builder.serverKeys, "serverKeys");
        requireNonNull(builder.ciphersuite, "ciphersuite");
        requireNonNull(builder.encapsulatedKey, "encapsulatedKey");
        requireNonNull(builder.encryption, "encryption");
        AsymmetricCipherKeyPair keyPair = builder.serverKeys.getKeyPair(builder.ciphersuite);
        if (keyPair == null) {
            throw new DecoderException("ciphersuite not supported");
        }
        byte[] enc = builder.encapsulatedKey;

        HPKE hpke = builder.ciphersuite.newHPKE(builder.encryption);
        this.context = hpke.setupBaseR(enc, keyPair, builder.ciphersuite.createInfo(configuration));
        if (builder.forcedResponseNonce == null) {
            this.responseNonce = builder.ciphersuite.createResponseNonce();
        } else {
            this.responseNonce = builder.forcedResponseNonce;
        }
        this.aead = builder.ciphersuite.createResponseAead(builder.encryption, this.context, enc, this.responseNonce, configuration);
    }

    public byte[] responseNonce() {
        return this.responseNonce.clone();
    }

    public void decrypt(ByteBuf message, int messageLength, boolean isFinal, ByteBuf out) throws CryptoException {
        final ByteBuffer decrypted = this.context.open(
                aad(isFinal && configuration.useFinalAad()),
                readableTemporaryBuffer(message, messageLength));
        message.skipBytes(messageLength);
        out.writeBytes(decrypted);
    }

    public void encrypt(ByteBuf message, int messageLength, boolean isFinal, ByteBuf out) throws CryptoException {
        final ByteBuffer encrypted = this.aead.seal(
                aad(isFinal && configuration.useFinalAad()),
                readableTemporaryBuffer(message, messageLength));
        message.skipBytes(messageLength);
        out.writeBytes(encrypted);
    }
}
