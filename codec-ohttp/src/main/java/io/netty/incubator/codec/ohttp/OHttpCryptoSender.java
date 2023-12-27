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
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.CryptoDecryptContext;
import io.netty.incubator.codec.hpke.CryptoEncryptContext;
import io.netty.buffer.ByteBuf;
import io.netty.incubator.codec.hpke.HPKEMode;
import io.netty.incubator.codec.hpke.HPKESenderContext;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import static java.util.Objects.requireNonNull;

/**
 * {@link OHttpCryptoSender} handles all the client-side crypto for an OHTTP request/response.
 */

public final class OHttpCryptoSender extends OHttpCrypto {
    private final OHttpCryptoConfiguration configuration;
    private final OHttpCiphersuite ciphersuite;
    private final OHttpCryptoProvider provider;
    private final HPKESenderContext context;
    private CryptoDecryptContext aead;

    public static final class Builder {
        private OHttpCryptoProvider provider;
        private OHttpCryptoConfiguration configuration;
        private OHttpCiphersuite ciphersuite;
        private AsymmetricKeyParameter receiverPublicKey;
        private AsymmetricCipherKeyPair forcedEphemeralKeyPair; // for testing only!

        public Builder setOHttpCryptoProvider(OHttpCryptoProvider provider) {
            this.provider = provider;
            return this;
        }

        public Builder setConfiguration(OHttpCryptoConfiguration configuration) {
            this.configuration = configuration;
            return this;
        }

        public Builder setCiphersuite(OHttpCiphersuite value) {
            this.ciphersuite = value;
            return this;
        }

        public Builder setReceiverPublicKey(AsymmetricKeyParameter value) {
            this.receiverPublicKey = value;
            return this;
        }

        Builder setForcedEphemeralKeyPair(AsymmetricCipherKeyPair value) {
            this.forcedEphemeralKeyPair = value;
            return this;
        }

        public OHttpCryptoSender build() {
            return new OHttpCryptoSender(this);
        }

        private Builder() {
        }
    }

    /**
     * Return a new {@link Builder} that can be used to build a {@link OHttpCryptoSender} instance.
     *
     * @return a builder.
     */
    public static Builder newBuilder() {
        return new Builder();
    }

    private OHttpCryptoSender(Builder builder) {
        this.configuration = requireNonNull(builder.configuration, "configuration");
        this.ciphersuite = requireNonNull(builder.ciphersuite, "ciphersuite");
        this.provider = requireNonNull(builder.provider, "provider");

        AsymmetricKeyParameter pkR = requireNonNull(builder.receiverPublicKey, "receiverPublicKey");
        AsymmetricCipherKeyPair forcedEphemeralKeyPair = builder.forcedEphemeralKeyPair;
        this.context = this.provider.setupHPKEBaseS(HPKEMode.Base, ciphersuite.kem(),
                ciphersuite.kdf(), ciphersuite.aead(), pkR, ciphersuite.createInfo(configuration.requestExportContext()),
                forcedEphemeralKeyPair);
    }

    /**
     * Returns the used {@link OHttpCiphersuite}.
     *
     * @return used ciphersuite.
     */
    public OHttpCiphersuite ciphersuite() {
        return this.ciphersuite;
    }

    /**
     * Write the header into the given {@link ByteBuf}.
     *
     * @param out   the buffer into which the writes are done.
     */
    public void writeHeader(ByteBuf out) {
        this.ciphersuite.encode(out);
        out.writeBytes(this.context.encapsulation());
    }

    /**
     * Read the response nonce if possible and return {@code true}. If not enough bytes
     * are readable it will return {@code false}.
     *
     * @param in    the buffer from which we read.
     * @return      {@code true} if there were enough bytes to read the nounce, {@code false} otherwise.
     */
    public boolean readResponseNonce(ByteBuf in) {
        if (in.readableBytes() < ciphersuite().responseNonceLength()) {
            return false;
        }
        byte[] responseNonce = new byte[ciphersuite().responseNonceLength()];
        in.readBytes(responseNonce);
        this.aead = ciphersuite.createResponseAEAD(
                provider, context, context.encapsulation(), responseNonce, configuration.responseExportContext());
        return true;
    }

    @Override
    protected CryptoEncryptContext encryptCrypto() {
        return context;
    }

    @Override
    protected CryptoDecryptContext decryptCrypto() {
        return aead;
    }

    @Override
    protected boolean useFinalAad() {
        return configuration.useFinalAad();
    }
}
