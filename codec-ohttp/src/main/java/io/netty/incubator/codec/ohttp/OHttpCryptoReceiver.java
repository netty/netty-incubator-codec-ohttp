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
import io.netty.incubator.codec.hpke.CryptoDecryptContext;
import io.netty.incubator.codec.hpke.CryptoEncryptContext;
import io.netty.buffer.ByteBuf;
import io.netty.incubator.codec.hpke.HPKEMode;
import io.netty.incubator.codec.hpke.HPKERecipientContext;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import static java.util.Objects.requireNonNull;

/**
 * {@link OHttpCryptoReceiver} handles all the server-side crypto for an OHTTP request/response.
 */
public final class OHttpCryptoReceiver extends OHttpCrypto {
    private final OHttpCryptoConfiguration configuration;
    private final HPKERecipientContext context;
    private final byte[] responseNonce;
    private final CryptoEncryptContext aead;

    public final static class Builder {
        private OHttpCryptoProvider provider;
        private OHttpCryptoConfiguration configuration;
        private AsymmetricCipherKeyPair privateKey;
        private OHttpCiphersuite ciphersuite;
        private byte[] encapsulatedKey;
        private byte[] forcedResponseNonce; // for testing only!

        public Builder setOHttpCryptoProvider(OHttpCryptoProvider provider) {
            this.provider = provider;
            return this;
        }

        public Builder setConfiguration(OHttpCryptoConfiguration configuration) {
            this.configuration = configuration;
            return this;
        }

        public Builder setSenderPrivateKey(AsymmetricCipherKeyPair privateKey) {
            this.privateKey = privateKey;
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


    /**
     * Return a new {@link Builder} that can be used to build a {@link OHttpCryptoReceiver} instance.
     *
     * @return a builder.
     */
    public static Builder newBuilder() {
        return new Builder();
    }

    private OHttpCryptoReceiver(Builder builder) {
        this.configuration = requireNonNull(builder.configuration, "configuration");
        OHttpCiphersuite ciphersuite = requireNonNull(builder.ciphersuite, "ciphersuite");
        byte[] encapsulatedKey = requireNonNull(builder.encapsulatedKey, "encapsulatedKey");
        OHttpCryptoProvider provider = requireNonNull(builder.provider, "provider");
        AsymmetricCipherKeyPair keyPair = requireNonNull(builder.privateKey, "privateKey");
        if (builder.forcedResponseNonce == null) {
            this.responseNonce = ciphersuite.createResponseNonce();
        } else {
            this.responseNonce = builder.forcedResponseNonce;
        }
        this.context = provider.setupHPKEBaseR(HPKEMode.Base, ciphersuite.kem(), ciphersuite.kdf(),
                ciphersuite.aead(), encapsulatedKey, keyPair, ciphersuite.createInfo(configuration.requestExportContext()));
        try {
            this.aead = ciphersuite.createResponseAEAD(provider, context, encapsulatedKey,
                    this.responseNonce, configuration.responseExportContext());
        } catch (Throwable cause) {
            // Close context before rethrowing as otherwise we might leak resources.
            context.close();
            throw cause;
        }
    }

    /**
     * Write the response nonce to the given {@link ByteBuf}.
     *
     * @param out the buffer into which the nonce will be written.
     */
    public void writeResponseNonce(ByteBuf out) {
        out.writeBytes(responseNonce);
    }

    @Override
    protected CryptoEncryptContext encryptCrypto() {
        return this.aead;
    }

    @Override
    protected CryptoDecryptContext decryptCrypto() {
        return this.context;
    }

    @Override
    protected OHttpCryptoConfiguration configuration() {
        return configuration;
    }
}
