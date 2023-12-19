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
import io.netty.incubator.codec.hpke.CryptoContext;
import io.netty.incubator.codec.hpke.HPKEContext;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.DecoderException;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import static java.util.Objects.requireNonNull;

/**
 * {@link OHttpCryptoReceiver} handles all the server-side crypto for an OHTTP request/response.
 */
public final class OHttpCryptoReceiver extends OHttpCrypto {
    private final OHttpCryptoConfiguration configuration;
    private final HPKEContext context;
    private final byte[] responseNonce;
    private final CryptoContext aead;

    public final static class Builder {
        private OHttpCryptoProvider provider;
        private OHttpCryptoConfiguration configuration;
        private OHttpServerKeys serverKeys;
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
        OHttpServerKeys serverKeys = requireNonNull(builder.serverKeys, "serverKeys");
        OHttpCiphersuite ciphersuite = requireNonNull(builder.ciphersuite, "ciphersuite");
        byte[] encapsulatedKey = requireNonNull(builder.encapsulatedKey, "encapsulatedKey");
        OHttpCryptoProvider provider = requireNonNull(builder.provider, "provider");
        AsymmetricCipherKeyPair keyPair = serverKeys.getKeyPair(ciphersuite);
        if (keyPair == null) {
            throw new DecoderException("ciphersuite not supported");
        }
        this.context = provider.setupHPKEBaseR(OHttpCryptoProvider.Mode.Base, ciphersuite.kem(), ciphersuite.kdf(),
                ciphersuite.aead(), encapsulatedKey, keyPair, ciphersuite.createInfo(configuration));
        if (builder.forcedResponseNonce == null) {
            this.responseNonce = builder.ciphersuite.createResponseNonce();
        } else {
            this.responseNonce = builder.forcedResponseNonce;
        }
        this.aead = builder.ciphersuite.createResponseAead(provider, this.context, encapsulatedKey,
                this.responseNonce, configuration);
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
    protected CryptoContext encryptCrypto() {
        return this.aead;
    }

    @Override
    protected CryptoContext decryptCrypto() {
        return this.context;
    }

    @Override
    protected OHttpCryptoConfiguration configuration() {
        return configuration;
    }
}
