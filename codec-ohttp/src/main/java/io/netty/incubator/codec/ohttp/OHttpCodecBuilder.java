/*
 * Copyright 2026 The Netty Project
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

import io.netty.handler.codec.MessageToMessageCodec;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Builder for configuring and building OHTTP codecs.
 * Use either {@link #forServer()} or {@link #forClient()} for the specific codec.
 */
public abstract class OHttpCodecBuilder<B extends OHttpCodecBuilder<B>> implements Cloneable {
    static final int DEFAULT_MAX_FIELD_SECTION_SIZE = 8 * 1024;

    private OHttpCryptoProvider provider;
    private int maxFieldSectionSize = DEFAULT_MAX_FIELD_SECTION_SIZE;

    /**
     * Package-private constructor, to prevent integrators from extending this class.
     */
    private OHttpCodecBuilder() {
    }

    /**
     * Create a new builder for building {@link OHttpServerCodec} instances.
     * <p>
     * The following settings are mandatory to configure:
     * <ul>
     *     <li>{@link ForServer#setProvider(OHttpCryptoProvider)}</li>
     *     <li>{@link ForServer#setServerKeys(OHttpServerKeys)}</li>
     * </ul>
     * @return a new {@link ForServer} builder instance.
     */
    public static ForServer forServer() {
        return new ForServer();
    }

    /**
     * Create a new builder for building {@link OHttpClientCodec} instances.
     * <p>
     * The following settings are mandatory to configure:
     * <ul>
     *     <li>{@link ForClient#setProvider(OHttpCryptoProvider)}</li>
     *     <li>{@link ForClient#setEncapsulationFunction(Function)}</li>
     * </ul>
     * @return a new {@link ForClient} builder instance.
     */
    public static ForClient forClient() {
        return new ForClient();
    }

    @SuppressWarnings("unchecked")
    protected B self() {
        return (B) this;
    }

    /**
     * The {@link OHttpCryptoProvider} to use for all the crypto.
     * @return the configured provider.
     */
    public final OHttpCryptoProvider getProvider() {
        return provider;
    }

    /**
     * Set the {@link OHttpCryptoProvider} to use for all the crypto.
     * @param provider the {@link OHttpCryptoProvider}, not {@code null}.
     * @return this builder.
     */
    public final B setProvider(OHttpCryptoProvider provider) {
        this.provider = requireNonNull(provider, "provider");
        return self();
    }

    /**
     * The maximum size of the field-section (in bytes).
     * @return The max field section size.
     */
    public final int getMaxFieldSectionSize() {
        return maxFieldSectionSize;
    }

    /**
     * Set the maximum size of the field-section (in bytes).
     * @param maxFieldSectionSize The max field section size, in bytes. Must be positive.
     * @return this builder.
     */
    public final B setMaxFieldSectionSize(int maxFieldSectionSize) {
        if (maxFieldSectionSize < 1) {
            throw new IllegalArgumentException("Max field section size must be positive");
        }
        if (maxFieldSectionSize > (Integer.MAX_VALUE >> 1)) {
            throw new IllegalArgumentException("Max field section size cannot be greater than " +
                    (Integer.MAX_VALUE >> 1));
        }
        this.maxFieldSectionSize = maxFieldSectionSize;
        return self();
    }

    @SuppressWarnings("unchecked")
    @Override
    public B clone() {
        try {
            return (B) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Build the configured codec.
     * @return A new codec instance.
     */
    public abstract MessageToMessageCodec<HttpObject, HttpObject> build();

    /**
     * Configuration for the {@link OHttpServerCodec}.
     * The following settings are mandatory to configure:
     * <ul>
     *     <li>{@link #setProvider(OHttpCryptoProvider)}</li>
     *     <li>{@link #setServerKeys(OHttpServerKeys)}</li>
     * </ul>
     */
    public static final class ForServer extends OHttpCodecBuilder<ForServer> {
        private OHttpServerKeys serverKeys;

        private ForServer() {
        }

        /**
         * The {@link OHttpServerKeys} to use.
         * @return The keys.
         */
        public OHttpServerKeys getServerKeys() {
            return serverKeys;
        }

        /**
         * Set the {@link OHttpServerKeys} to use.
         * @param serverKeys The keys, not {@code null}.
         * @return this builder.
         */
        public ForServer setServerKeys(OHttpServerKeys serverKeys) {
            this.serverKeys = requireNonNull(serverKeys, "serverKeys");
            return self();
        }

        @Override
        public OHttpServerCodec build() {
            return new OHttpServerCodec(this);
        }
    }

    /**
     * Configuration for the {@link OHttpClientCodec}.
     * The following settings are mandatory to configure:
     * <ul>
     *     <li>{@link #setProvider(OHttpCryptoProvider)}</li>
     *     <li>{@link #setEncapsulationFunction(Function)}</li>
     * </ul>
     */
    public static final class ForClient extends OHttpCodecBuilder<ForClient> {
        private Function<HttpRequest, OHttpClientCodec.EncapsulationParameters> encapsulationFunction;

        private ForClient() {
        }

        /**
         * The {@link Function} that will be used to return the correct {@link OHttpClientCodec.EncapsulationParameters}
         * for a given {@link HttpRequest}.
         * If {@link Function} returns {@code null} no encapsulation will take place.
         * @return The function.
         */
        public Function<HttpRequest, OHttpClientCodec.EncapsulationParameters> getEncapsulationFunction() {
            return encapsulationFunction;
        }

        /**
         * Set he {@link Function} that will be used to return the correct
         * {@link OHttpClientCodec.EncapsulationParameters} for a given {@link HttpRequest}.
         * If {@link Function} returns {@code null} no encapsulation will take place.
         * @param encapsulationFunction the encapsulation function.
         * @return this builder.
         */
        public ForClient setEncapsulationFunction(
                Function<HttpRequest, OHttpClientCodec.EncapsulationParameters> encapsulationFunction) {
            this.encapsulationFunction = requireNonNull(encapsulationFunction, "encapsulationFunction");
            return self();
        }

        @Override
        public OHttpClientCodec build() {
            return new OHttpClientCodec(this);
        }
    }
}
