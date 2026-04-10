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

import io.netty.channel.ChannelHandler;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import static java.util.Objects.requireNonNull;

/**
 * Builder for configuring and building OHTTP codecs.
 * Use either {@link OHttpServerCodecBuilder} or {@link OHttpClientCodecBuilder} for the specific codec.
 */
public abstract class OHttpCodecBuilder<B extends OHttpCodecBuilder<B>> implements Cloneable {
    static final int DEFAULT_MAX_FIELD_SECTION_SIZE = 8 * 1024;

    private OHttpCryptoProvider provider;
    private int maxFieldSectionSize = DEFAULT_MAX_FIELD_SECTION_SIZE;

    /**
     * Package-private constructor, to prevent integrators from extending this class.
     */
    OHttpCodecBuilder() {
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
    public abstract ChannelHandler build();
}
