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
import io.netty.util.internal.ObjectUtil;

import static java.util.Objects.requireNonNull;

/**
 * Builder for the {@link OHttpServerCodec}.
 * The following settings are mandatory to configure:
 * <ul>
 *     <li>{@link #setProvider(OHttpCryptoProvider)}</li>
 *     <li>{@link #setServerKeys(OHttpServerKeys)}</li>
 * </ul>
 */
public final class OHttpServerCodecBuilder extends OHttpCodecBuilder<OHttpServerCodecBuilder> {
    private OHttpServerKeys serverKeys;

    private int maxBufferLength = OHttpConstants.MAX_BUFFER_LENGTH;

    /**
     * Create a new builder for building {@link OHttpServerCodec} instances.
     * <p>
     * The following settings are mandatory to configure:
     * <ul>
     *     <li>{@link OHttpServerCodecBuilder#setProvider(OHttpCryptoProvider)}</li>
     *     <li>{@link OHttpServerCodecBuilder#setServerKeys(OHttpServerKeys)}</li>
     * </ul>
     */
    public OHttpServerCodecBuilder() {
    }

    /**
     * The {@link OHttpServerKeys} to use.
     *
     * @return The keys.
     */
    public OHttpServerKeys getServerKeys() {
        return serverKeys;
    }

    /**
     * Set the {@link OHttpServerKeys} to use.
     *
     * @param serverKeys The keys, not {@code null}.
     * @return this builder.
     */
    public OHttpServerCodecBuilder setServerKeys(OHttpServerKeys serverKeys) {
        this.serverKeys = requireNonNull(serverKeys, "serverKeys");
        return self();
    }

    /**
     * Set the maximum number of bytes that are allowed to be buffered for an OHTTP request.
     *
     * @param maxBufferLength the maximum number of bytes that will be allowed to buffer for an OHTTP request.
     * @return this builder.
     */
    public OHttpServerCodecBuilder setMaxBufferLength(int maxBufferLength) {
        this.maxBufferLength = ObjectUtil.checkPositive(maxBufferLength, "maxBufferLength");
        return self();
    }

    /**
     * The maximum number of bytes that are allowed to be buffered for an OHTTP request.
     *
     * @return The length.
     */
    public int maxBufferLength() {
        return maxBufferLength;
    }

    @Override
    public ChannelHandler build() {
        return new OHttpServerCodec(this);
    }
}
