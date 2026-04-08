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

import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import static java.util.Objects.requireNonNull;

/**
 * Configuration for the {@link OHttpServerCodec}.
 * The following settings are mandatory to configure:
 * <ul>
 *     <li>{@link #setProvider(OHttpCryptoProvider)}</li>
 *     <li>{@link #setServerKeys(OHttpServerKeys)}</li>
 * </ul>
 */
public final class OHttpServerCodecConfig extends OHttpCodecConfig {
    private OHttpServerKeys serverKeys;

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
     */
    public void setServerKeys(OHttpServerKeys serverKeys) {
        this.serverKeys = requireNonNull(serverKeys, "serverKeys");
    }

    @Override
    public OHttpServerCodecConfig clone() {
        return (OHttpServerCodecConfig) super.clone();
    }
}
