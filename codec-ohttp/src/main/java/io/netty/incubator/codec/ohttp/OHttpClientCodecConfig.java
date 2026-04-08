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

import io.netty.handler.codec.http.HttpRequest;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;

import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Configuration for the {@link OHttpClientCodec}.
 * The following settings are mandatory to configure:
 * <ul>
 *     <li>{@link #setProvider(OHttpCryptoProvider)}</li>
 *     <li>{@link #setEncapsulationFunction(Function)}</li>
 * </ul>
 */
public final class OHttpClientCodecConfig extends OHttpCodecConfig {
    private Function<HttpRequest, OHttpClientCodec.EncapsulationParameters> encapsulationFunction;

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
     * Set he {@link Function} that will be used to return the correct {@link OHttpClientCodec.EncapsulationParameters}
     * for a given {@link HttpRequest}.
     * If {@link Function} returns {@code null} no encapsulation will take place.
     */
    public void setEncapsulationFunction(
            Function<HttpRequest, OHttpClientCodec.EncapsulationParameters> encapsulationFunction) {
        this.encapsulationFunction = requireNonNull(encapsulationFunction, "encapsulationFunction");
    }

    @Override
    public OHttpClientCodecConfig clone() {
        return (OHttpClientCodecConfig) super.clone();
    }
}
