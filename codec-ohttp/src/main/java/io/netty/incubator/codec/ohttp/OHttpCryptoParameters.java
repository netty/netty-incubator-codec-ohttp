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

import io.netty.incubator.codec.hpke.HPKEMode;
import io.netty.util.internal.EmptyArrays;

import static java.util.Objects.requireNonNull;

/**
 * Per-request parameters for the HPKE operations of an OHTTP request / response, in addition to the
 * {@link OHttpCryptoConfiguration} of the used {@link OHttpVersion}.
 */
public final class OHttpCryptoParameters {

    /**
     * {@link OHttpCryptoParameters} that don't change the default behaviour.
     */
    public static final OHttpCryptoParameters DEFAULT = newBuilder().build();

    // Package-private so OHttpCryptoSender / OHttpCryptoReceiver can access these without a copy.
    final byte[] infoSuffix;
    final byte[] requestAad;
    final byte[] psk;
    final byte[] pskId;

    private OHttpCryptoParameters(Builder builder) {
        this.infoSuffix = builder.infoSuffix;
        this.requestAad = builder.requestAad;
        this.psk = builder.psk;
        this.pskId = builder.pskId;
    }

    /**
     * Returns the bytes that are appended to the HPKE {@code info}, after the encoded {@link OHttpCiphersuite}.
     *
     * @return the suffix, empty if nothing is appended.
     */
    public byte[] infoSuffix() {
        return infoSuffix.clone();
    }

    /**
     * Returns the AAD that is used to seal / open the request, or {@code null} if the AAD defined by the
     * {@link OHttpVersion} is used.
     *
     * @return the AAD or {@code null}.
     */
    public byte[] requestAad() {
        return requestAad == null ? null : requestAad.clone();
    }

    /**
     * Returns the pre-shared key, or {@code null} if none is used.
     *
     * @return the pre-shared key or {@code null}.
     */
    public byte[] psk() {
        return psk == null ? null : psk.clone();
    }

    /**
     * Returns the identifier of the pre-shared key, or {@code null} if no pre-shared key is used.
     *
     * @return the identifier or {@code null}.
     */
    public byte[] pskId() {
        return pskId == null ? null : pskId.clone();
    }

    /**
     * Returns the {@link HPKEMode} that is used.
     *
     * @return the mode.
     */
    public HPKEMode mode() {
        return psk == null ? HPKEMode.BASE : HPKEMode.PSK;
    }

    /**
     * Return a new {@link Builder} that can be used to build a {@link OHttpCryptoParameters} instance.
     *
     * @return a builder.
     */
    public static Builder newBuilder() {
        return new Builder();
    }

    public static final class Builder {
        private byte[] infoSuffix = EmptyArrays.EMPTY_BYTES;
        private byte[] requestAad;
        private byte[] psk;
        private byte[] pskId;

        /**
         * Set the bytes that are appended to the HPKE {@code info}, after the encoded {@link OHttpCiphersuite}.
         *
         * @param value the suffix.
         * @return      this builder.
         */
        public Builder setInfoSuffix(byte[] value) {
            this.infoSuffix = requireNonNull(value, "value").clone();
            return this;
        }

        /**
         * Set the AAD that is used to seal / open the request, instead of the AAD defined by the
         * {@link OHttpVersion}. This is only supported by {@link OHttpVersion}s that don't use
         * {@link OHttpCryptoConfiguration#useFinalAad()}.
         *
         * @param value the AAD.
         * @return      this builder.
         */
        public Builder setRequestAad(byte[] value) {
            this.requestAad = requireNonNull(value, "value").clone();
            return this;
        }

        /**
         * Set the pre-shared key and its identifier, which will use {@link HPKEMode#PSK}.
         *
         * @param psk   the pre-shared key, must not be empty.
         * @param pskId the identifier of the pre-shared key, must not be empty.
         * @return      this builder.
         */
        public Builder setPsk(byte[] psk, byte[] pskId) {
            requireNonNull(psk, "psk");
            requireNonNull(pskId, "pskId");
            // See https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-10
            if (psk.length == 0) {
                throw new IllegalArgumentException("psk must not be empty");
            }
            if (pskId.length == 0) {
                throw new IllegalArgumentException("pskId must not be empty");
            }
            this.psk = psk.clone();
            this.pskId = pskId.clone();
            return this;
        }

        public OHttpCryptoParameters build() {
            return new OHttpCryptoParameters(this);
        }

        private Builder() {
        }
    }
}
