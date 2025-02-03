/*
 * Copyright 2025 The Netty Project
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
package io.netty.incubator.codec.hpke;

import java.util.Arrays;
import java.util.Objects;

public final class AEADParameters {

    private final AEAD aead;
    private final byte[] aeadKey;
    private final byte[] aeadNounce;

    public AEADParameters(AEAD aead, byte[] aeadKey, byte[] aeadNounce) {
        this.aead = Objects.requireNonNull(aead, "aead");
        this.aeadKey = Objects.requireNonNull(aeadKey, "aeadKey");
        this.aeadNounce = Objects.requireNonNull(aeadNounce, "aeadNounce");
    }

    /**
     * Returns the {@link AEAD}
     * @return the aead.
     */
    public AEAD aead() {
        return aead;
    }

    /**
     * Returns the aead key.
     * @return the key
     */
    public byte[] aeadKey() {
        return aeadKey.clone();
    }

    /**
     * Returns the aead nounce.
     * @return nounce.
     */
    public byte[] aeadNounce() {
        return aeadNounce.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AEADParameters that = (AEADParameters) o;
        return aead == that.aead && Objects.deepEquals(aeadKey, that.aeadKey)
                && Objects.deepEquals(aeadNounce, that.aeadNounce);
    }

    @Override
    public int hashCode() {
        return Objects.hash(aead, Arrays.hashCode(aeadKey), Arrays.hashCode(aeadNounce));
    }
}
