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
package io.netty.incubator.codec.hpke.boringssl;

import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;

import java.util.Arrays;

final class BoringSSLAsymmetricKeyParameter implements AsymmetricKeyParameter {
    // Package-private so we can access it without doing a clone().
    final byte[] bytes;
    private final boolean isPrivate;

    BoringSSLAsymmetricKeyParameter(byte[] bytes, boolean isPrivate) {
        this.bytes = bytes;
        this.isPrivate = isPrivate;
    }

    @Override
    public byte[] encoded() {
        return bytes.clone();
    }

    @Override
    public boolean isPrivate() {
        return isPrivate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)  {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        BoringSSLAsymmetricKeyParameter that = (BoringSSLAsymmetricKeyParameter) o;
        if (isPrivate != that.isPrivate) {
            return false;
        }
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(bytes);
        result = 31 * result + (isPrivate ? 1 : 0);
        return result;
    }
}
