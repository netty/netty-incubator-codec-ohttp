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

import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;

// TODO: Maybe expose sub-type which is ReferenceCounted and so allows to take ownership of EVP_HPKE_KEY.
final class BoringSSLAsymmetricCipherKeyPair implements AsymmetricCipherKeyPair {
    private final BoringSSLAsymmetricKeyParameter privateKey;
    private final BoringSSLAsymmetricKeyParameter publicKey;

    BoringSSLAsymmetricCipherKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        privateKey = new BoringSSLAsymmetricKeyParameter(privateKeyBytes, true);
        publicKey = new BoringSSLAsymmetricKeyParameter(publicKeyBytes, false);
    }

    @Override
    public BoringSSLAsymmetricKeyParameter publicParameters() {
        return publicKey;
    }

    @Override
    public BoringSSLAsymmetricKeyParameter privateParameters() {
        return privateKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        BoringSSLAsymmetricCipherKeyPair that = (BoringSSLAsymmetricCipherKeyPair) o;
        if (!privateKey.equals(that.privateKey)) {
            return false;
        }
        return publicKey.equals(that.publicKey);
    }

    @Override
    public int hashCode() {
        int result = privateKey.hashCode();
        result = 31 * result + publicKey.hashCode();
        return result;
    }
}

