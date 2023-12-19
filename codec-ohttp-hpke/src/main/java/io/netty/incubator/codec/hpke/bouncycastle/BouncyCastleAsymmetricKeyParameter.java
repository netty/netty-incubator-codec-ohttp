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
package io.netty.incubator.codec.hpke.bouncycastle;

import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;

final class BouncyCastleAsymmetricKeyParameter implements AsymmetricKeyParameter {

    final org.bouncycastle.crypto.params.AsymmetricKeyParameter param;

    BouncyCastleAsymmetricKeyParameter(org.bouncycastle.crypto.params.AsymmetricKeyParameter param) {
        this.param = param;
    }

    @Override
    public boolean isPrivate() {
        return param.isPrivate();
    }

    @Override
    public byte[] encoded() throws UnsupportedOperationException {
        if (param instanceof X25519PublicKeyParameters) {
            return ((X25519PublicKeyParameters) param).getEncoded();
        }
        if (param instanceof X448PublicKeyParameters) {
            return ((X448PublicKeyParameters) param).getEncoded();
        }
        if (param instanceof X25519PrivateKeyParameters) {
            return ((X25519PrivateKeyParameters) param).getEncoded();
        }
        if (param instanceof X448PrivateKeyParameters) {
            return ((X448PrivateKeyParameters) param).getEncoded();
        }
        return null;
    }
}
