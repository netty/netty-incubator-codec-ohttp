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
package io.netty.incubator.codec.hpke;

public interface HPKE {

    /**
     * Deserialize the public key and return it.
     *
     * @param pkEncoded the encoded key.
     * @return          the deserialized key.
     */
    AsymmetricKeyParameter deserializePublicKey(byte[] pkEncoded);

    /**
     * Deserialize the private key and return it.
     *
     * @param skEncoded the encoded secret key.
     * @param pkEncoded the encoded public key.
     * @return          the deserialized key.
     */
    AsymmetricCipherKeyPair deserializePrivateKey(byte[] skEncoded, byte[] pkEncoded);

    /**
     * Serialize the public key and return it.
     *
     * @param pk    the public key.
     * @return      the serialized key.
     */
    byte[] serializePublicKey(AsymmetricKeyParameter pk);

    /**
     * Serialize the private key and return it.
     *
     * @param sk    the private key.
     * @return      the serialized key.
     */
    byte[] serializePrivateKey(AsymmetricKeyParameter sk);

    /**
     * Establish a {@link HPKEContextWithEncapsulation} that can be used for encryption.
     *
     * @param pkR   the public key.
     * @param info  info parameter.
     * @param kpE   the ephemeral keypair or {@code null} if none should be used.
     * @return      the context.
     */
    HPKEContextWithEncapsulation setupBaseS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE);

    /**
     * Establish a {@link HPKEContext} that can be used for decryption.
     *
     * @param enc   an encapsulated KEM shared secret.
     * @param skR   the private key.
     * @param info  info parameter.
     * @return      the context.
     */
    HPKEContext setupBaseR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info);
}
