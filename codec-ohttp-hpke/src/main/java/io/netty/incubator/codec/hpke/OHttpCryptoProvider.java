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

import java.util.List;

/**
 * Provides methods to handle <a href="https://www.rfc-editor.org/rfc/rfc9180.html">Hybrid Public Key Encryption</a>
 * for oHTTP. Because of that the functionality is limited to what is needed for oHTTP.
 */
public interface OHttpCryptoProvider {
    /**
     * Creates a new {@link AEADContext} instance implementation of
     * <a href="https://datatracker.ietf.org/doc/html/rfc5116">An AEAD encryption algorithm [RFC5116]</a>.
     *
     * @param aead          the {@link AEAD} to use.
     * @param key           the key to use.
     * @param baseNonce     the nounce to use.
     * @return              the created {@link AEADContext} based on the given arguments.
     */
    AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce);

    /**
     * Establish a {@link HPKESenderContext} that can be used for encryption.
     *
     * @param mode  the {@link HPKEMode} to use.
     * @param kem   the {@link KEM} to use.
     * @param kdf   the {@link KDF} to use.
     * @param aead  the {@link AEAD} to use.
     * @param pkR   the public key.
     * @param info  info parameter.
     * @param kpE   the ephemeral keypair or {@code null} if none should be used.
     * @return      the context.
     */
    HPKESenderContext setupHPKEBaseS(HPKEMode mode, KEM kem, KDF kdf, AEAD aead,
                                     AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE);

    /**
     * Establish a {@link HPKERecipientContext} that can be used for decryption.
     *
     * @param mode  the {@link HPKEMode} to use.
     * @param kem   the {@link KEM} to use.
     * @param kdf   the {@link KDF} to use.
     * @param aead  the {@link AEAD} to use.
     * @param enc   an encapsulated KEM shared secret.
     * @param skR   the private key.
     * @param info  info parameter.
     * @return      the context.
     */
    HPKERecipientContext setupHPKEBaseR(HPKEMode mode, KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                        AsymmetricCipherKeyPair skR, byte[] info);

    /**
     * Deserialize the input and return the private key.
     *
     * @param kem               the {@link KEM} that is used.
     * @param privateKeyBytes   the private key
     * @param publicKeyBytes    the public key.
     * @return                  the deserialized {@link AsymmetricCipherKeyPair}.
     */
    AsymmetricCipherKeyPair deserializePrivateKey(KEM kem, byte[] privateKeyBytes, byte[] publicKeyBytes);

    /**
     * Deserialize the input and return the public key.
     *
     * @param kem               the {@link KEM} that is used.
     * @param publicKeyBytes    the public key.
     * @return                  the deserialized {@link AsymmetricKeyParameter}.
     */
    AsymmetricKeyParameter deserializePublicKey(KEM kem, byte[] publicKeyBytes);

    /**
     * Returns an immutable {@link List} of all supported {@link AEAD}s.
     *
     * @return supported {@link AEAD}s.
     */
    List<AEAD> supportedAEAD();

    /**
     * Returns an immutable {@link List} of all supported {@link KEM}s.
     *
     * @return supported {@link KEM}s.
     */
    List<KEM> supportedKEM();

    /**
     * Returns an immutable {@link List} of all supported {@link KDF}s.
     *
     * @return supported {@link KDF}s.
     */
    List<KDF> supportedKDF();

    /**
     * Returns an immutable {@link List} of all supported {@link HPKEMode}s.
     *
     * @return supported {@link HPKEMode}s.
     */
    List<HPKEMode> supportedMode();
}
