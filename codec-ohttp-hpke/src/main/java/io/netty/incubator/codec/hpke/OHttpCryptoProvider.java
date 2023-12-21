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
     * @param mode  the {@link Mode} to use.
     * @param kem   the {@link KEM} to use.
     * @param kdf   the {@link KDF} to use.
     * @param aead  the {@link AEAD} to use.
     * @param pkR   the public key.
     * @param info  info parameter.
     * @param kpE   the ephemeral keypair or {@code null} if none should be used.
     * @return      the context.
     */
    HPKESenderContext setupHPKEBaseS(Mode mode, KEM kem, KDF kdf, AEAD aead,
                                                AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE);

    /**
     * Establish a {@link HPKERecipientContext} that can be used for decryption.
     *
     * @param mode  the {@link Mode} to use.
     * @param kem   the {@link KEM} to use.
     * @param kdf   the {@link KDF} to use.
     * @param aead  the {@link AEAD} to use.
     * @param enc   an encapsulated KEM shared secret.
     * @param skR   the private key.
     * @param info  info parameter.
     * @return      the context.
     */
    HPKERecipientContext setupHPKEBaseR(Mode mode, KEM kem, KDF kdf, AEAD aead, byte[] enc,
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
     * Returns an immutable {@link List} of all supported {@link Mode}s.
     *
     * @return supported {@link Mode}s.
     */
    List<Mode> supportedMode();

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-hybrid-public-key-encryptio">Hybrid Public Key Encryption</a>
     */
    enum Mode {
        Base((byte) 0x00),
        Psk((byte) 0x01),
        Auth((byte) 0x02),
        AuthPsk((byte) 0x03);

        private final byte id;

        Mode(byte id) {
            this.id = id;
        }

        public byte value() {
            return id;
        }

        public static Mode forId(byte id) {
            for (Mode val : values()) {
                if (val.id == id) {
                    return val;
                }
            }
            throw new IllegalArgumentException("unknown Mode id " + id);
        }
    }

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1">Key Encapsulation Mechanism</a>
     */
    enum KEM {
        P256_SHA256((short) 16, 65, 65),
        P384_SHA348((short) 17, 97, 97),
        P521_SHA512((short) 18, 133, 133),
        X25519_SHA256((short) 32, 32, 32),
        X448_SHA512((short) 33, 56, 56);

        public static KEM forId(short id) {
            for (KEM val : values()) {
                if (val.id == id) {
                    return val;
                }
            }
            throw new IllegalArgumentException("unknown KEM id " + id);
        }

        KEM(short id, int nenc, int npk) {
            this.id = id;
            this.nenc = nenc;
            this.npk = npk;
        }

        private final short id;
        private final int nenc;
        private final int npk;

        public short id() {
            return id;
        }

        public int nenc() {
            return nenc;
        }

        public int npk() {
            return npk;
        }
    }

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">Key Derivation Functions (KDFs)</a>
     */
    enum KDF {
        HKDF_SHA256((short) 0x0001),
        HKDF_SHA384((short) 0x0002),
        HKDF_SHA512((short) 0x0003);

        public static KDF forId(short id) {
            for (KDF val : values()) {
                if (val.id == id) {
                    return val;
                }
            }
            throw new IllegalArgumentException("unknown KDF id " + id);
        }

        private final short id;
        KDF(short id) {
            this.id = id;
        }

        public short id() {
            return id;
        }
    }

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">Authenticated Encryption with Associated Data (AEAD) Functions</a>
     */
    enum AEAD {
        AES_GCM128((short) 0x0001, 16, 12),
        AES_GCM256((short) 0x0002, 32, 12),
        CHACHA20_POLY1305((short) 0x0003, 32, 12);

        public static AEAD forId(short id) {
            for (AEAD val : values()) {
                if (val.id == id) {
                    return val;
                }
            }
            throw new IllegalArgumentException("unknown AEAD id " + id);
        }

        private final short id;
        private final int nk;
        private final int nn;
        AEAD(short id, int nk, int nn) {
            this.id = id;
            this.nk = nk;
            this.nn = nn;
        }

        public short id() {
            return id;
        }

        public int nk() {
            return nk;
        }

        public int nn() {
            return nn;
        }
    }
}
