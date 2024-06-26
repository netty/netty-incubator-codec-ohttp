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
package io.netty.incubator.codec.ohttp;

import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.KDF;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import io.netty.incubator.codec.hpke.KEM;
import static java.util.Objects.requireNonNull;

public abstract class OHttpKey {

    private final byte id;
    private final KEM kem;
    private final List<Cipher> ciphers;

    OHttpKey(byte id, KEM kem, List<Cipher> ciphers) {
        this.id = id;
        this.kem = requireNonNull(kem);
        this.ciphers = Collections.unmodifiableList(requireNonNull(ciphers, "ciphers"));
    }

    public byte id() {
        return this.id;
    }

    public KEM kem() {
        return this.kem;
    }

    public List<Cipher> ciphers() {
        return this.ciphers;
    }

    public List<OHttpCiphersuite> ciphersuites() {
        return ciphers.stream()
                .map(c -> new OHttpCiphersuite(id, kem, c.kdf(), c.aead()))
                .collect(Collectors.toList());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OHttpKey oHttpKey = (OHttpKey) o;
        return id == oHttpKey.id && kem == oHttpKey.kem && Objects.equals(ciphers, oHttpKey.ciphers);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, kem, ciphers);
    }

    public static final class Cipher {
        private final KDF kdf;
        private final AEAD aead;

        public KDF kdf() {
            return this.kdf;
        }

        public AEAD aead() {
            return this.aead;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Cipher cipher = (Cipher) o;
            return kdf == cipher.kdf && aead == cipher.aead;
        }

        @Override
        public int hashCode() {
            return Objects.hash(kdf, aead);
        }

        private Cipher(
                KDF kdf,
                AEAD aead) {
            this.kdf = requireNonNull(kdf, "kdf");
            this.aead = requireNonNull(aead, "aead");
        }
    }

    public static final class PublicKey extends OHttpKey {
        private final byte[] pkEncoded;

        public byte[] pkEncoded() {
            return pkEncoded.clone();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            if (!super.equals(o)) {
                return false;
            }
            PublicKey publicKey = (PublicKey) o;
            return Arrays.equals(pkEncoded, publicKey.pkEncoded);
        }

        @Override
        public int hashCode() {
            return Objects.hash(super.hashCode(), Arrays.hashCode(pkEncoded));
        }

        private PublicKey(byte id, KEM kem, List<Cipher> ciphers, byte[] pkEncoded) throws CryptoException {
            super(id, kem, ciphers);
            this.pkEncoded = requireNonNull(pkEncoded, "pkEncoded").clone();

            if (pkEncoded.length != kem.npk()) {
                throw new CryptoException("Invalid public key, pkEncoded.length does not match Npk from KEM");
            }
        }
    }

    public static final class PrivateKey extends OHttpKey {
        private final AsymmetricCipherKeyPair keyPair;

        public AsymmetricCipherKeyPair keyPair() {
            return this.keyPair;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            if (!super.equals(o)) {
                return false;
            }
            PrivateKey that = (PrivateKey) o;
            return Objects.equals(keyPair, that.keyPair);
        }

        @Override
        public int hashCode() {
            return Objects.hash(super.hashCode(), keyPair);
        }

        private PrivateKey(
                byte id,
                KEM kem,
                List<Cipher> ciphers,
                AsymmetricCipherKeyPair keyPair) throws CryptoException {
            super(id, kem, ciphers);

            requireNonNull(keyPair, "keyPair");

            byte[] encoded = keyPair.privateParameters().encoded();
            if (encoded != null && encoded.length != kem.npk()) {
                throw new CryptoException("Invalid public key, pkEncoded.length does not match Npk from KEM");
            }
            this.keyPair = keyPair;
        }
    }

    public static PublicKey newPublicKey(byte id, KEM kem, List<Cipher> ciphers, byte[] pkEncoded)
            throws CryptoException {
        return new PublicKey(id, kem, ciphers, pkEncoded);
    }

    public static Cipher newCipher(KDF kdf, AEAD aead) {
        return new Cipher(kdf, aead);
    }

    public static PrivateKey newPrivateKey(byte id, KEM kem, List<Cipher> ciphers, AsymmetricCipherKeyPair keyPair)
            throws CryptoException {
        return new PrivateKey(id, kem, ciphers, keyPair);
    }
}
