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

import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.buffer.ByteBuf;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public final class OHttpCiphersuite {

    static final int ENCODED_LENGTH = 7;

    public OHttpCiphersuite(byte keyId, KEM kem, KDF kdf,
                            AEAD aead) {
        this.keyId = keyId;
        this.kem = requireNonNull(kem, "kem");
        this.kdf = requireNonNull(kdf, "kdf");
        this.aead = requireNonNull(aead, "ahead");
    }

    private final byte keyId;
    private final KEM kem;
    private final KDF kdf;
    private final AEAD aead;

    public int responseNonceLength() {
        return Math.max(aead.nk(), aead.nn());
    }

    public int encapsulatedKeyLength() {
        return kem.nenc();
    }

    public byte keyId() {
        return keyId;
    }

    public KEM kem() {
        return kem;
    }

    public KDF kdf() {
        return kdf;
    }

    public AEAD aead() {
        return aead;
    }

    void encode(ByteBuf out) {
        out.writeByte(keyId);
        out.writeShort(kem.id());
        out.writeShort(kdf.id());
        out.writeShort(aead.id());
    }

    static OHttpCiphersuite decode(ByteBuf in) {
        if (in.readableBytes() < ENCODED_LENGTH) {
            return null;
        }
        byte keyId = in.readByte();
        short kemId = in.readShort();
        short kdfId = in.readShort();
        short aeadId = in.readShort();
        return new OHttpCiphersuite(
                keyId,
                KEM.forId(kemId),
                KDF.forId(kdfId),
                AEAD.forId(aeadId));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OHttpCiphersuite that = (OHttpCiphersuite) o;
        return keyId == that.keyId && kem == that.kem && kdf == that.kdf && aead == that.aead;
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, kem, kdf, aead);
    }

    @Override
    public String toString() {
        return "OHttpCiphersuite{id=" + Byte.toUnsignedInt(keyId) +
                ", kem=" + this.kem + ", kdf=" + this.kdf + ", aead=" + this.aead + "}";
    }
}
