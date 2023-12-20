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

import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.CryptoContext;
import io.netty.incubator.codec.hpke.HPKEContext;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DecoderException;
import org.bouncycastle.util.Arrays;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;

import static java.util.Objects.requireNonNull;

public final class OHttpCiphersuite {
    private static final Random RAND = new SecureRandom();

    private static final int ENCODED_LENGTH = 7;

    public OHttpCiphersuite(byte keyId, OHttpCryptoProvider.KEM kem, OHttpCryptoProvider.KDF kdf,
                            OHttpCryptoProvider.AEAD aead) {
        this.keyId = keyId;
        this.kem = requireNonNull(kem, "kem");
        this.kdf = requireNonNull(kdf, "kdf");
        this.aead = requireNonNull(aead, "ahead");
    }

    private final byte keyId;
    private final OHttpCryptoProvider.KEM kem;
    private final OHttpCryptoProvider.KDF kdf;
    private final OHttpCryptoProvider.AEAD aead;

    public int responseNonceLength() {
        return Math.max(aead.nk(), aead.nn());
    }


    public int encapsulatedKeyLength() {
        return kem.nenc();
    }

    public byte keyId() {
        return keyId;
    }

    public OHttpCryptoProvider.KEM kem() {
        return kem;
    }

    public OHttpCryptoProvider.KDF kdf() {
        return kdf;
    }

    public OHttpCryptoProvider.AEAD aead() {
        return aead;
    }

    void encode(ByteBuf out) {
        out.writeByte(keyId);
        out.writeShort(kem.id());
        out.writeShort(kdf.id());
        out.writeShort(aead.id());
    }

    /*
     * See https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html#section-4.3
     */
    byte[] createInfo(OHttpCryptoConfiguration configuration) {
        byte[] exportContext = configuration.requestExportContext();
        byte[] ret = new byte[exportContext.length + 8];
        ByteBuf buf = Unpooled.wrappedBuffer(ret);
        try {
            buf.writerIndex(0)
                    .writeBytes(exportContext)
                    .writeByte(0);
            encode(buf);
            return ret;
        } finally {
            buf.release();
        }
    }

    static OHttpCiphersuite decode(ByteBuf in) {
        if (in.readableBytes() < ENCODED_LENGTH) {
            return null;
        }
        try {
            byte keyId = in.readByte();
            short kemId = in.readShort();
            short kdfId = in.readShort();
            short aeadId = in.readShort();
            return new OHttpCiphersuite(
                    keyId,
                    OHttpCryptoProvider.KEM.forId(kemId),
                    OHttpCryptoProvider.KDF.forId(kdfId),
                    OHttpCryptoProvider.AEAD.forId(aeadId));
        } catch (Exception e) {
            throw new DecoderException("invalid ciphersuite", e);
        }
    }

    byte[] createResponseNonce() {
        byte[] ret = new byte[responseNonceLength()];
        RAND.nextBytes(ret);
        return ret;
    }

    /*
     * See https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html#name-encapsulation-of-responses
     */
    AEADContext createResponseAead(OHttpCryptoProvider provider, HPKEContext context, byte[] enc,
                                                 byte[] responseNonce, OHttpCryptoConfiguration configuration) {
        int secretLength = Math.max(aead.nk(), aead.nn());
        byte[] secret = context.export(configuration.responseExportContext(), secretLength);
        byte[] salt = Arrays.concatenate(enc, responseNonce);
        byte[] prk = context.extract(salt, secret);
        byte[] aeadKey = context.expand(prk, "key".getBytes(StandardCharsets.US_ASCII), aead.nk());
        byte[] aeadNonce = context.expand(prk, "nonce".getBytes(StandardCharsets.US_ASCII), aead.nn());
        return provider.setupAEAD(aead, aeadKey, aeadNonce);
    }
    @Override
    public String toString() {
        return "OHttpCiphersuite{id=" + Byte.toUnsignedInt(keyId) + ", kem=" + this.kem + ", kdf=" + this.kdf + ", aead=" + this.aead + "}";
    }
}
