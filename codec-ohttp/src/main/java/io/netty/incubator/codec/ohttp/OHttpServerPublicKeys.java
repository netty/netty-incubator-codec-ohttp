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

import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import io.netty.incubator.codec.hpke.AEAD;

import io.netty.incubator.codec.hpke.KDF;

import io.netty.incubator.codec.hpke.KEM;
import static java.util.Objects.requireNonNull;

/**
 * Set of server public keys and cipher suites for a OHTTP client.
 */
public final class OHttpServerPublicKeys implements Iterable<Map.Entry<Byte, OHttpKey.PublicKey>> {
    private final Map<Byte, OHttpKey.PublicKey> keys;

    public OHttpServerPublicKeys(Map<Byte, OHttpKey.PublicKey> keys) {
        this.keys = Collections.unmodifiableMap(requireNonNull(keys, "keys"));
    }

    /**
     * Return all {@link OHttpKey.PublicKey}s.
     *
     * @return keys.
     */
    public Collection<OHttpKey.PublicKey> keys() {
        return keys.values();
    }

    /**
     * Return the {@link OHttpKey.PublicKey} for the given id or {@code null} if there is no key for the id.
     *
     * @param keyId the id of the key.
     * @return  key the key.
     */
    public OHttpKey.PublicKey key(byte keyId) {
        return keys.get(keyId);
    }

    @Override
    public Iterator<Map.Entry<Byte, OHttpKey.PublicKey>> iterator() {
        return keys.entrySet().iterator();
    }

    @Override
    public String toString() {
        return keys.values()
                .stream()
                .map(k -> "{ciphers=" +
                        k.ciphersuites().stream()
                                .map(OHttpCiphersuite::toString)
                                .collect(Collectors.joining(", ", "[", "]")) +
                        ", publicKey=" + ByteBufUtil.hexDump(k.pkEncoded()) + "}")
                .collect(Collectors.joining(", ", "[", "]"));
    }

    /**
     * Decode a serialized {@link OHttpServerPublicKeys} on the client.
     *
     *
     * @param       input the {@link ByteBuf} that is decoded
     * @return      the {@link OHttpServerPublicKeys} that were decoded.
     * @deprecated  use {@link #decodeKeyConfigurationMediaType(ByteBuf)} as this implementation does not correctly
     *              follow the RFC9458.
     * @throws      CryptoException in case of a decoding failure
     */
    @Deprecated
    public static OHttpServerPublicKeys decode(ByteBuf input) throws CryptoException {
        return decode0(input, false);
    }
    /**
     * Decode a key configuration on the client from bytes, using the format
     * described in <a href="https://www.rfc-editor.org/rfc/rfc9458.html#section-3.1">RFC 9458 Section 3.2</a>.
     *
     * @param   input the {@link ByteBuf} that is decoded
     * @return  the {@link OHttpServerPublicKeys} that were decoded.
     * @throws  CryptoException in case of a decoding failure
     */
    public static OHttpServerPublicKeys decodeKeyConfigurationMediaType(ByteBuf input) throws CryptoException {
        return decode0(input, true);
    }

    private static OHttpServerPublicKeys decode0(ByteBuf input, boolean rfc9458Mode) throws CryptoException {
        Map<Byte, OHttpKey.PublicKey> keys = new HashMap<>();
        while (input.isReadable()) {
            short length = -1;
            if (rfc9458Mode) {
                length = input.readShort();
            }
            int readerIndex = input.readerIndex();
            byte keyId = input.readByte();
            KEM kem = KEM.forId(input.readShort());
            byte[] publicKeyBytes = new byte[kem.npk()];
            input.readBytes(publicKeyBytes);
            int len = input.readShort();
            ByteBuf ecInput = input.readSlice(len);
            List<OHttpKey.Cipher> ciphers = new ArrayList<>();
            while (ecInput.isReadable()) {
                KDF kdf = KDF.forId(ecInput.readShort());
                AEAD aead = AEAD.forId(ecInput.readShort());
                ciphers.add(OHttpKey.newCipher(kdf, aead));
            }
            if (rfc9458Mode && input.readerIndex() - readerIndex != length) {
                throw new CryptoException("Unable to decode key configuration media type");
            }
            OHttpKey.PublicKey publicKey = OHttpKey.newPublicKey(keyId, kem, ciphers, publicKeyBytes);
            keys.put(keyId, publicKey);
        }
        return new OHttpServerPublicKeys(keys);
    }
}
