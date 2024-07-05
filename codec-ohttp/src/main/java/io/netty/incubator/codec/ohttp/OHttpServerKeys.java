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

import io.netty.handler.codec.EncoderException;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.buffer.ByteBuf;
import io.netty.util.internal.ObjectUtil;

import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import io.netty.incubator.codec.hpke.KEM;
import io.netty.util.internal.PlatformDependent;

/**
 * Set of key pairs and cipher suites for a OHTTP server.
 */
public final class OHttpServerKeys {
    private final Map<Byte, OHttpKey.PrivateKey> keyMap = new HashMap<>();

    public OHttpServerKeys(OHttpKey.PrivateKey... keys) {
        this(Arrays.asList(ObjectUtil.checkNonEmpty(keys, "keys")));
    }

    public OHttpServerKeys(Collection<OHttpKey.PrivateKey> keys) {
        ObjectUtil.checkNonEmpty(keys, "keys");
        for (OHttpKey.PrivateKey key : keys) {
            if (keyMap.put(key.id(), key) != null) {
                throw new IllegalArgumentException("Duplicate keyID " + key.id());
            }
        }
    }

    public AsymmetricCipherKeyPair getKeyPair(OHttpCiphersuite ciphersuite) {
        OHttpKey.PrivateKey key = keyMap.get(ciphersuite.keyId());
        if (key == null) {
            return null;
        }
        for (OHttpKey.Cipher cipher : key.ciphers()) {
            if (cipher.kdf() == ciphersuite.kdf() && cipher.aead() == ciphersuite.aead()) {
                return key.keyPair();
            }
        }
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        OHttpServerKeys that = (OHttpServerKeys) o;
        return keyMap.equals(that.keyMap);
    }

    @Override
    public String toString() {
        return "OHttpServerKeys{" +
                "keyMap=" + keyMap +
                '}';
    }

    @Override
    public int hashCode() {
        return keyMap.hashCode();
    }

    /**
     * Encode {@link OHttpServerKeys} into bytes that represent {@link OHttpServerPublicKeys}, using the format
     * described at https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html#section-3.1
     *
     * @deprecated use {@link #encodeKeyConfigurationMediaType(ByteBuf)}
     */
    @Deprecated
    public void encodePublicKeys(ByteBuf output) {
        encodeKeyConfigurationMediaType(output);
    }

    /**
     * Encode a key configuration into bytes, using the format
     * described in <a href="https://www.rfc-editor.org/rfc/rfc9458.html#section-3.1">RFC 9458 Section 3.1</a>.
     *
     * @param id        the id of the key.
     * @param key       the {@link OHttpKey.PrivateKey}.
     * @param output    the {@link ByteBuf} into which the configuration is written.
     */
    private static void encodeKeyConfiguration(Byte id, OHttpKey.PrivateKey key, ByteBuf output) {
        KEM kem = key.kem();
        AsymmetricCipherKeyPair kp = key.keyPair();
        output.writeByte(id);
        output.writeShort(kem.id());

        byte[] encoded = kp.publicParameters().encoded();
        if (encoded == null) {
            throw new EncoderException("Unable to encode public keys.");
        }
        output.writeBytes(encoded);

        // Multiple by 4 as for each cipher we will write 2 short values.
        output.writeShort(key.ciphers().size() * 4);
        for (OHttpKey.Cipher cipher : key.ciphers()) {
            output.writeShort(cipher.kdf().id());
            output.writeShort(cipher.aead().id());
        }
    }

    /**
     * Encode the key configurations into bytes, using the format described in
     * <a href="https://www.rfc-editor.org/rfc/rfc9458.html#section-3.2">RFC 9458 Section 3.2</a>.
     *
     * @param output    the {@link ByteBuf} into which the configuration is written.
     */
    public void encodeKeyConfigurationMediaType(ByteBuf output) {
        for (Map.Entry<Byte, OHttpKey.PrivateKey> key : keyMap.entrySet()) {
            int writerIndex = output.writerIndex();
            // Skip the first two bytes as we will use these later to set the actual len that was used.
            output.ensureWritable(2);
            output.writerIndex(writerIndex + 2);
            encodeKeyConfiguration(key.getKey(), key.getValue(), output);
            int written = output.writerIndex() - writerIndex - 2;
            // The length needs to be added in front:
            // See https://www.rfc-editor.org/rfc/rfc9458.html#section-3.2
            output.setShort(writerIndex, written);
        }
    }
}
