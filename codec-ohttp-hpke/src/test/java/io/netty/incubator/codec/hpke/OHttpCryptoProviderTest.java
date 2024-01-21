/*
 * Copyright 2024 The Netty Project
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.concurrent.FastThreadLocalThread;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

public class OHttpCryptoProviderTest {

    @Test
    public void testCachingDisabled() {
        TestOHttpCryptoProvider testProvider = new TestOHttpCryptoProvider();
        CachingOHttpCryptoProvider provider = new CachingOHttpCryptoProvider(testProvider, 0, 0);
        byte[] enc = new byte[128];
        ThreadLocalRandom.current().nextBytes(enc);
        byte[] info = new byte[128];
        ThreadLocalRandom.current().nextBytes(info);

        TestAsymmetricCipherKeyPair skR = new TestAsymmetricCipherKeyPair();
        TestAsymmetricCipherKeyPair kpE = new TestAsymmetricCipherKeyPair();
        TestAsymmetricKeyParameter pkR = new TestAsymmetricKeyParameter();
        try (HPKERecipientContext context =
                provider.setupHPKEBaseR(KEM.P256_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, enc, skR, info)) {
            try (HPKERecipientContext context2 =
                    provider.setupHPKEBaseR(KEM.P256_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, enc, skR, info)) {
                assertNotSame(context, context2);
            }
        }

        try (HPKESenderContext senderContext =
                     provider.setupHPKEBaseS(KEM.P256_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, pkR, info, kpE)) {
            try (HPKESenderContext senderContext2 =
                         provider.setupHPKEBaseS(KEM.P256_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, pkR, info, kpE)) {
                assertNotSame(senderContext, senderContext2);
            }
        }
    }

    @Test
    public void testCachingRecipientContext() throws InterruptedException {
        TestOHttpCryptoProvider testProvider = new TestOHttpCryptoProvider();
        CachingOHttpCryptoProvider provider = new CachingOHttpCryptoProvider(testProvider, 1, 0);
        byte[] enc = new byte[128];
        ThreadLocalRandom.current().nextBytes(enc);
        byte[] info = new byte[128];
        ThreadLocalRandom.current().nextBytes(info);

        executeInFastThread(() -> {
            TestAsymmetricCipherKeyPair skR = new TestAsymmetricCipherKeyPair();
            try (HPKERecipientContext context =
                         provider.setupHPKEBaseR(KEM.P256_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, enc, skR, info)) {
                try (HPKERecipientContext context2 = provider.setupHPKEBaseR(KEM.P256_SHA256, KDF.HKDF_SHA256,
                        AEAD.AES_GCM128, enc, skR, info)) {
                    assertSame(context, context2);
                }
            }
        });
    }

    private void executeInFastThread(Runnable r) throws InterruptedException {
        final AtomicReference<AssertionError> errorRef = new AtomicReference<>();
        FastThreadLocalThread t = new FastThreadLocalThread(() -> {
            try {
                r.run();
            } catch (AssertionError e) {
                errorRef.set(e);
            }
        });
        t.start();
        t.join();
        AssertionError e = errorRef.get();
        if (e != null) {
            throw e;
        }
    }

    private static final class TestAsymmetricKeyParameter implements AsymmetricKeyParameter {
        @Override
        public byte[] encoded() {
            return new byte[0];
        }

        @Override
        public boolean isPrivate() {
            return false;
        }
    }

    private static final class TestAsymmetricCipherKeyPair implements AsymmetricCipherKeyPair {
        @Override
        public AsymmetricKeyParameter publicParameters() {
            return null;
        }

        @Override
        public AsymmetricKeyParameter privateParameters() {
            return null;
        }
    }

    private final class TestOHttpCryptoProvider implements OHttpCryptoProvider {
        @Override
        public AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
            return null;
        }

        @Override
        public HPKESenderContext setupHPKEBaseS(KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR,
                                                byte[] info, AsymmetricCipherKeyPair kpE) {
            return new TestHPKESenderContext();
        }

        @Override
        public HPKERecipientContext setupHPKEBaseR(KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                                   AsymmetricCipherKeyPair skR, byte[] info) {
            return new TestHPKERecipientContext();
        }

        @Override
        public AsymmetricCipherKeyPair deserializePrivateKey(KEM kem, byte[] privateKeyBytes, byte[] publicKeyBytes) {
            return null;
        }

        @Override
        public AsymmetricKeyParameter deserializePublicKey(KEM kem, byte[] publicKeyBytes) {
            return null;
        }

        @Override
        public AsymmetricCipherKeyPair newRandomPrivateKey(KEM kem) {
            return null;
        }

        @Override
        public boolean isSupported(AEAD aead) {
            return false;
        }

        @Override
        public boolean isSupported(KEM kem) {
            return false;
        }

        @Override
        public boolean isSupported(KDF kdf) {
            return false;
        }
    }

    private static final class TestHPKESenderContext implements HPKESenderContext {
        final AtomicBoolean closed = new AtomicBoolean();
        @Override
        public void close() {
            closed.set(true);
        }

        @Override
        public void seal(ByteBufAllocator alloc, ByteBuf aad, ByteBuf pt, ByteBuf out) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isDirectBufferPreferred() {
            return false;
        }

        @Override
        public byte[] export(byte[] exportContext, int length) {
            return new byte[0];
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            return new byte[0];
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            return new byte[0];
        }

        @Override
        public byte[] encapsulation() {
            return new byte[0];
        }
    }
    private static final class TestHPKERecipientContext implements HPKERecipientContext {

        final AtomicBoolean closed = new AtomicBoolean();

        @Override
        public void close() {
            closed.set(true);
        }

        @Override
        public void open(ByteBufAllocator alloc, ByteBuf aad, ByteBuf ct, ByteBuf out) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isDirectBufferPreferred() {
            return false;
        }

        @Override
        public byte[] export(byte[] exportContext, int length) {
            return new byte[0];
        }

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            return new byte[0];
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            return new byte[0];
        }
    }
}
