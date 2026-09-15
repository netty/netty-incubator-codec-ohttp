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
package io.netty.incubator.codec.ohttp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.PendingWriteQueue;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class OHttpServerCodecTest {

    @Test
    public void testNoOHttpWillBeDroppedAndForbidden() throws Exception {
        AsymmetricCipherKeyPair kpR = OHttpCryptoTest.createX25519KeyPair(BouncyCastleOHttpCryptoProvider.INSTANCE,
                "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        byte keyId = 0x66;

        OHttpServerKeys serverKeys = new OHttpServerKeys(
                OHttpKey.newPrivateKey(
                        keyId,
                        KEM.X25519_SHA256,
                        Arrays.asList(
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128),
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)),
                        kpR));

        DelayingWriteHandler delayingWriteHandler = new DelayingWriteHandler();
        EmbeddedChannel channel = new EmbeddedChannel(
                delayingWriteHandler,
                new OHttpServerCodec(BouncyCastleOHttpCryptoProvider.INSTANCE, serverKeys) {
                    @Override
                    protected OHttpVersion selectVersion(String contentTypeValue) {
                        return null;
                    }
                });

        assertFalse(channel.writeInbound(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/test")));

        // Write delayed by DelayingWriteHandler
        assertNull(channel.readOutbound());

        HttpContent content = new DefaultHttpContent(Unpooled.buffer().writeZero(8));
        assertFalse(channel.writeInbound(content));
        assertEquals(0, content.refCnt());

        HttpContent lastContent = new DefaultLastHttpContent(Unpooled.buffer().writeZero(8));
        assertFalse(channel.writeInbound(lastContent));
        assertEquals(0, lastContent.refCnt());

        delayingWriteHandler.writeAndFlushNow();

        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        assertTrue(response.release());

        assertFalse(channel.finish());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    public void testCryptoErrorProduceBadRequest(boolean incompletePrefix) throws Exception {
        AsymmetricCipherKeyPair kpR = OHttpCryptoTest.createX25519KeyPair(BouncyCastleOHttpCryptoProvider.INSTANCE,
                "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        byte keyId = 0x66;

        OHttpServerKeys serverKeys = new OHttpServerKeys(
                OHttpKey.newPrivateKey(
                        keyId,
                        KEM.X25519_SHA256,
                        Arrays.asList(
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128),
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)),
                        kpR));

        EmbeddedChannel channel = new EmbeddedChannel(
                new OHttpServerCodec(BouncyCastleOHttpCryptoProvider.INSTANCE, serverKeys) {
                    @Override
                    protected OHttpVersion selectVersion(String contentTypeValue) {
                        return OHttpVersionDraft.INSTANCE;
                    }
                });

        assertFalse(channel.writeInbound(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/test")));

        // There should be no outbound message yet as we did not try to parse the prefix so far.
        assertNull(channel.readOutbound());

        // Write some invalid prefix so it will fail.
        HttpContent lastContent = new DefaultLastHttpContent(Unpooled.buffer().writeZero(incompletePrefix ? 1 : 8));
        assertFalse(channel.writeInbound(lastContent));

        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        assertTrue(response.release());

        assertFalse(channel.finish());
        assertEquals(0, lastContent.refCnt());
    }

    private static final class DelayingWriteHandler extends ChannelOutboundHandlerAdapter {
        private PendingWriteQueue queue;
        private ChannelHandlerContext ctx;
        @Override
        public void handlerAdded(ChannelHandlerContext ctx) {
            this.ctx = ctx;
            queue = new PendingWriteQueue(ctx);
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            queue.add(msg, promise);
        }

        void writeAndFlushNow() {
            queue.removeAndWriteAll();
            ctx.flush();
        }
    }

    @Test
    public void testReadWhenNoAutoRead() throws Exception {
        AsymmetricCipherKeyPair kpR = OHttpCryptoTest.createX25519KeyPair(BouncyCastleOHttpCryptoProvider.INSTANCE,
                "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        byte keyId = 0x66;

        OHttpServerKeys serverKeys = new OHttpServerKeys(
                OHttpKey.newPrivateKey(
                        keyId,
                        KEM.X25519_SHA256,
                        Arrays.asList(
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128),
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)),
                        kpR));

        ReadCountHandler readCountHandler = new ReadCountHandler();
        EmbeddedChannel channel = new EmbeddedChannel(
                readCountHandler,
                new OHttpServerCodec(BouncyCastleOHttpCryptoProvider.INSTANCE, serverKeys) {
                    @Override
                    protected OHttpVersion selectVersion(String contentTypeValue) {
                        return OHttpVersionDraft.INSTANCE;
                    }
                });

        channel.config().setOption(ChannelOption.AUTO_READ, false);

        assertFalse(channel.writeInbound(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/test")));

        assertEquals(2, readCountHandler.readCount.get());

        assertFalse(channel.finish());
    }

    @Test
    public void eventLoopMustNotGetStuckOnTruncatedEncapsulatedBHttp() throws Exception {
        AsymmetricCipherKeyPair kpR = OHttpCryptoTest.createX25519KeyPair(BouncyCastleOHttpCryptoProvider.INSTANCE,
                "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        byte keyId = 0x66;

        OHttpServerKeys serverKeys = new OHttpServerKeys(
                OHttpKey.newPrivateKey(
                        keyId,
                        KEM.X25519_SHA256,
                        Arrays.asList(
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128),
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)),
                        kpR));

        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(
                keyId, KEM.X25519_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128);
        AsymmetricKeyParameter receiverPublicKey = BouncyCastleOHttpCryptoProvider.INSTANCE
                .deserializePublicKey(KEM.X25519_SHA256, kpR.publicParameters().encoded());

        // Build a well-formed encapsulated request whose plaintext is a single truncated varint byte.
        ByteBuf encapsulated = Unpooled.buffer();
        ByteBuf plaintext = Unpooled.wrappedBuffer(new byte[] { 0x40 });
        ByteBuf encrypted = Unpooled.buffer();
        try (OHttpCryptoSender sender = OHttpCryptoSender.newBuilder()
                .setOHttpCryptoProvider(BouncyCastleOHttpCryptoProvider.INSTANCE)
                .setConfiguration(OHttpVersionDraft.INSTANCE)
                .setCiphersuite(ciphersuite)
                .setReceiverPublicKey(receiverPublicKey)
                .build()) {
            sender.encrypt(UnpooledByteBufAllocator.DEFAULT, plaintext, plaintext.readableBytes(), true, encrypted);
            sender.writeHeader(encapsulated);
            encapsulated.writeBytes(encrypted);
        } finally {
            plaintext.release();
            encrypted.release();
        }

        EmbeddedChannel channel = new EmbeddedChannel(
                new OHttpServerCodecBuilder()
                        .setProvider(BouncyCastleOHttpCryptoProvider.INSTANCE)
                        .setServerKeys(serverKeys)
                        .build());

        DefaultHttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/test");
        req.headers().set(HttpHeaderNames.CONTENT_TYPE, OHttpConstants.REQUEST_CONTENT_TYPE);
        assertFalse(channel.writeInbound(req));

        // Feed the encapsulated request on a daemon thread: if decoding never returns, the test fails on the
        // deadline instead of hanging the build, and the spinning thread cannot keep the JVM alive.
        CountDownLatch done = new CountDownLatch(1);
        Thread thread = new Thread(() -> {
            try {
                channel.writeInbound(new DefaultLastHttpContent(encapsulated));
            } catch (Throwable ignore) {
                // A protocol error (e.g. CorruptedFrameException surfacing as a 4xx) is a perfectly acceptable
                // outcome here; the only unacceptable outcome is never returning.
            } finally {
                done.countDown();
            }
        }, "ohttp-decode");
        thread.setDaemon(true);
        thread.start();

        try {
            if (!done.await(10, TimeUnit.SECONDS)) {
                fail("Decoding a truncated encapsulated bHTTP message never completed: " +
                        "the decoding thread is spinning inside BinaryHttpParser.parse(...)");
            }
        } finally {
            // Whatever the codec decided to emit, nothing may be retained.
            Object outbound;
            while ((outbound = channel.readOutbound()) != null) {
                ReferenceCountUtil.release(outbound);
            }
            channel.finishAndReleaseAll();
        }
    }

    private static final class ReadCountHandler extends ChannelDuplexHandler {
        AtomicInteger readCount = new AtomicInteger();

        @Override
        public void read(ChannelHandlerContext ctx) throws Exception {
            readCount.incrementAndGet();
            super.read(ctx);
        }
    }
}
