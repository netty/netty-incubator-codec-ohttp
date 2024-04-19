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

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.PendingWriteQueue;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
