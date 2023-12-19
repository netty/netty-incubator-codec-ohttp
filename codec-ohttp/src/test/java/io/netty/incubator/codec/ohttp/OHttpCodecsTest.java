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

import io.netty.incubator.codec.bhttp.BinaryHttpRequest;
import io.netty.incubator.codec.bhttp.DefaultBinaryHttpRequest;
import io.netty.incubator.codec.bhttp.DefaultBinaryHttpResponse;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpRequest;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpResponse;
import io.netty.incubator.codec.bhttp.FullBinaryHttpRequest;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.logging.LoggingHandler;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import io.netty.util.ReferenceCountUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class OHttpCodecsTest {

    private static final class OHttpVersionArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(OHttpVersionDraft.INSTANCE),
                    Arguments.of(OHttpVersionChunkDraft.INSTANCE)
            );
        }
    }

    @BeforeAll
    public static void setupAll() {
        System.setProperty("io.netty.leakDetection.level", "paranoid");
        Security.addProvider(new BouncyCastleProvider());
    }

    private static void transfer(EmbeddedChannel writer, EmbeddedChannel reader) {
        for (;;) {
            ByteBuf buffer = writer.readOutbound();
            if (buffer == null) {
                break;
            }
            reader.writeInbound(buffer);
        }
    }

    public interface ChannelPair {
        EmbeddedChannel client();
        EmbeddedChannel server();
    }

    public static ChannelPair createChannelPair(OHttpVersion version) throws Exception {
        AsymmetricCipherKeyPair kpR = OHttpCryptoTest.createX25519KeyPair("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        byte keyId = 0x66;

        OHttpServerKeys serverKeys = new OHttpServerKeys(
                OHttpKey.newPrivateKey(
                        keyId,
                        OHttpCryptoProvider.KEM.X25519_SHA256,
                        Arrays.asList(
                                OHttpKey.newCipher(OHttpCryptoProvider.KDF.HKDF_SHA256, OHttpCryptoProvider.AEAD.AES_GCM128),
                                OHttpKey.newCipher(OHttpCryptoProvider.KDF.HKDF_SHA256, OHttpCryptoProvider.AEAD.CHACHA20_POLY1305)),
                        kpR));

        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(keyId,
                OHttpCryptoProvider.KEM.X25519_SHA256,
                OHttpCryptoProvider.KDF.HKDF_SHA256,
                OHttpCryptoProvider.AEAD.AES_GCM128);

        AsymmetricKeyParameter publicKey = kpR.publicParameters();
        return new ChannelPair() {
            @Override
            public EmbeddedChannel client() {
                return createClientChannel(version, ciphersuite, publicKey);
            }

            @Override
            public EmbeddedChannel server() {
                return createServerChannel(serverKeys);
            }
        };
    }

    private static EmbeddedChannel createClientChannel(OHttpVersion version, OHttpCiphersuite ciphersuite, AsymmetricKeyParameter publicKey) {
        return new EmbeddedChannel(
                new LoggingHandler("CLIENT-RAW"),
                new HttpClientCodec(),
                new LoggingHandler("CLIENT-OUTER"),
                new OHttpClientCodec(BouncyCastleOHttpCryptoProvider.INSTANCE,
                        __ -> OHttpClientCodec.EncapsulationParameters.newInstance(version, ciphersuite, publicKey,
                        "/ohttp", "autority")),
                new LoggingHandler("CLIENT-INNER"));
    }

    private static EmbeddedChannel createServerChannel(OHttpServerKeys keys) {
        return new EmbeddedChannel(
                new LoggingHandler("SERVER-RAW"),
                new HttpServerCodec(),
                new LoggingHandler("SERVER-OUTER"),
                new OHttpServerCodec(BouncyCastleOHttpCryptoProvider.INSTANCE, keys),
                new LoggingHandler("SERVER-INNER"));
    }

    public static void testTransferFlow(EmbeddedChannel sender,
                                        EmbeddedChannel receiver,
                                        boolean shutdownReceiverInput,
                                        List<HttpObject> sentPieces,
                                        List<HttpObject> expectedReceivedPieces) {
        for (HttpObject obj : sentPieces) {
            sender.writeOutbound(obj);
        }
        transfer(sender, receiver);
        if (shutdownReceiverInput) {
            receiver.pipeline().fireUserEventTriggered(ChannelInputShutdownEvent.INSTANCE);
        }
        for (HttpObject expected : expectedReceivedPieces) {
            HttpObject received = receiver.readInbound();
            assertNotNull(received);
            assertEquals(expected, received);
            if (expected instanceof HttpContent) {
                assertEquals(((HttpContent) expected).content(), ((HttpContent) received).content());
            }
            ReferenceCountUtil.release(expected);
            ReferenceCountUtil.release(received);
        }
        assertTrue(receiver.inboundMessages().isEmpty());
        assertTrue(receiver.outboundMessages().isEmpty());
    }

    public static ByteBuf strToBuf(String str) {
        return Unpooled.wrappedBuffer(str.getBytes(StandardCharsets.US_ASCII));
    }

    @ParameterizedTest
    @ArgumentsSource(value = OHttpVersionArgumentsProvider.class)
    void testContent(OHttpVersion version) throws Exception {

        ChannelPair channels = createChannelPair(version);
        EmbeddedChannel client = channels.client();
        EmbeddedChannel server = channels.server();

        testTransferFlow(client, server, false,
                Collections.singletonList(new DefaultFullBinaryHttpRequest(
                        HttpVersion.HTTP_1_1,
                        HttpMethod.POST,
                        "https",
                        "foo.bar",
                        "/test",
                        strToBuf("THIS IS MY BODY"))),
                Arrays.asList(new DefaultHttpRequest(
                                HttpVersion.HTTP_1_1,
                                HttpMethod.POST,
                                "/test"),
                        new DefaultHttpContent(strToBuf("THIS IS MY BODY")),
                        new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER))
        );

        testTransferFlow(server, client, false,
                Collections.singletonList(new DefaultFullBinaryHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.OK,
                        strToBuf("RESPONSE"))),
                Arrays.asList(new DefaultHttpResponse(
                                HttpVersion.HTTP_1_1,
                                HttpResponseStatus.OK),
                        new DefaultHttpContent(strToBuf("RESPONSE")),
                        new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER))
        );

        client.finishAndReleaseAll();
        server.finishAndReleaseAll();
    }

    @ParameterizedTest
    @ArgumentsSource(value = OHttpVersionArgumentsProvider.class)
    void testContentChunked(OHttpVersion version) throws Exception {

        assumeTrue(version != OHttpVersionDraft.INSTANCE);

        ChannelPair channels = createChannelPair(version);
        EmbeddedChannel client = channels.client();
        EmbeddedChannel server = channels.server();

        testTransferFlow(client, server, false,
                Arrays.asList(newRequestWithHeaders("test", true),
                        new DefaultHttpContent(strToBuf("111"))),
                Arrays.asList(newRequestWithHeaders("test", true),
                        new DefaultHttpContent(strToBuf("111")))
        );

        testTransferFlow(client, server, false,
                Collections.singletonList(new DefaultHttpContent(strToBuf("222"))),
                Collections.singletonList(new DefaultHttpContent(strToBuf("222")))
        );

        testTransferFlow(client, server, true,
                Collections.singletonList(new DefaultHttpContent(strToBuf("333"))),
                Collections.singletonList(new DefaultHttpContent(strToBuf("333")))
        );

        testTransferFlow(server, client, false,
                Arrays.asList(new DefaultBinaryHttpResponse(
                                HttpVersion.HTTP_1_1,
                                HttpResponseStatus.OK),
                        new DefaultHttpContent(strToBuf("444"))),
                Arrays.asList(new DefaultBinaryHttpResponse(
                                HttpVersion.HTTP_1_1,
                                HttpResponseStatus.OK),
                        new DefaultHttpContent(strToBuf("444")))
        );

        testTransferFlow(server, client, false,
                Collections.singletonList(new DefaultHttpContent(strToBuf("555"))),
                Collections.singletonList(new DefaultHttpContent(strToBuf("555")))
        );

        testTransferFlow(server, client, true,
                Collections.singletonList(new DefaultHttpContent(strToBuf("666"))),
                Collections.singletonList(new DefaultHttpContent(strToBuf("666")))
        );

        client.finishAndReleaseAll();
        server.finishAndReleaseAll();
    }

    @ParameterizedTest
    @ArgumentsSource(value = OHttpVersionArgumentsProvider.class)
    void testCodec(OHttpVersion version) throws Exception {

        ChannelPair channels = createChannelPair(version);
        EmbeddedChannel client = channels.client();
        EmbeddedChannel server = channels.server();

        testTransferFlow(client, server, false,
                Collections.singletonList(newFullRequestWithHeaders("/test", strToBuf("request body"))),
                Arrays.asList(newRequestWithHeaders("/test", false),
                        new DefaultHttpContent(strToBuf("request body")),
                        new DefaultLastHttpContent()));

        testTransferFlow(server, client, false,
                Collections.singletonList(new DefaultFullBinaryHttpResponse(
                        HttpVersion.HTTP_1_1,
                        HttpResponseStatus.OK, strToBuf("response body"))),
                Arrays.asList(new DefaultBinaryHttpResponse(
                                HttpVersion.HTTP_1_1,
                                HttpResponseStatus.OK),
                        new DefaultHttpContent(strToBuf("response body")),
                        new DefaultLastHttpContent())
        );
        client.finishAndReleaseAll();
        server.finishAndReleaseAll();
    }

    public static BinaryHttpRequest newRequestWithHeaders(String path, boolean chunked) {
        BinaryHttpRequest httpRequest = new DefaultBinaryHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "https",
                "foo.bar",
                path);
        HttpUtil.setTransferEncodingChunked(httpRequest, chunked);
        return httpRequest;
    }

    private static FullBinaryHttpRequest newFullRequestWithHeaders(String path, ByteBuf content) {
        return new DefaultFullBinaryHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "https",
                "foo.bar",
                path, content);
    }
}
