/*
 * Copyright 2026 The Netty Project
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
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseDecoder;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpRequest;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpResponse;
import io.netty.incubator.codec.bhttp.FullBinaryHttpRequest;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLHPKE;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLOHttpCryptoProvider;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OHttpServerCodecResponseTest {

    private static final byte KEY_ID = 0x66;
    private static final String INNER_STATUS_HEADER = "x-inner-status";

    static Stream<Arguments> providers() {
        List<Arguments> arguments = new ArrayList<>();
        arguments.add(Arguments.of(BouncyCastleOHttpCryptoProvider.INSTANCE));
        if (BoringSSLHPKE.isAvailable()) {
            arguments.add(Arguments.of(BoringSSLOHttpCryptoProvider.INSTANCE));
        }
        return arguments.stream();
    }

    static Stream<Arguments> providersAndVersions() {
        List<Arguments> arguments = new ArrayList<>();
        providers().forEach(provider -> {
            arguments.add(Arguments.of(provider.get()[0], OHttpVersionDraft.INSTANCE));
            arguments.add(Arguments.of(provider.get()[0], OHttpVersionChunkDraft.INSTANCE));
        });
        return arguments.stream();
    }

    private static final class Keys {
        final OHttpServerKeys serverKeys;
        final OHttpCiphersuite ciphersuite;
        final AsymmetricKeyParameter publicKey;

        Keys(OHttpCryptoProvider provider) throws Exception {
            AsymmetricCipherKeyPair kpR = provider.newRandomPrivateKey(KEM.X25519_SHA256);
            serverKeys = new OHttpServerKeys(
                    OHttpKey.newPrivateKey(
                            KEY_ID,
                            KEM.X25519_SHA256,
                            Collections.singletonList(OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128)),
                            kpR));
            ciphersuite = new OHttpCiphersuite(KEY_ID, KEM.X25519_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128);
            publicKey = provider.deserializePublicKey(KEM.X25519_SHA256, kpR.publicParameters().encoded());
        }

        OHttpServerCodecBuilder serverCodecBuilder(OHttpCryptoProvider provider) {
            return new OHttpServerCodecBuilder()
                    .setProvider(provider)
                    .setServerKeys(serverKeys);
        }

        EmbeddedChannel newClientChannel(OHttpCryptoProvider provider, OHttpVersion version) {
            return new EmbeddedChannel(
                    new HttpClientCodec(),
                    new OHttpClientCodecBuilder()
                            .setProvider(provider)
                            .setEncapsulationFunction(ignore -> OHttpClientCodec.EncapsulationParameters.newInstance(
                                    version, ciphersuite, publicKey, "/ohttp", "authority"))
                            .build());
        }
    }

    /**
     * {@link OHttpServerCodec} that replies without encapsulation if the inner response has no content.
     */
    private static class EmptyResponseUnencapsulatingServerCodec extends OHttpServerCodec {
        final List<HttpResponse> outerResponses = new ArrayList<>();

        EmptyResponseUnencapsulatingServerCodec(OHttpServerCodecBuilder builder) {
            super(builder);
        }

        @Override
        protected FullHttpResponse unencapsulatedResponse(HttpRequest request, FullHttpResponse response) {
            if (response.content().isReadable()) {
                return null;
            }
            FullHttpResponse outer = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
            outer.headers().set(INNER_STATUS_HEADER, response.status().code());
            HttpUtil.setContentLength(outer, 0);
            return outer;
        }

        @Override
        protected void onResponse(HttpRequest request, HttpResponse response) {
            outerResponses.add(response);
        }
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

    private static ByteBuf readAllOutbound(EmbeddedChannel channel) {
        ByteBuf bytes = Unpooled.buffer();
        for (;;) {
            ByteBuf buffer = channel.readOutbound();
            if (buffer == null) {
                return bytes;
            }
            bytes.writeBytes(buffer);
            buffer.release();
        }
    }

    private static FullBinaryHttpRequest newRequest(String path) {
        return new DefaultFullBinaryHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "https", "foo.bar", path,
                Unpooled.copiedBuffer("request body", StandardCharsets.US_ASCII));
    }

    /**
     * Reads a complete inner request from the server and returns its uri.
     */
    private static String readInnerRequest(EmbeddedChannel server) {
        HttpRequest request = server.readInbound();
        assertNotNull(request);
        StringBuilder content = new StringBuilder();
        for (;;) {
            HttpContent httpContent = server.readInbound();
            assertNotNull(httpContent);
            content.append(httpContent.content().toString(StandardCharsets.US_ASCII));
            boolean isLast = httpContent instanceof LastHttpContent;
            httpContent.release();
            if (isLast) {
                break;
            }
        }
        assertEquals("request body", content.toString());
        assertNull(server.readInbound());
        return request.uri();
    }

    /**
     * Decodes the unencapsulated outer response written by the server.
     */
    private static FullHttpResponse readOuterResponse(EmbeddedChannel server) {
        EmbeddedChannel decoder = new EmbeddedChannel(new HttpResponseDecoder(), new HttpObjectAggregator(1024));
        assertTrue(decoder.writeInbound(readAllOutbound(server)));
        FullHttpResponse response = decoder.readInbound();
        assertFalse(decoder.finish());
        return response;
    }

    private static void assertUnencapsulatedNoContentResponse(EmbeddedChannel server) {
        FullHttpResponse outer = readOuterResponse(server);
        try {
            assertEquals(HttpResponseStatus.OK, outer.status());
            assertEquals("204", outer.headers().get(INNER_STATUS_HEADER));
            assertNull(outer.headers().get(HttpHeaderNames.CONTENT_TYPE));
            assertFalse(outer.content().isReadable());
        } finally {
            assertTrue(outer.release());
        }
    }

    /**
     * Sends a request and an encapsulated response over the server channel and checks that the client can
     * decrypt it.
     */
    private static void assertEncapsulatedRoundTrip(Keys keys, OHttpCryptoProvider provider, OHttpVersion version,
                                                    EmbeddedChannel server) {
        EmbeddedChannel client = keys.newClientChannel(provider, version);
        assertTrue(client.writeOutbound(newRequest("/second")));
        transfer(client, server);
        assertEquals("/second", readInnerRequest(server));

        assertTrue(server.writeOutbound(new DefaultFullBinaryHttpResponse(HttpVersion.HTTP_1_1,
                HttpResponseStatus.OK, Unpooled.copiedBuffer("response body", StandardCharsets.US_ASCII))));
        transfer(server, client);

        HttpResponse response = client.readInbound();
        assertEquals(HttpResponseStatus.OK, response.status());
        StringBuilder content = new StringBuilder();
        for (;;) {
            HttpContent httpContent = client.readInbound();
            assertNotNull(httpContent);
            content.append(httpContent.content().toString(StandardCharsets.US_ASCII));
            boolean isLast = httpContent instanceof LastHttpContent;
            httpContent.release();
            if (isLast) {
                break;
            }
        }
        assertEquals("response body", content.toString());
        assertFalse(client.finishAndReleaseAll());
    }

    @ParameterizedTest
    @MethodSource("providersAndVersions")
    public void testUnencapsulatedResponse(OHttpCryptoProvider provider, OHttpVersion version) throws Exception {
        Keys keys = new Keys(provider);
        EmptyResponseUnencapsulatingServerCodec codec =
                new EmptyResponseUnencapsulatingServerCodec(keys.serverCodecBuilder(provider));
        EmbeddedChannel server = new EmbeddedChannel(new HttpServerCodec(), codec);

        EmbeddedChannel client = keys.newClientChannel(provider, version);
        assertTrue(client.writeOutbound(newRequest("/first")));
        transfer(client, server);
        assertEquals("/first", readInnerRequest(server));

        FullHttpResponse inner = new DefaultFullBinaryHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.NO_CONTENT, Unpooled.buffer(0));
        assertTrue(server.writeOutbound(inner));
        assertEquals(0, inner.refCnt());
        assertUnencapsulatedNoContentResponse(server);
        assertEquals(1, codec.outerResponses.size());
        assertEquals("204", codec.outerResponses.get(0).headers().get(INNER_STATUS_HEADER));

        // The per-request state must have been cleaned up, so a following request on the same
        // connection is handled and its non-empty response is encapsulated.
        assertEncapsulatedRoundTrip(keys, provider, version, server);
        assertTrue(server.isOpen());

        assertFalse(client.finishAndReleaseAll());
        assertFalse(server.finishAndReleaseAll());
    }

    @ParameterizedTest
    @MethodSource("providersAndVersions")
    public void testUnencapsulatedResponseBeforeRequestFullyReceived(OHttpCryptoProvider provider,
                                                                     OHttpVersion version) throws Exception {
        Keys keys = new Keys(provider);
        EmbeddedChannel server = new EmbeddedChannel(new HttpServerCodec(),
                new EmptyResponseUnencapsulatingServerCodec(keys.serverCodecBuilder(provider)));

        EmbeddedChannel client = keys.newClientChannel(provider, version);
        assertTrue(client.writeOutbound(newRequest("/first")));
        ByteBuf requestBytes = readAllOutbound(client);
        // Hold back the terminating chunk of the outer request.
        String terminator = "0\r\n\r\n";
        int terminatorIndex = requestBytes.writerIndex() - terminator.length();
        assertEquals(terminator, requestBytes.toString(terminatorIndex, terminator.length(),
                StandardCharsets.US_ASCII));
        server.writeInbound(requestBytes.readRetainedSlice(terminatorIndex));

        // Reply before the request was fully received.
        assertTrue(server.writeOutbound(
                new DefaultFullBinaryHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NO_CONTENT)));
        assertUnencapsulatedNoContentResponse(server);

        server.writeInbound(requestBytes);
        assertEquals("/first", readInnerRequest(server));

        assertEncapsulatedRoundTrip(keys, provider, version, server);
        assertTrue(server.isOpen());

        assertFalse(client.finishAndReleaseAll());
        assertFalse(server.finishAndReleaseAll());
    }

    @Test
    public void testUnencapsulatedResponseMayBeTheInnerResponse() throws Exception {
        Keys keys = new Keys(BouncyCastleOHttpCryptoProvider.INSTANCE);
        EmbeddedChannel server = new EmbeddedChannel(
                new OHttpServerCodec(keys.serverCodecBuilder(BouncyCastleOHttpCryptoProvider.INSTANCE)) {
                    @Override
                    protected FullHttpResponse unencapsulatedResponse(HttpRequest request,
                                                                      FullHttpResponse response) {
                        return response;
                    }
                });

        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/ohttp");
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, OHttpConstants.REQUEST_CONTENT_TYPE);
        assertFalse(server.writeInbound(request));

        FullHttpResponse inner = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.ACCEPTED,
                Unpooled.copiedBuffer("plaintext", StandardCharsets.US_ASCII));
        assertTrue(server.writeOutbound(inner));
        FullHttpResponse outer = server.readOutbound();
        assertSame(inner, outer);
        assertEquals(1, outer.refCnt());
        assertTrue(outer.release());

        assertFalse(server.finishAndReleaseAll());
    }

    @ParameterizedTest
    @MethodSource("providers")
    public void testErrorResponseStatusForDecryptionFailure(OHttpCryptoProvider provider) throws Exception {
        Keys keys = new Keys(provider);
        AtomicReference<Throwable> errorCause = new AtomicReference<>();
        AtomicReference<Boolean> errorEncapsulated = new AtomicReference<>();
        EmbeddedChannel server = new EmbeddedChannel(new OHttpServerCodec(keys.serverCodecBuilder(provider)) {
            @Override
            protected HttpResponseStatus errorResponseStatus(Throwable cause, boolean encapsulated) {
                errorCause.set(cause);
                errorEncapsulated.set(encapsulated);
                return HttpResponseStatus.UNPROCESSABLE_ENTITY;
            }
        });

        // Build an encapsulated request and corrupt its authentication tag.
        ByteBuf encapsulated = Unpooled.buffer();
        ByteBuf plaintext = Unpooled.copiedBuffer("plaintext", StandardCharsets.US_ASCII);
        try (OHttpCryptoSender sender = OHttpCryptoSender.newBuilder()
                .setOHttpCryptoProvider(provider)
                .setConfiguration(OHttpVersionDraft.INSTANCE)
                .setCiphersuite(keys.ciphersuite)
                .setReceiverPublicKey(keys.publicKey)
                .build()) {
            sender.writeHeader(encapsulated);
            sender.encrypt(UnpooledByteBufAllocator.DEFAULT, plaintext, plaintext.readableBytes(), true,
                    encapsulated);
        } finally {
            plaintext.release();
        }
        int last = encapsulated.writerIndex() - 1;
        encapsulated.setByte(last, encapsulated.getByte(last) ^ 0xFF);

        DefaultHttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/ohttp");
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, OHttpConstants.REQUEST_CONTENT_TYPE);
        assertFalse(server.writeInbound(request));
        assertFalse(server.writeInbound(new DefaultLastHttpContent(encapsulated)));

        FullHttpResponse response = server.readOutbound();
        assertEquals(HttpResponseStatus.UNPROCESSABLE_ENTITY, response.status());
        assertNull(response.headers().get(HttpHeaderNames.CONTENT_TYPE));
        assertTrue(response.release());

        assertFalse(errorEncapsulated.get());
        assertInstanceOf(OHttpDecoderException.class, errorCause.get());
        assertInstanceOf(CryptoException.class, errorCause.get().getCause());
        assertEquals(0, encapsulated.refCnt());

        assertFalse(server.finishAndReleaseAll());
    }

    @ParameterizedTest
    @MethodSource("providersAndVersions")
    public void testErrorResponseStatusForEncapsulatedFailure(OHttpCryptoProvider provider, OHttpVersion version)
            throws Exception {
        Keys keys = new Keys(provider);
        AtomicReference<Throwable> errorCause = new AtomicReference<>();
        AtomicReference<Boolean> errorEncapsulated = new AtomicReference<>();
        // Use a very small max field section size so decoding fails after the encapsulation was removed.
        OHttpServerCodecBuilder builder = keys.serverCodecBuilder(provider).setMaxFieldSectionSize(64);
        EmbeddedChannel server = new EmbeddedChannel(new HttpServerCodec(),
                new EmptyResponseUnencapsulatingServerCodec(builder) {
                    @Override
                    protected HttpResponseStatus errorResponseStatus(Throwable cause, boolean encapsulated) {
                        errorCause.set(cause);
                        errorEncapsulated.set(encapsulated);
                        return HttpResponseStatus.UNPROCESSABLE_ENTITY;
                    }
                });

        EmbeddedChannel client = keys.newClientChannel(provider, version);
        FullBinaryHttpRequest request = newRequest("/test");
        request.headers().add("a", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        assertTrue(client.writeOutbound(request));
        transfer(client, server);
        transfer(server, client);

        // The error response is encapsulated even though it has no content, as the unencapsulatedResponse(...)
        // callback is not used for error responses that are generated by the codec itself.
        HttpResponse response = client.readInbound();
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNPROCESSABLE_ENTITY, response.status());
        for (;;) {
            HttpObject msg = client.readInbound();
            if (msg == null) {
                break;
            }
            ReferenceCountUtil.release(msg);
        }

        assertTrue(errorEncapsulated.get());
        assertInstanceOf(OHttpDecoderException.class, errorCause.get());
        assertFalse(server.isOpen());

        client.finishAndReleaseAll();
        server.finishAndReleaseAll();
    }
}
