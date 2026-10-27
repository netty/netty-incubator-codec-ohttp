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
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.incubator.codec.bhttp.BinaryHttpResponse;
import io.netty.incubator.codec.bhttp.DefaultBinaryHttpResponse;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpRequest;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpResponse;
import io.netty.incubator.codec.bhttp.FullBinaryHttpRequest;
import io.netty.incubator.codec.bhttp.FullBinaryHttpResponse;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLHPKE;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLOHttpCryptoProvider;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static io.netty.incubator.codec.ohttp.OHttpCodecsTest.strToBuf;
import static io.netty.incubator.codec.ohttp.OHttpCodecsTest.testRequestResponseFlow;
import static io.netty.incubator.codec.ohttp.OHttpCodecsTest.testTransferFlow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class OHttpPlaintextTransformerTest {

    private static final KEM KEM_ID = KEM.X25519_SHA256;
    private static final byte KEY_ID = 0x66;

    @BeforeAll
    public static void setupAll() {
        System.setProperty("io.netty.leakDetection.level", "paranoid");
    }

    static Stream<Arguments> versionsAndProviders() {
        List<Arguments> arguments = new ArrayList<>();
        for (OHttpVersion version : Arrays.asList(OHttpVersionDraft.INSTANCE, OHttpVersionChunkDraft.INSTANCE)) {
            arguments.add(Arguments.of(version, BouncyCastleOHttpCryptoProvider.INSTANCE));
            if (BoringSSLHPKE.isAvailable()) {
                arguments.add(Arguments.of(version, BoringSSLOHttpCryptoProvider.INSTANCE));
            }
        }
        return arguments.stream();
    }

    static Stream<Arguments> roundTripArguments() {
        List<Arguments> arguments = new ArrayList<>();
        versionsAndProviders().forEach(args -> {
            for (boolean knownLength : new boolean[] { false, true }) {
                for (boolean useTransformer : new boolean[] { false, true }) {
                    arguments.add(Arguments.of(args.get()[0], args.get()[1], knownLength, useTransformer));
                }
            }
        });
        return arguments.stream();
    }

    @ParameterizedTest
    @MethodSource("roundTripArguments")
    void testRoundTrip(OHttpVersion version, OHttpCryptoProvider provider, boolean knownLength,
                       boolean useTransformer) throws Exception {
        MarkerXorTransformer clientTransformer = useTransformer ? new MarkerXorTransformer() : null;
        MarkerXorTransformer serverTransformer = useTransformer ? new MarkerXorTransformer() : null;
        AtomicReference<HttpRequest> outerRequest = new AtomicReference<>();
        Channels channels = new Channels(version, provider, knownLength, clientTransformer,
                (ctx, request) -> {
                    outerRequest.set(request);
                    return serverTransformer;
                });

        HttpHeaders trailers = new DefaultHttpHeaders().add("x-trailer", "value");
        FullBinaryHttpRequest request = new DefaultFullBinaryHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.POST, "https", "foo.bar", "/test", strToBuf("request body"));
        request.trailingHeaders().set(trailers);

        testTransferFlow(channels.client, channels.server, false,
                Collections.singletonList(request),
                Arrays.asList(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/test"),
                        new DefaultHttpContent(strToBuf("request body")),
                        new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER, trailers)));

        assertNotNull(outerRequest.get());
        assertEquals("/ohttp", outerRequest.get().uri());
        assertEquals(version.requestContentType().toString(),
                outerRequest.get().headers().get(HttpHeaderNames.CONTENT_TYPE));

        FullBinaryHttpResponse response = new DefaultFullBinaryHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK, strToBuf("response body"));
        response.trailingHeaders().set(trailers);

        testTransferFlow(channels.server, channels.client, false,
                Collections.singletonList(response),
                Arrays.asList(new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK),
                        new DefaultHttpContent(strToBuf("response body")),
                        new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER, trailers)));

        if (useTransformer) {
            // Each side decoded what the other side encoded and saw the expected binary HTTP framing indicator.
            assertEquals(clientTransformer.encoded, serverTransformer.decoded);
            assertEquals(serverTransformer.encoded, clientTransformer.decoded);
            assertEquals(knownLength ? 0x00 : 0x02, clientTransformer.firstEncodedByte);
            assertEquals(knownLength ? 0x01 : 0x03, serverTransformer.firstEncodedByte);
        }
        channels.finish();
    }

    @ParameterizedTest
    @MethodSource("versionsAndProviders")
    void testServerTransformerFailureProducesBadRequest(OHttpVersion version, OHttpCryptoProvider provider)
            throws Exception {
        Channels channels = new Channels(version, provider, false, new MarkerXorTransformer(),
                (ctx, request) -> new MarkerXorTransformer() {
                    @Override
                    public void decode(ByteBufAllocator alloc, ByteBuf in, boolean isFinal, ByteBuf out) {
                        throw new CorruptedFrameException("Unable to transform");
                    }
                });

        testRequestResponseFlow(channels.client, channels.server,
                Collections.singletonList(newFullRequest()),
                Collections.singletonList(newBadRequestResponse()));
        channels.finish();
    }

    @ParameterizedTest
    @MethodSource("versionsAndProviders")
    void testServerTransformerRejectsIndeterminateLength(OHttpVersion version, OHttpCryptoProvider provider)
            throws Exception {
        // Accepted as the request uses the known-length encoding.
        Channels channels = new Channels(version, provider, true, new MarkerXorTransformer(),
                (ctx, request) -> new KnownLengthOnlyTransformer());
        channels.client.writeOutbound(newFullRequest());
        transfer(channels.client, channels.server);
        HttpRequest received = channels.server.readInbound();
        assertEquals("/test", received.uri());
        channels.finish();

        // Rejected as the request uses the indeterminate-length encoding.
        channels = new Channels(version, provider, false, new MarkerXorTransformer(),
                (ctx, request) -> new KnownLengthOnlyTransformer());
        testRequestResponseFlow(channels.client, channels.server,
                Collections.singletonList(newFullRequest()),
                Collections.singletonList(newBadRequestResponse()));
        channels.finish();
    }

    private static FullBinaryHttpRequest newFullRequest() {
        return new DefaultFullBinaryHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.POST, "https", "foo.bar", "/test", strToBuf("request body"));
    }

    private static BinaryHttpResponse newBadRequestResponse() {
        BinaryHttpResponse response = new DefaultBinaryHttpResponse(HttpVersion.HTTP_1_1,
                HttpResponseStatus.BAD_REQUEST);
        response.headers().add(HttpHeaderNames.CONNECTION, "close");
        return response;
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

    private interface ServerTransformerFactory {
        OHttpPlaintextTransformer create(ChannelHandlerContext ctx, HttpRequest request);
    }

    private static final class Channels {
        final EmbeddedChannel client;
        final EmbeddedChannel server;

        Channels(OHttpVersion version, OHttpCryptoProvider provider, boolean knownLength,
                 OHttpPlaintextTransformer clientTransformer, ServerTransformerFactory serverTransformerFactory)
                throws Exception {
            AsymmetricCipherKeyPair kpR = provider.newRandomPrivateKey(KEM_ID);
            OHttpServerKeys serverKeys = new OHttpServerKeys(
                    OHttpKey.newPrivateKey(KEY_ID, KEM_ID,
                            Collections.singletonList(OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128)), kpR));
            OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, KEM_ID, KDF.HKDF_SHA256, AEAD.AES_GCM128);
            AsymmetricKeyParameter publicKey = provider.deserializePublicKey(KEM_ID, kpR.publicParameters().encoded());
            OHttpClientCodec.EncapsulationParameters parameters = OHttpClientCodec.EncapsulationParameters.newInstance(
                    version, ciphersuite, publicKey, "/ohttp", "authority");

            client = new EmbeddedChannel(new HttpClientCodec(), new OHttpClientCodecBuilder()
                    .setProvider(provider)
                    .setKnownLengthBinaryHttp(knownLength)
                    .setEncapsulationFunction(ignore -> new TransformingEncapsulationParameters(
                            parameters, clientTransformer))
                    .build());

            server = new EmbeddedChannel(new HttpServerCodec(), new OHttpServerCodec(new OHttpServerCodecBuilder()
                    .setProvider(provider)
                    .setServerKeys(serverKeys)
                    .setKnownLengthBinaryHttp(knownLength)) {
                @Override
                protected OHttpPlaintextTransformer plaintextTransformer(ChannelHandlerContext ctx,
                                                                         HttpRequest request) {
                    return serverTransformerFactory.create(ctx, request);
                }
            });
        }

        void finish() {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    private static final class TransformingEncapsulationParameters
            implements OHttpClientCodec.EncapsulationParameters {
        private final OHttpClientCodec.EncapsulationParameters delegate;
        private final OHttpPlaintextTransformer transformer;

        TransformingEncapsulationParameters(OHttpClientCodec.EncapsulationParameters delegate,
                                            OHttpPlaintextTransformer transformer) {
            this.delegate = delegate;
            this.transformer = transformer;
        }

        @Override
        public String outerRequestUri() {
            return delegate.outerRequestUri();
        }

        @Override
        public String outerRequestAuthority() {
            return delegate.outerRequestAuthority();
        }

        @Override
        public OHttpCiphersuite ciphersuite() {
            return delegate.ciphersuite();
        }

        @Override
        public AsymmetricKeyParameter serverPublicKey() {
            return delegate.serverPublicKey();
        }

        @Override
        public OHttpVersion version() {
            return delegate.version();
        }

        @Override
        public OHttpPlaintextTransformer plaintextTransformer() {
            return transformer;
        }
    }

    /**
     * Prepends a marker byte and XORs all other bytes, so the plaintext can only be parsed if both sides applied the
     * transformation.
     */
    private static class MarkerXorTransformer implements OHttpPlaintextTransformer {
        private static final byte MARKER = 0x7f;
        private static final int MASK = 0x5a;

        int encoded;
        int decoded;
        Integer firstEncodedByte;

        @Override
        public void decode(ByteBufAllocator alloc, ByteBuf in, boolean isFinal, ByteBuf out) {
            if (in.readByte() != MARKER) {
                throw new CorruptedFrameException("Missing marker");
            }
            xor(in, out);
            decoded++;
        }

        @Override
        public void encode(ByteBufAllocator alloc, ByteBuf in, boolean isFinal, ByteBuf out) {
            if (firstEncodedByte == null && in.isReadable()) {
                firstEncodedByte = (int) in.getByte(in.readerIndex());
            }
            out.writeByte(MARKER);
            xor(in, out);
            encoded++;
        }

        private static void xor(ByteBuf in, ByteBuf out) {
            while (in.isReadable()) {
                out.writeByte(in.readByte() ^ MASK);
            }
        }
    }

    /**
     * Rejects binary HTTP messages that use the indeterminate-length encoding.
     */
    private static final class KnownLengthOnlyTransformer extends MarkerXorTransformer {
        @Override
        public void decode(ByteBufAllocator alloc, ByteBuf in, boolean isFinal, ByteBuf out) {
            int writerIndex = out.writerIndex();
            super.decode(alloc, in, isFinal, out);
            if (decoded == 1 && out.writerIndex() > writerIndex && out.getByte(writerIndex) == 0x02) {
                throw new CorruptedFrameException("Indeterminate-length binary HTTP is not supported");
            }
        }
    }
}
