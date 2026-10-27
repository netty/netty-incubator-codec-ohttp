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
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpRequest;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpResponse;
import io.netty.incubator.codec.hpke.AEAD;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKEMode;
import io.netty.incubator.codec.hpke.HPKERecipientContext;
import io.netty.incubator.codec.hpke.KDF;
import io.netty.incubator.codec.hpke.KEM;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLHPKE;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLOHttpCryptoProvider;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class OHttpCryptoParametersTest {

    private static final byte KEY_ID = 0x66;
    // Known-length GET https://example.com/ with empty field section, content and trailer section.
    private static final byte[] REQUEST = ByteBufUtil.decodeHexDump(
            "00034745540568747470730b6578616d706c652e636f6d012f000000");
    private static final byte[] RESPONSE = ByteBufUtil.decodeHexDump("0140c8");

    private static final OHttpCryptoParameters INFO_SUFFIX = OHttpCryptoParameters.newBuilder()
            .setInfoSuffix(bytes("info suffix"))
            .build();
    private static final OHttpCryptoParameters REQUEST_AAD = OHttpCryptoParameters.newBuilder()
            .setRequestAad(bytes("request aad"))
            .build();
    private static final OHttpCryptoParameters PSK = OHttpCryptoParameters.newBuilder()
            .setPsk(bytes("0123456789abcdef0123456789abcdef"), bytes("psk id"))
            .build();
    private static final OHttpCryptoParameters ALL = OHttpCryptoParameters.newBuilder()
            .setInfoSuffix(bytes("info suffix"))
            .setRequestAad(bytes("request aad"))
            .setPsk(bytes("0123456789abcdef0123456789abcdef"), bytes("psk id"))
            .build();

    private static final class ProviderArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            List<Arguments> arguments = new ArrayList<>();
            for (KEM kem : new KEM[] { KEM.X25519_SHA256, KEM.XWING }) {
                for (OHttpCryptoParameters parameters : new OHttpCryptoParameters[] {
                        OHttpCryptoParameters.DEFAULT, INFO_SUFFIX, REQUEST_AAD, PSK, ALL }) {
                    arguments.add(Arguments.of(BouncyCastleOHttpCryptoProvider.INSTANCE,
                            BouncyCastleOHttpCryptoProvider.INSTANCE, kem, parameters));
                    if (BoringSSLHPKE.isAvailable()) {
                        arguments.add(Arguments.of(BoringSSLOHttpCryptoProvider.INSTANCE,
                                BoringSSLOHttpCryptoProvider.INSTANCE, kem, parameters));
                        arguments.add(Arguments.of(BouncyCastleOHttpCryptoProvider.INSTANCE,
                                BoringSSLOHttpCryptoProvider.INSTANCE, kem, parameters));
                        arguments.add(Arguments.of(BoringSSLOHttpCryptoProvider.INSTANCE,
                                BouncyCastleOHttpCryptoProvider.INSTANCE, kem, parameters));
                    }
                }
            }
            return arguments.stream();
        }
    }

    private static final class MismatchArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            OHttpCryptoParameters otherInfoSuffix = OHttpCryptoParameters.newBuilder()
                    .setInfoSuffix(bytes("other info suffix"))
                    .build();
            OHttpCryptoParameters otherRequestAad = OHttpCryptoParameters.newBuilder()
                    .setRequestAad(bytes("other request aad"))
                    .build();
            OHttpCryptoParameters otherPsk = OHttpCryptoParameters.newBuilder()
                    .setPsk(bytes("fedcba9876543210fedcba9876543210"), bytes("psk id"))
                    .build();
            OHttpCryptoParameters otherPskId = OHttpCryptoParameters.newBuilder()
                    .setPsk(bytes("0123456789abcdef0123456789abcdef"), bytes("other psk id"))
                    .build();
            return Stream.of(
                    Arguments.of(INFO_SUFFIX, OHttpCryptoParameters.DEFAULT),
                    Arguments.of(OHttpCryptoParameters.DEFAULT, INFO_SUFFIX),
                    Arguments.of(INFO_SUFFIX, otherInfoSuffix),
                    Arguments.of(REQUEST_AAD, OHttpCryptoParameters.DEFAULT),
                    Arguments.of(OHttpCryptoParameters.DEFAULT, REQUEST_AAD),
                    Arguments.of(REQUEST_AAD, otherRequestAad),
                    Arguments.of(PSK, OHttpCryptoParameters.DEFAULT),
                    Arguments.of(OHttpCryptoParameters.DEFAULT, PSK),
                    Arguments.of(PSK, otherPsk),
                    Arguments.of(PSK, otherPskId));
        }
    }

    @BeforeAll
    public static void setupAll() {
        System.setProperty("io.netty.leakDetection.level", "paranoid");
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static boolean supports(OHttpCryptoProvider provider, KEM kem, OHttpCryptoParameters parameters) {
        return provider.isSupported(kem) && provider.isSupported(parameters.mode());
    }

    private static OHttpServerKeys newServerKeys(OHttpCryptoProvider provider, KEM kem) throws CryptoException {
        return new OHttpServerKeys(OHttpKey.newPrivateKey(KEY_ID, kem,
                Collections.singletonList(OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)),
                provider.newRandomPrivateKey(kem)));
    }

    private static OHttpCryptoSender newSender(OHttpCryptoProvider provider, OHttpServerKeys serverKeys,
                                               OHttpCiphersuite ciphersuite, OHttpCryptoParameters parameters) {
        AsymmetricKeyParameter publicKey = provider.deserializePublicKey(
                ciphersuite.kem(), serverKeys.getKeyPair(ciphersuite).publicParameters().encoded());
        return OHttpCryptoSender.newBuilder()
                .setOHttpCryptoProvider(provider)
                .setConfiguration(OHttpVersionDraft.INSTANCE)
                .setCiphersuite(ciphersuite)
                .setReceiverPublicKey(publicKey)
                .setCryptoParameters(parameters)
                .build();
    }

    /**
     * Encrypts {@link #REQUEST} and returns the encapsulated request.
     */
    private static ByteBuf encryptRequest(OHttpCryptoSender sender) throws CryptoException {
        ByteBuf encapsulated = Unpooled.buffer();
        ByteBuf request = Unpooled.wrappedBuffer(REQUEST);
        try {
            sender.writeHeader(encapsulated);
            sender.encrypt(UnpooledByteBufAllocator.DEFAULT, request, request.readableBytes(), true, encapsulated);
            return encapsulated;
        } finally {
            request.release();
        }
    }

    /*
     * Use values from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.2
     */
    @Test
    public void testPskTestVector() throws CryptoException {
        OHttpCryptoProvider provider = BouncyCastleOHttpCryptoProvider.INSTANCE;
        AsymmetricCipherKeyPair kpR = provider.deserializePrivateKey(KEM.X25519_SHA256,
                ByteBufUtil.decodeHexDump("c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd"),
                ByteBufUtil.decodeHexDump("9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366"));
        HPKERecipientContext context = provider.setupHPKEPskR(KEM.X25519_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128,
                ByteBufUtil.decodeHexDump("0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b"),
                kpR,
                ByteBufUtil.decodeHexDump("4f6465206f6e2061204772656369616e2055726e"),
                ByteBufUtil.decodeHexDump("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82"),
                ByteBufUtil.decodeHexDump("456e6e796e20447572696e206172616e204d6f726961"));
        ByteBuf aad = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump("436f756e742d30"));
        ByteBuf ct = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(
                "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea"));
        ByteBuf pt = Unpooled.buffer();
        try {
            context.open(UnpooledByteBufAllocator.DEFAULT, aad, ct, pt);
            assertEquals("4265617574792069732074727574682c20747275746820626561757479", ByteBufUtil.hexDump(pt));
            assertEquals("dff17af354c8b41673567db6259fd6029967b4e1aad13023c2ae5df8f4f43bf6",
                    ByteBufUtil.hexDump(context.export(new byte[0], 32)));
        } finally {
            context.close();
            aad.release();
            ct.release();
            pt.release();
        }
    }

    @Test
    public void testDefaultModeSupport() {
        OHttpCryptoProvider provider = new OHttpCryptoProvider() {
            @Override
            public io.netty.incubator.codec.hpke.AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
                throw new UnsupportedOperationException();
            }

            @Override
            public io.netty.incubator.codec.hpke.HPKESenderContext setupHPKEBaseS(
                    KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR, byte[] info,
                    AsymmetricCipherKeyPair kpE) {
                throw new UnsupportedOperationException();
            }

            @Override
            public HPKERecipientContext setupHPKEBaseR(KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                                       AsymmetricCipherKeyPair skR, byte[] info) {
                throw new UnsupportedOperationException();
            }

            @Override
            public AsymmetricCipherKeyPair deserializePrivateKey(KEM kem, byte[] privateKeyBytes,
                                                                 byte[] publicKeyBytes) {
                throw new UnsupportedOperationException();
            }

            @Override
            public AsymmetricKeyParameter deserializePublicKey(KEM kem, byte[] publicKeyBytes) {
                throw new UnsupportedOperationException();
            }

            @Override
            public AsymmetricCipherKeyPair newRandomPrivateKey(KEM kem) {
                throw new UnsupportedOperationException();
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
        };
        assertTrue(provider.isSupported(HPKEMode.BASE));
        assertFalse(provider.isSupported(HPKEMode.PSK));
        assertFalse(provider.isSupported(HPKEMode.AUTH));
        assertFalse(provider.isSupported(HPKEMode.AUTH_PSK));
        assertThrows(UnsupportedOperationException.class, () -> provider.setupHPKEPskS(
                KEM.X25519_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, null, new byte[0], new byte[1], new byte[1]));
        assertThrows(UnsupportedOperationException.class, () -> provider.setupHPKEPskR(
                KEM.X25519_SHA256, KDF.HKDF_SHA256, AEAD.AES_GCM128, new byte[32], null, new byte[0],
                new byte[1], new byte[1]));
    }

    @Test
    public void testModeSupport() {
        assertTrue(BouncyCastleOHttpCryptoProvider.INSTANCE.isSupported(HPKEMode.BASE));
        assertTrue(BouncyCastleOHttpCryptoProvider.INSTANCE.isSupported(HPKEMode.PSK));
        assertFalse(BouncyCastleOHttpCryptoProvider.INSTANCE.isSupported(HPKEMode.AUTH));
        assertFalse(BouncyCastleOHttpCryptoProvider.INSTANCE.isSupported(HPKEMode.AUTH_PSK));
        assertFalse(BouncyCastleOHttpCryptoProvider.INSTANCE.isSupported((HPKEMode) null));

        assumeTrue(BoringSSLHPKE.isAvailable());
        assertTrue(BoringSSLOHttpCryptoProvider.INSTANCE.isSupported(HPKEMode.BASE));
        assertFalse(BoringSSLOHttpCryptoProvider.INSTANCE.isSupported(HPKEMode.PSK));
    }

    @Test
    public void testBuilder() {
        assertArrayEquals(new byte[0], OHttpCryptoParameters.DEFAULT.infoSuffix());
        assertNull(OHttpCryptoParameters.DEFAULT.requestAad());
        assertNull(OHttpCryptoParameters.DEFAULT.psk());
        assertNull(OHttpCryptoParameters.DEFAULT.pskId());
        assertEquals(HPKEMode.BASE, OHttpCryptoParameters.DEFAULT.mode());

        byte[] psk = bytes("psk");
        OHttpCryptoParameters parameters = OHttpCryptoParameters.newBuilder()
                .setPsk(psk, bytes("psk id"))
                .build();
        assertEquals(HPKEMode.PSK, parameters.mode());
        assertArrayEquals(bytes("psk"), parameters.psk());
        assertArrayEquals(bytes("psk id"), parameters.pskId());

        // Values are copied.
        psk[0] = 'x';
        assertArrayEquals(bytes("psk"), parameters.psk());
        assertNotSame(parameters.psk(), parameters.psk());

        OHttpCryptoParameters.Builder builder = OHttpCryptoParameters.newBuilder();
        assertThrows(IllegalArgumentException.class, () -> builder.setPsk(new byte[0], bytes("psk id")));
        assertThrows(IllegalArgumentException.class, () -> builder.setPsk(bytes("psk"), new byte[0]));
        assertThrows(NullPointerException.class, () -> builder.setPsk(null, bytes("psk id")));
        assertThrows(NullPointerException.class, () -> builder.setPsk(bytes("psk"), null));
        assertThrows(NullPointerException.class, () -> builder.setInfoSuffix(null));
        assertThrows(NullPointerException.class, () -> builder.setRequestAad(null));
    }

    @Test
    public void testCreateInfo() {
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite((byte) 1, KEM.X25519_SHA256, KDF.HKDF_SHA256,
                AEAD.AES_GCM128);
        assertEquals("6d6573736167652f626874747020726571756573740001002000010001",
                ByteBufUtil.hexDump(OHttpCrypto.createInfo(ciphersuite,
                        OHttpVersionDraft.INSTANCE.requestExportContext(), new byte[0])));
        assertEquals("6d6573736167652f626874747020726571756573740001002000010001abcd",
                ByteBufUtil.hexDump(OHttpCrypto.createInfo(ciphersuite,
                        OHttpVersionDraft.INSTANCE.requestExportContext(), new byte[] { (byte) 0xab, (byte) 0xcd })));
    }

    @Test
    public void testRequestAadNotSupportedWithFinalAad() throws CryptoException {
        OHttpCryptoProvider provider = BouncyCastleOHttpCryptoProvider.INSTANCE;
        OHttpServerKeys serverKeys = newServerKeys(provider, KEM.X25519_SHA256);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, KEM.X25519_SHA256, KDF.HKDF_SHA256,
                AEAD.CHACHA20_POLY1305);
        AsymmetricKeyParameter publicKey = provider.deserializePublicKey(
                KEM.X25519_SHA256, serverKeys.getKeyPair(ciphersuite).publicParameters().encoded());

        assertThrows(IllegalArgumentException.class, () -> OHttpCryptoSender.newBuilder()
                .setOHttpCryptoProvider(provider)
                .setConfiguration(OHttpVersionChunkDraft.INSTANCE)
                .setCiphersuite(ciphersuite)
                .setReceiverPublicKey(publicKey)
                .setCryptoParameters(REQUEST_AAD)
                .build());
        assertThrows(IllegalArgumentException.class, () -> OHttpCryptoReceiver.newBuilder()
                .setOHttpCryptoProvider(provider)
                .setConfiguration(OHttpVersionChunkDraft.INSTANCE)
                .setCiphersuite(ciphersuite)
                .setPrivateKey(serverKeys.getKeyPair(ciphersuite))
                .setEncapsulatedKey(new byte[ciphersuite.encapsulatedKeyLength()])
                .setCryptoParameters(REQUEST_AAD)
                .build());
    }

    @ParameterizedTest
    @ArgumentsSource(ProviderArgumentsProvider.class)
    public void testCrypto(OHttpCryptoProvider senderProvider, OHttpCryptoProvider receiverProvider, KEM kem,
                           OHttpCryptoParameters parameters) throws CryptoException {
        assumeTrue(supports(senderProvider, kem, parameters));
        assumeTrue(supports(receiverProvider, kem, parameters));

        OHttpServerKeys serverKeys = newServerKeys(receiverProvider, kem);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, kem, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305);

        try (OHttpCryptoSender sender = newSender(senderProvider, serverKeys, ciphersuite, parameters)) {
            ByteBuf encapsulatedRequest = encryptRequest(sender);
            ByteBuf request = Unpooled.buffer();
            ByteBuf response = Unpooled.wrappedBuffer(RESPONSE);
            ByteBuf encapsulatedResponse = Unpooled.buffer();
            ByteBuf decryptedResponse = Unpooled.buffer();
            try {
                OHttpCiphersuite receivedCiphersuite = OHttpCiphersuite.decode(encapsulatedRequest);
                byte[] encapsulatedKey = new byte[receivedCiphersuite.encapsulatedKeyLength()];
                encapsulatedRequest.readBytes(encapsulatedKey);

                try (OHttpCryptoReceiver receiver = OHttpCryptoReceiver.newBuilder()
                        .setOHttpCryptoProvider(receiverProvider)
                        .setConfiguration(OHttpVersionDraft.INSTANCE)
                        .setPrivateKey(serverKeys.getKeyPair(receivedCiphersuite))
                        .setCiphersuite(receivedCiphersuite)
                        .setEncapsulatedKey(encapsulatedKey)
                        .setCryptoParameters(parameters)
                        .build()) {
                    receiver.decrypt(UnpooledByteBufAllocator.DEFAULT, encapsulatedRequest,
                            encapsulatedRequest.readableBytes(), true, request);
                    assertEquals(Unpooled.wrappedBuffer(REQUEST), request);

                    receiver.writeResponseNonce(encapsulatedResponse);
                    receiver.encrypt(UnpooledByteBufAllocator.DEFAULT, response, response.readableBytes(), true,
                            encapsulatedResponse);
                }

                assertTrue(sender.readResponseNonce(encapsulatedResponse));
                sender.decrypt(UnpooledByteBufAllocator.DEFAULT, encapsulatedResponse,
                        encapsulatedResponse.readableBytes(), true, decryptedResponse);
                assertEquals(Unpooled.wrappedBuffer(RESPONSE), decryptedResponse);
            } finally {
                encapsulatedRequest.release();
                request.release();
                response.release();
                encapsulatedResponse.release();
                decryptedResponse.release();
            }
        }
    }

    @ParameterizedTest
    @ArgumentsSource(MismatchArgumentsProvider.class)
    public void testCryptoMismatch(OHttpCryptoParameters senderParameters,
                                   OHttpCryptoParameters receiverParameters) throws CryptoException {
        OHttpCryptoProvider provider = BouncyCastleOHttpCryptoProvider.INSTANCE;
        OHttpServerKeys serverKeys = newServerKeys(provider, KEM.X25519_SHA256);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, KEM.X25519_SHA256, KDF.HKDF_SHA256,
                AEAD.CHACHA20_POLY1305);

        try (OHttpCryptoSender sender = newSender(provider, serverKeys, ciphersuite, senderParameters)) {
            ByteBuf encapsulatedRequest = encryptRequest(sender);
            ByteBuf request = Unpooled.buffer();
            try {
                OHttpCiphersuite.decode(encapsulatedRequest);
                byte[] encapsulatedKey = new byte[ciphersuite.encapsulatedKeyLength()];
                encapsulatedRequest.readBytes(encapsulatedKey);

                try (OHttpCryptoReceiver receiver = OHttpCryptoReceiver.newBuilder()
                        .setOHttpCryptoProvider(provider)
                        .setConfiguration(OHttpVersionDraft.INSTANCE)
                        .setPrivateKey(serverKeys.getKeyPair(ciphersuite))
                        .setCiphersuite(ciphersuite)
                        .setEncapsulatedKey(encapsulatedKey)
                        .setCryptoParameters(receiverParameters)
                        .build()) {
                    assertThrows(CryptoException.class, () -> receiver.decrypt(UnpooledByteBufAllocator.DEFAULT,
                            encapsulatedRequest, encapsulatedRequest.readableBytes(), true, request));
                }
            } finally {
                encapsulatedRequest.release();
                request.release();
            }
        }
    }

    @ParameterizedTest
    @ArgumentsSource(ProviderArgumentsProvider.class)
    public void testServerCodec(OHttpCryptoProvider senderProvider, OHttpCryptoProvider receiverProvider, KEM kem,
                                OHttpCryptoParameters parameters) throws Exception {
        assumeTrue(supports(senderProvider, kem, parameters));
        assumeTrue(supports(receiverProvider, kem, parameters));

        OHttpServerKeys serverKeys = newServerKeys(receiverProvider, kem);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, kem, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305);
        List<OHttpCiphersuite> ciphersuites = new ArrayList<>();
        List<HttpRequest> outerRequests = new ArrayList<>();
        EmbeddedChannel channel = new EmbeddedChannel(new OHttpServerCodec(receiverProvider, serverKeys) {
            @Override
            protected OHttpCryptoParameters cryptoParameters(
                    ChannelHandlerContext ctx, HttpRequest request, OHttpCiphersuite ciphersuite) {
                ciphersuites.add(ciphersuite);
                outerRequests.add(request);
                return parameters;
            }
        });

        try (OHttpCryptoSender sender = newSender(senderProvider, serverKeys, ciphersuite, parameters)) {
            HttpRequest outerRequest = newOuterRequest();
            assertFalse(channel.writeInbound(outerRequest));
            assertTrue(channel.writeInbound(new DefaultLastHttpContent(encryptRequest(sender))));

            assertEquals(Collections.singletonList(ciphersuite), ciphersuites);
            assertEquals(1, outerRequests.size());
            assertEquals("/ohttp", outerRequests.get(0).uri());
            assertEquals("value", outerRequests.get(0).headers().get("x-outer"));

            HttpRequest innerRequest = channel.readInbound();
            assertEquals(HttpMethod.GET, innerRequest.method());
            assertEquals("/", innerRequest.uri());
            LastHttpContent innerContent = channel.readInbound();
            innerContent.release();
            assertNull(channel.readInbound());

            assertTrue(channel.writeOutbound(new DefaultFullBinaryHttpResponse(
                    HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(bytes("body")))));
            HttpResponse outerResponse = channel.readOutbound();
            assertEquals(HttpResponseStatus.OK, outerResponse.status());
            assertEquals(OHttpConstants.RESPONSE_CONTENT_TYPE.toString(),
                    outerResponse.headers().get(HttpHeaderNames.CONTENT_TYPE));

            HttpContent encapsulatedResponse = channel.readOutbound();
            ByteBuf decryptedResponse = Unpooled.buffer();
            try {
                assertTrue(sender.readResponseNonce(encapsulatedResponse.content()));
                sender.decrypt(UnpooledByteBufAllocator.DEFAULT, encapsulatedResponse.content(),
                        encapsulatedResponse.content().readableBytes(), true, decryptedResponse);
                assertTrue(decryptedResponse.isReadable());
            } finally {
                encapsulatedResponse.release();
                decryptedResponse.release();
            }
            assertFalse(channel.finishAndReleaseAll());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @ParameterizedTest
    @ArgumentsSource(MismatchArgumentsProvider.class)
    public void testServerCodecMismatch(OHttpCryptoParameters senderParameters,
                                        OHttpCryptoParameters receiverParameters) throws Exception {
        OHttpCryptoProvider provider = BouncyCastleOHttpCryptoProvider.INSTANCE;
        assertBadRequest(provider, provider, senderParameters, receiverParameters);
    }

    @Test
    public void testServerCodecPskNotSupported() throws Exception {
        assumeTrue(BoringSSLHPKE.isAvailable());
        assertBadRequest(BouncyCastleOHttpCryptoProvider.INSTANCE, BoringSSLOHttpCryptoProvider.INSTANCE, PSK, PSK);
    }

    @Test
    public void testServerCodecCryptoParametersThrows() throws Exception {
        OHttpCryptoProvider provider = BouncyCastleOHttpCryptoProvider.INSTANCE;
        OHttpServerKeys serverKeys = newServerKeys(provider, KEM.X25519_SHA256);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, KEM.X25519_SHA256, KDF.HKDF_SHA256,
                AEAD.CHACHA20_POLY1305);
        EmbeddedChannel channel = new EmbeddedChannel(new OHttpServerCodec(provider, serverKeys) {
            @Override
            protected OHttpCryptoParameters cryptoParameters(
                    ChannelHandlerContext ctx, HttpRequest request, OHttpCiphersuite ciphersuite) {
                throw new IllegalStateException();
            }
        });
        try (OHttpCryptoSender sender = newSender(provider, serverKeys, ciphersuite, OHttpCryptoParameters.DEFAULT)) {
            assertFalse(channel.writeInbound(newOuterRequest()));
            assertFalse(channel.writeInbound(new DefaultLastHttpContent(encryptRequest(sender))));
            FullHttpResponse response = channel.readOutbound();
            assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
            assertTrue(response.release());
            assertFalse(channel.finishAndReleaseAll());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static void assertBadRequest(OHttpCryptoProvider senderProvider, OHttpCryptoProvider receiverProvider,
                                         OHttpCryptoParameters senderParameters,
                                         OHttpCryptoParameters receiverParameters) throws Exception {
        OHttpServerKeys serverKeys = newServerKeys(receiverProvider, KEM.X25519_SHA256);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, KEM.X25519_SHA256, KDF.HKDF_SHA256,
                AEAD.CHACHA20_POLY1305);
        EmbeddedChannel channel = new EmbeddedChannel(new OHttpServerCodec(receiverProvider, serverKeys) {
            @Override
            protected OHttpCryptoParameters cryptoParameters(
                    ChannelHandlerContext ctx, HttpRequest request, OHttpCiphersuite ciphersuite) {
                return receiverParameters;
            }
        });
        try (OHttpCryptoSender sender = newSender(senderProvider, serverKeys, ciphersuite, senderParameters)) {
            assertFalse(channel.writeInbound(newOuterRequest()));
            assertFalse(channel.writeInbound(new DefaultLastHttpContent(encryptRequest(sender))));

            // The request could not be decrypted, so the response is not encapsulated.
            FullHttpResponse response = channel.readOutbound();
            assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
            assertNull(response.headers().get(HttpHeaderNames.CONTENT_TYPE));
            assertTrue(response.release());
            assertNull(channel.readInbound());
            assertFalse(channel.finishAndReleaseAll());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static HttpRequest newOuterRequest() {
        HttpRequest request = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/ohttp");
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, OHttpConstants.REQUEST_CONTENT_TYPE);
        request.headers().set("x-outer", "value");
        return request;
    }

    @ParameterizedTest
    @ArgumentsSource(ProviderArgumentsProvider.class)
    public void testCodecs(OHttpCryptoProvider clientProvider, OHttpCryptoProvider serverProvider, KEM kem,
                           OHttpCryptoParameters parameters) throws Exception {
        assumeTrue(supports(clientProvider, kem, parameters));
        assumeTrue(supports(serverProvider, kem, parameters));

        OHttpServerKeys serverKeys = newServerKeys(serverProvider, kem);
        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(KEY_ID, kem, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305);
        AsymmetricKeyParameter publicKey = clientProvider.deserializePublicKey(
                kem, serverKeys.getKeyPair(ciphersuite).publicParameters().encoded());
        OHttpClientCodec.EncapsulationParameters encapsulationParameters =
                OHttpClientCodec.EncapsulationParameters.newInstance(
                        OHttpVersionDraft.INSTANCE, ciphersuite, publicKey, "/ohttp", "authority");

        EmbeddedChannel client = new EmbeddedChannel(new HttpClientCodec(), new OHttpClientCodecBuilder()
                .setProvider(clientProvider)
                .setEncapsulationFunction(request -> new OHttpClientCodec.EncapsulationParameters() {
                    @Override
                    public String outerRequestUri() {
                        return encapsulationParameters.outerRequestUri();
                    }

                    @Override
                    public String outerRequestAuthority() {
                        return encapsulationParameters.outerRequestAuthority();
                    }

                    @Override
                    public HttpHeaders outerRequestHeaders() {
                        return new DefaultHttpHeaders().set("x-outer", "value");
                    }

                    @Override
                    public OHttpCiphersuite ciphersuite() {
                        return encapsulationParameters.ciphersuite();
                    }

                    @Override
                    public AsymmetricKeyParameter serverPublicKey() {
                        return encapsulationParameters.serverPublicKey();
                    }

                    @Override
                    public OHttpVersion version() {
                        return encapsulationParameters.version();
                    }

                    @Override
                    public OHttpCryptoParameters cryptoParameters() {
                        return parameters;
                    }
                })
                .build());
        EmbeddedChannel server = new EmbeddedChannel(new HttpServerCodec(),
                new OHttpServerCodec(serverProvider, serverKeys) {
                    @Override
                    protected OHttpCryptoParameters cryptoParameters(
                            ChannelHandlerContext ctx, HttpRequest request, OHttpCiphersuite ciphersuite) {
                        // Only use the parameters if the outer request carries the expected header.
                        return "value".equals(request.headers().get("x-outer")) ?
                                parameters : OHttpCryptoParameters.DEFAULT;
                    }
                });

        try {
            assertTrue(client.writeOutbound(new DefaultFullBinaryHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST,
                    "https", "authority", "/test", Unpooled.copiedBuffer(bytes("request body")))));
            transfer(client, server);

            HttpRequest innerRequest = server.readInbound();
            assertEquals("/test", innerRequest.uri());
            assertEquals("request body", readContent(server));

            assertTrue(server.writeOutbound(new DefaultFullBinaryHttpResponse(
                    HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(bytes("response body")))));
            transfer(server, client);

            HttpResponse innerResponse = client.readInbound();
            assertEquals(HttpResponseStatus.OK, innerResponse.status());
            assertEquals("response body", readContent(client));
            assertFalse(client.finishAndReleaseAll());
            assertFalse(server.finishAndReleaseAll());
        } finally {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
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

    private static String readContent(EmbeddedChannel channel) {
        StringBuilder sb = new StringBuilder();
        for (;;) {
            HttpObject msg = channel.readInbound();
            assertInstanceOf(HttpContent.class, msg);
            try {
                sb.append(((HttpContent) msg).content().toString(StandardCharsets.US_ASCII));
                if (msg instanceof LastHttpContent) {
                    return sb.toString();
                }
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }
    }
}
