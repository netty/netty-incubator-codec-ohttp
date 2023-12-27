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

import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLHPKE;
import io.netty.incubator.codec.hpke.boringssl.BoringSSLOHttpCryptoProvider;
import io.netty.incubator.codec.hpke.bouncycastle.BouncyCastleOHttpCryptoProvider;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DecoderException;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import io.netty.incubator.codec.hpke.AEAD;

import io.netty.incubator.codec.hpke.KDF;

import io.netty.incubator.codec.hpke.KEM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class OHttpCryptoTest {

    private static final class OHttpCryptoProviderArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            List<Arguments> arguments = new ArrayList<>();
            arguments.add(Arguments.of(BouncyCastleOHttpCryptoProvider.INSTANCE, BouncyCastleOHttpCryptoProvider.INSTANCE));
            if (BoringSSLHPKE.isAvailable()) {
                arguments.add(Arguments.of(BoringSSLOHttpCryptoProvider.INSTANCE, BoringSSLOHttpCryptoProvider.INSTANCE));
                arguments.add(Arguments.of(BouncyCastleOHttpCryptoProvider.INSTANCE, BoringSSLOHttpCryptoProvider.INSTANCE));
                arguments.add(Arguments.of(BoringSSLOHttpCryptoProvider.INSTANCE, BouncyCastleOHttpCryptoProvider.INSTANCE));
            }
            return arguments.stream();
        }
    }

    static AsymmetricCipherKeyPair createX25519KeyPair(OHttpCryptoProvider cryptoProvider, String privateKeyHexBytes)  {
        X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(
                ByteBufUtil.decodeHexDump(privateKeyHexBytes));
        X25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return cryptoProvider.deserializePrivateKey(
                KEM.X25519_SHA256, privateKey.getEncoded(), publicKey.getEncoded());
    }

    /*
     * Use values from https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html#name-complete-example-of-a-reque
     */
    @ParameterizedTest
    @ArgumentsSource(value = OHttpCryptoProviderArgumentsProvider.class)
    public void testCryptoVectors(OHttpCryptoProvider senderProvider, OHttpCryptoProvider receiverProvider) throws DecoderException, CryptoException {
        byte keyId = 1;
        AsymmetricCipherKeyPair kpR = createX25519KeyPair(receiverProvider, "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        AsymmetricCipherKeyPair kpE = createX25519KeyPair(senderProvider, "bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73");
        byte[] request = ByteBufUtil.decodeHexDump("00034745540568747470730b6578616d706c652e636f6d012f");
        byte[] response = ByteBufUtil.decodeHexDump("0140c8");

        OHttpServerKeys serverKeys = new OHttpServerKeys(
                OHttpKey.newPrivateKey(
                        keyId,
                        KEM.X25519_SHA256,
                        Arrays.asList(
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.AES_GCM128),
                                OHttpKey.newCipher(KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)),
                        kpR));

        // Key configuration encoding

        ByteBuf encodedKeyConfiguration = Unpooled.buffer();
        try {
            serverKeys.encodePublicKeys(encodedKeyConfiguration);
            assertEquals("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003", ByteBufUtil.hexDump(encodedKeyConfiguration));

            // Key configuration decoding

            OHttpServerPublicKeys clientKeys = OHttpServerPublicKeys.decode(encodedKeyConfiguration);
            assertEquals(1, clientKeys.keys().size());
            OHttpKey.PublicKey key = clientKeys.key(keyId);
            assertNotNull(key);
        } finally {
            encodedKeyConfiguration.release();
        }

        // Sender encodes request

        OHttpCiphersuite ciphersuite = new OHttpCiphersuite(keyId,
                KEM.X25519_SHA256,
                KDF.HKDF_SHA256,
                AEAD.AES_GCM128);

        assertEquals("6d6573736167652f626874747020726571756573740001002000010001",
                ByteBufUtil.hexDump(ciphersuite.createInfo(OHttpVersionDraft.INSTANCE.requestExportContext())));

        AsymmetricKeyParameter receiverPublicKey
                = senderProvider.deserializePublicKey(KEM.X25519_SHA256, kpR.publicParameters().encoded());

        try (OHttpCryptoSender sender = OHttpCryptoSender.newBuilder()
                .setOHttpCryptoProvider(senderProvider)
                .setConfiguration(OHttpVersionDraft.INSTANCE)
                .setCiphersuite(ciphersuite)
                .setReceiverPublicKey(receiverPublicKey)
                .setForcedEphemeralKeyPair(kpE)
                .build()) {

            ByteBuf encrypted = Unpooled.buffer();
            ByteBuf encodedRequest = Unpooled.buffer();
            ByteBuf decodedRequest = Unpooled.buffer();
            ByteBuf requestBuffer = Unpooled.wrappedBuffer(request);
            ByteBuf enc = Unpooled.buffer();
            ByteBuf responseBuffer = Unpooled.wrappedBuffer(response);
            ByteBuf encodedResponse = Unpooled.buffer();
            ByteBuf decodedResponse = Unpooled.buffer();
            try {
                sender.encrypt(Unpooled.wrappedBuffer(request), request.length, true, encrypted);
                sender.writeHeader(encodedRequest);
                encodedRequest.writeBytes(encrypted);

                assertEquals(
                        "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992"
                                + "e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525",
                        ByteBufUtil.hexDump(encodedRequest));
                // Receiver decodes request

                encodedRequest.readerIndex(0);
                OHttpCiphersuite receiverCiphersuite = OHttpCiphersuite.decode(encodedRequest);
                byte[] receiverEncapsulatedKey = new byte[receiverCiphersuite.encapsulatedKeyLength()];
                encodedRequest.readBytes(receiverEncapsulatedKey);

                try (OHttpCryptoReceiver receiver = OHttpCryptoReceiver.newBuilder()
                        .setOHttpCryptoProvider(receiverProvider)
                        .setConfiguration(OHttpVersionDraft.INSTANCE)
                        .setSenderPrivateKey(serverKeys.getKeyPair(ciphersuite))
                        .setCiphersuite(receiverCiphersuite)
                        .setEncapsulatedKey(receiverEncapsulatedKey)
                        .setForcedResponseNonce(ByteBufUtil.decodeHexDump("c789e7151fcba46158ca84b04464910d"))
                        .build()) {

                    receiver.decrypt(encodedRequest, encodedRequest.readableBytes(), true, decodedRequest);
                    assertEquals(requestBuffer, decodedRequest);

                    // Receiver encodes response

                    receiver.encrypt(responseBuffer, response.length, true, enc);
                    receiver.writeResponseNonce(encodedResponse);
                    encodedResponse.writeBytes(enc);
                    assertEquals("c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd", ByteBufUtil.hexDump(encodedResponse));

                    // Sender decodes response

                    encodedResponse.readerIndex(0);
                    sender.readResponseNonce(encodedResponse);

                    sender.decrypt(encodedResponse, encodedResponse.readableBytes(), true, decodedResponse);
                    assertEquals(responseBuffer.readerIndex(0), decodedResponse);
                }
            } finally {
                encrypted.release();
                encodedRequest.release();
                decodedRequest.release();
                requestBuffer.release();
                enc.release();
                responseBuffer.release();
                encodedResponse.release();
                decodedResponse.release();
            }
        }
    }
}
