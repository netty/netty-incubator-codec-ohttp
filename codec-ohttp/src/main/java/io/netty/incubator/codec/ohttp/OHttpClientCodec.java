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

import io.netty.handler.codec.MessageToMessageCodec;
import io.netty.incubator.codec.hpke.AsymmetricKeyParameter;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.util.AsciiString;
import io.netty.util.ReferenceCountUtil;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.function.Function;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;
import static java.util.Objects.requireNonNull;

/**
 * {@link MessageToMessageCodec} that HTTP clients can use to encrypt outgoing HTTP requests into
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">Oblivious HTTP</a> requests
 * and decrypt incoming OHTTP responses.
 * <br><br>
 * Both incoming and outgoing messages are {@link HttpObject}s.
 */
public final class OHttpClientCodec extends MessageToMessageCodec<HttpObject, HttpObject> {

    private final Deque<OHttpRequestResponseContextHolder> contextHolders = new ArrayDeque<>();

    private static final class OHttpRequestResponseContextHolder {

        static final OHttpRequestResponseContextHolder NONE = new OHttpRequestResponseContextHolder(null);

        final OHttpRequestResponseContext handler;

        OHttpRequestResponseContextHolder(OHttpRequestResponseContext handler) {
            this.handler = handler;
        }

        void destroy() {
            if (handler != null) {
                handler.destroy();
            }
        }
    }

    private final OHttpCryptoProvider provider;
    private final Function<HttpRequest, EncapsulationParameters> encapsulationFunc;

    private ByteBuf cumulationBuffer = Unpooled.EMPTY_BUFFER;
    private boolean destroyed;

    /**
     * Creates a new instance
     *
     * @param provider        the {@link OHttpCryptoProvider} to use for all the crypto.
     * @param encapsulationFunc the {@link Function} that will be used to return the correct
     *                          {@link EncapsulationParameters} for a given {@link HttpRequest}.
     *                          If {@link Function} returns {@code null} no encapsulation will
     *                          take place.
     */
    public OHttpClientCodec(OHttpCryptoProvider provider, Function<HttpRequest,
            EncapsulationParameters> encapsulationFunc) {
        this.provider = requireNonNull(provider, "provider");
        this.encapsulationFunc = requireNonNull(encapsulationFunc, "encapsulationFunc");
    }

    /**
     * Parameters that control the OHTTP encapsulation of an HTTP request.
     */
    public interface EncapsulationParameters {

        /**
         * @return URI for the outer HTTP request that.
         */
        String outerRequestUri();

        /**
         * @return Authority for outer HTTP request.
         */
        String outerRequestAuthority();

        /**
         * Create the headers for the other HTTP request.
         * @return  headers
         */
        default HttpHeaders outerRequestHeaders() {
            return new DefaultHttpHeaders();
        }

        /**
         * Return the {@link OHttpCiphersuite}s to use.
         *
         * @return the ciphersuites.
         */
        OHttpCiphersuite ciphersuite();

        /**
         * The public key bytes of the server.
         *
         * @return bytes.
         */
        AsymmetricKeyParameter serverPublicKey();

        /**
         * The {@link OHttpVersion} to use.
         *
         * @return the version.
         */
        OHttpVersion version();

        /**
         * Create a simple {@link EncapsulationParameters} instance.
         *
         * @param version               the version to use.
         * @param ciphersuite           the suite to use.
         * @param serverPublicKey  the public key to use.
         * @param outerRequestUri       the outer requst uri.
         * @param outerRequestAuthority the authority.
         * @return                      created params.
         */
        static EncapsulationParameters newInstance(OHttpVersion version, OHttpCiphersuite ciphersuite,
                                                 AsymmetricKeyParameter serverPublicKey, String outerRequestUri,
                                                   String outerRequestAuthority) {
            requireNonNull(version, "version");
            requireNonNull(ciphersuite, "ciphersuite");
            requireNonNull(serverPublicKey, "serverPublicKey");
            requireNonNull(outerRequestUri, "outerRequestUri");
            requireNonNull(outerRequestAuthority, "outerRequestAuthority");
            return new EncapsulationParameters() {
                @Override
                public String outerRequestUri() {
                    return outerRequestUri;
                }

                @Override
                public String outerRequestAuthority() {
                    return outerRequestAuthority;
                }

                @Override
                public OHttpCiphersuite ciphersuite() {
                    return ciphersuite;
                }

                @Override
                public AsymmetricKeyParameter serverPublicKey() {
                    return serverPublicKey;
                }

                @Override
                public OHttpVersion version() {
                    return version;
                }
            };
        }
    }

    @Override
    public boolean isSharable() {
        return false;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, HttpObject msg, List<Object> out) {
        if (destroyed) {
            throw new IllegalStateException("Already destroyed");
        }
        try {
            assert !contextHolders.isEmpty();
            OHttpRequestResponseContext ohttpContext = contextHolders.peekFirst().handler;
            if (msg instanceof HttpResponse) {
                HttpResponse resp = (HttpResponse) msg;
                if (ohttpContext != null) {
                    if (resp.status() != HttpResponseStatus.OK) {
                        throw new DecoderException("OHTTP response status is not OK");
                    }
                    String contentTypeValue = resp.headers().get(HttpHeaderNames.CONTENT_TYPE);
                    AsciiString expectedContentType = ohttpContext.version().responseContentType();
                    if (!expectedContentType.contentEqualsIgnoreCase(contentTypeValue)) {
                        throw new DecoderException("OHTTP response has unexpected content type");
                    }
                }
            }

            boolean isLast = msg instanceof LastHttpContent;
            if (ohttpContext != null) {
                if (msg instanceof HttpContent) {
                    ByteBuf content = ((HttpContent) msg).content();
                    cumulationBuffer = MERGE_CUMULATOR.cumulate(content.alloc(), cumulationBuffer, content.retain());
                    ohttpContext.parse(cumulationBuffer, isLast, out);
                }
            } else {
                out.add(ReferenceCountUtil.retain(msg));
            }
            if (isLast) {
                OHttpRequestResponseContextHolder h = contextHolders.pollFirst();
                assert h != null;
                h.destroy();
            }
        } catch (CryptoException e) {
            throw new DecoderException("failed to decrypt bytes", e);
        }
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, HttpObject msg, List<Object> out) {
        try {
            if (msg instanceof HttpRequest) {
                HttpRequest innerRequest = (HttpRequest) msg;
                EncapsulationParameters encapsulation = encapsulationFunc.apply(innerRequest);
                if (encapsulation != null) {
                    OHttpClientRequestResponseContext oHttpContext =
                            new OHttpClientRequestResponseContext(encapsulation, provider);
                    HttpHeaders outerHeaders = encapsulation.outerRequestHeaders();
                    DefaultHttpRequest outerRequest = new DefaultHttpRequest(
                            innerRequest.protocolVersion(),
                            HttpMethod.POST,
                            encapsulation.outerRequestUri(), outerHeaders);
                    outerHeaders
                            .set(HttpHeaderNames.HOST, encapsulation.outerRequestAuthority())
                            .add(HttpHeaderNames.CONTENT_TYPE, oHttpContext.version().requestContentType());
                    HttpUtil.setTransferEncodingChunked(outerRequest, true);

                    contextHolders.addLast(new OHttpRequestResponseContextHolder(oHttpContext));

                    out.add(outerRequest);
                } else {
                    contextHolders.addLast(OHttpRequestResponseContextHolder.NONE);
                }
            }

            assert !contextHolders.isEmpty();
            OHttpRequestResponseContext contentHandler = contextHolders.peekLast().handler;
            if (contentHandler != null) {
                ByteBuf contentBytes = ctx.alloc().buffer();
                try {
                    boolean isLast = msg instanceof LastHttpContent;
                    contentHandler.serialize(msg, contentBytes);
                    // Use the correct version of HttpContent depending on if it was the last or not.
                    HttpContent content = isLast ? new DefaultLastHttpContent(contentBytes) :
                            new DefaultHttpContent(contentBytes);
                    out.add(content);
                    contentBytes = null;
                } finally {
                    if (contentBytes != null) {
                        contentBytes.release();
                    }
                }
            } else {
                // Retain the msg as MessageToMessageEncoder will call release on it.
                out.add(ReferenceCountUtil.retain(msg));
            }
        } catch (CryptoException e) {
            throw new EncoderException("failed to encrypt bytes", e);
        }
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        if (!destroyed) {
            destroyed = true;
            cumulationBuffer.release();
            cumulationBuffer = Unpooled.EMPTY_BUFFER;

            for (;;) {
                OHttpRequestResponseContextHolder h = contextHolders.poll();
                if (h == null) {
                    break;
                }
                h.destroy();
            }
        }
        super.handlerRemoved(ctx);
    }

    private static final class OHttpClientRequestResponseContext extends OHttpRequestResponseContext {

        private final OHttpCryptoSender sender;

        OHttpClientRequestResponseContext(EncapsulationParameters parameters, OHttpCryptoProvider provider) {
            super(parameters.version());
            this.sender = OHttpCryptoSender.newBuilder()
                    .setOHttpCryptoProvider(provider)
                    .setConfiguration(parameters.version())
                    .setCiphersuite(requireNonNull(parameters.ciphersuite(), "ciphersuite"))
                    .setReceiverPublicKey(requireNonNull(parameters.serverPublicKey(), "serverPublicKey"))
                    .build();
        }

        @Override
        public boolean decodePrefix(ByteBuf in) {
            return sender.readResponseNonce(in);
        }

        @Override
        protected void decryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out)
                throws CryptoException {
            sender.decrypt(chunk, chunkLength, isFinal, out);
        }

        @Override
        public void encodePrefix(ByteBuf out) {
            sender.writeHeader(out);
        }

        @Override
        protected void encryptChunk(ByteBuf chunk, int chunkLength, boolean isFinal, ByteBuf out)
                throws CryptoException {
            sender.encrypt(chunk, chunkLength, isFinal, out);
        }

        @Override
        void destroyCrypto() {
            sender.close();
        }
    };
}
