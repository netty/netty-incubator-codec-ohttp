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

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.codec.MessageToMessageCodec;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.incubator.codec.hpke.OHttpCryptoProvider;
import io.netty.util.ReferenceCountUtil;

import java.util.List;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;
import static java.util.Objects.requireNonNull;

/**
 * {@link MessageToMessageCodec} that HTTP servers can use to decrypt incoming
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">Oblivious HTTP</a> requests
 * and encrypt outgoing HTTP responses.
 * <br><br>
 * Both incoming and outgoing messages are {@link HttpObject}s.
 */
public class OHttpServerCodec extends MessageToMessageCodec<HttpObject, HttpObject> {

    private final OHttpCryptoProvider provider;
    private final OHttpServerKeys serverKeys;

    private HttpRequest request;
    private boolean sentResponse;
    private OHttpServerRequestResponseContext oHttpContext;
    private ByteBuf cumulationBuffer = Unpooled.EMPTY_BUFFER;
    private boolean destroyed;

    public OHttpServerCodec(OHttpCryptoProvider provider, OHttpServerKeys serverKeys) {
        this.provider = requireNonNull(provider, "provider");
        this.serverKeys = requireNonNull(serverKeys, "serverKeys");
    }

    /**
     * Select the correct {@link OHttpVersion} based on the content-type value or {@code null} if none
     * could be selected.
     *
     * @param contentTypeValue  the value of the content-type header.
     * @return                  the version or {@code null} if none could be selected.
     */
    protected OHttpVersion selectVersion(String contentTypeValue) {
        if (OHttpConstants.REQUEST_CONTENT_TYPE.contentEqualsIgnoreCase(contentTypeValue)) {
            return OHttpVersionDraft.INSTANCE;
        }
        if (OHttpConstants.CHUNKED_REQUEST_CONTENT_TYPE.contentEqualsIgnoreCase(contentTypeValue)) {
            return OHttpVersionChunkDraft.INSTANCE;
        }
        return null;
    }

    /**
     * Optional callback to report the outer HTTP request and response.
     * @param request Incoming {@link HttpRequest}.
     * @param response Outgoing {@link HttpResponse}.
     */
    protected void onResponse(
            @SuppressWarnings("unused") HttpRequest request, @SuppressWarnings("unused") HttpResponse response) {
        // NOOP.
    }

    @Override
    public final boolean isSharable() {
        return false;
    }

    @Override
    protected final void decode(ChannelHandlerContext ctx, HttpObject msg, List<Object> out) {
        if (destroyed) {
            throw new IllegalStateException("Already destroyed");
        }
        try {
            if (msg instanceof HttpRequest) {
                HttpRequest req = (HttpRequest) msg;
                if (oHttpContext != null) {
                    // Pipelining is not supported.
                    sentResponse = true;
                    FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                            HttpResponseStatus.BAD_REQUEST);
                    HttpUtil.setKeepAlive(response, false);
                    onResponse(req, response);
                    ctx.writeAndFlush(response)
                            .addListener(ChannelFutureListener.CLOSE);
                    return;
                }

                OHttpVersion version = null;
                sentResponse = false;
                if (req.method() == HttpMethod.POST) {
                    String contentTypeValue = req.headers().get(HttpHeaderNames.CONTENT_TYPE);
                    version = selectVersion(contentTypeValue);
                }
                if (version != null) {
                    // Keep a copy of the request, which will be used to generate the response.
                    request = new DefaultHttpRequest(req.protocolVersion(), req.method(), req.uri(), req.headers());
                    oHttpContext = new OHttpServerRequestResponseContext(version, provider, serverKeys);
                } else {
                    sentResponse = true;
                    FullHttpResponse response = new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
                    HttpUtil.setKeepAlive(response, false);
                    onResponse(req, response);
                    ctx.writeAndFlush(response)
                            .addListener(ChannelFutureListener.CLOSE);
                    return;
                }
            }
            if (oHttpContext != null) {
                if (msg instanceof HttpContent) {
                    boolean isLast = msg instanceof LastHttpContent;
                    try {
                        ByteBuf content = ((HttpContent) msg).content();
                        cumulationBuffer = MERGE_CUMULATOR.cumulate(
                                ctx.alloc(), cumulationBuffer, content.retain());
                        oHttpContext.parse(ctx.alloc(), cumulationBuffer, isLast, out);
                    } finally {
                        if (isLast && oHttpContext.receivedLastHttpContent()) {
                            destroyContext();
                        }
                    }
                }
            } else {
                // Just drop it on the floor. MessageToMessageCodec will take care of releasing it.
            }
        } catch (Exception e) {
            throw new OHttpServerDecoderException("failed to decode bytes", e);
        }
    }

    @Override
    public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (!sentResponse && request != null) {
            sentResponse = true;

            // Respond with 4xx status code in case of unable to decode message:
            // See https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#section-5.2
            HttpResponseStatus status = cause instanceof OHttpServerDecoderException ?
                    HttpResponseStatus.BAD_REQUEST : HttpResponseStatus.INTERNAL_SERVER_ERROR;
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status);
            HttpUtil.setKeepAlive(response, false);
            onResponse(request, response);

            write(ctx, response, ctx.newPromise().addListener(ChannelFutureListener.CLOSE));
            flush(ctx);
        } else {
            ctx.close();
        }
    }

    @Override
    protected final void encode(ChannelHandlerContext ctx, HttpObject msg, List<Object> out) {
        try {
            if (msg instanceof HttpResponse) {
                if (oHttpContext != null) {
                    assert request != null;
                    sentResponse = true;
                    HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                    response.headers().set(HttpHeaderNames.CONTENT_TYPE, oHttpContext.version().responseContentType());
                    HttpUtil.setTransferEncodingChunked(response, true);
                    HttpUtil.setKeepAlive(response, true);
                    onResponse(request, response);
                    out.add(response);
                }
            }
            if (oHttpContext != null) {
                boolean isLast = msg instanceof LastHttpContent;
                try {
                    ByteBuf contentBytes = ctx.alloc().buffer();
                    oHttpContext.serialize(ctx.alloc(), msg, contentBytes);
                    // Use the correct version of HttpContent depending on if it was the last or not.
                    HttpContent content = isLast ? new DefaultLastHttpContent(contentBytes) :
                            new DefaultHttpContent(contentBytes);
                    out.add(content);
                } finally {
                    if (isLast && oHttpContext.sendLastHttpContent()) {
                        destroyContext();
                    }
                }
            } else {
                // Retain the msg as MessageToMessageEncoder will release on it.
                out.add(ReferenceCountUtil.retain(msg));
            }
        } catch (CryptoException e) {
            throw new OHttpEncoderException("failed to encrypt bytes", e);
        }
    }

    @Override
    public final void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        if (!destroyed) {
            destroyed = true;
            cumulationBuffer.release();
            cumulationBuffer = Unpooled.EMPTY_BUFFER;

            destroyContext();
        }
        super.handlerRemoved(ctx);
    }

    private void destroyContext() {
        if (oHttpContext != null) {
            oHttpContext.destroy();
            oHttpContext = null;
        }
    }

    private static final class OHttpServerDecoderException extends OHttpDecoderException {
        OHttpServerDecoderException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }

    private static final class OHttpServerRequestResponseContext extends OHttpRequestResponseContext {

        private final OHttpCryptoProvider provider;
        private final OHttpServerKeys keys;
        private OHttpCryptoReceiver receiver;
        private boolean receivedLastHttpContent;
        private boolean sendLastHttpContent;

        OHttpServerRequestResponseContext(
                OHttpVersion version, OHttpCryptoProvider provider, OHttpServerKeys keys) {
            super(version);
            this.provider = provider;
            this.keys = keys;
        }

        private void checkPrefixDecoded()throws CryptoException {
            if (receiver == null) {
                throw new CryptoException("Prefix was not decoded yet");
            }
        }

        @Override
        public boolean decodePrefix(ByteBufAllocator alloc, ByteBuf in) {
            final int initialReaderIndex = in.readerIndex();
            final OHttpCiphersuite ciphersuite = OHttpCiphersuite.decode(in);
            if (ciphersuite == null) {
                return false;
            }
            final int encapsulatedKeyLength = ciphersuite.encapsulatedKeyLength();
            if (in.readableBytes() < encapsulatedKeyLength) {
                in.readerIndex(initialReaderIndex);
                return false;
            }
            final byte[] encapsulatedKey = new byte[encapsulatedKeyLength];
            in.readBytes(encapsulatedKey);
            receiver = OHttpCryptoReceiver.newBuilder()
                    .setOHttpCryptoProvider(provider)
                    .setConfiguration(version())
                    .setPrivateKey(keys.getKeyPair(ciphersuite))
                    .setCiphersuite(ciphersuite)
                    .setEncapsulatedKey(encapsulatedKey)
                    .build();
            return true;
        }

        @Override
        protected void decryptChunk(ByteBufAllocator alloc, ByteBuf chunk, int chunkSize, boolean isFinal, ByteBuf out)
                throws CryptoException {
            checkPrefixDecoded();
            receiver.decrypt(alloc, chunk, chunkSize, isFinal, out);
        }

        @Override
        public void encodePrefix(ByteBufAllocator alloc, ByteBuf out) throws CryptoException {
            checkPrefixDecoded();
            receiver.writeResponseNonce(out);
        }

        @Override
        protected void encryptChunk(ByteBufAllocator alloc, ByteBuf chunk, int chunkLength,
                                    boolean isFinal, ByteBuf out) throws CryptoException {
            checkPrefixDecoded();
            receiver.encrypt(alloc, chunk, chunkLength, isFinal, out);
        }

        /**
         * Called when a {@link LastHttpContent} was received.
         *
         * @return {@code true} if a {@link LastHttpContent} was received and also sent.
         *         In this case {@link #destroyContext()} must be called.
         */
        boolean receivedLastHttpContent() {
            receivedLastHttpContent = true;
            return sendLastHttpContent;
        }

        /**
         * Called when a {@link LastHttpContent} was sent.
         *
         * @return {@code true} if a {@link LastHttpContent} was received and also sent.
         *         In this case {@link #destroyContext()} must be called.
         */
        boolean sendLastHttpContent() {
            sendLastHttpContent = true;
            return receivedLastHttpContent;
        }

        @Override
        void destroyCrypto() {
            // check for null as the receiver might not have been created yet if we destroy
            // before decoding the prefix.
            if (receiver != null) {
                receiver.close();
            }
        }
    }
}
