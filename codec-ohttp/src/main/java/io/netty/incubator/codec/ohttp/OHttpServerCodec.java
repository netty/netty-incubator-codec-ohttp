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
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.MessageToMessageCodec;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.incubator.codec.bhttp.DefaultFullBinaryHttpResponse;
import io.netty.incubator.codec.hpke.AsymmetricCipherKeyPair;
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
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
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.util.List;
import java.util.function.Function;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;
import static io.netty.incubator.codec.ohttp.OHttpConstants.MAX_BUFFER_LENGTH;
import static java.util.Objects.requireNonNull;

/**
 * {@link MessageToMessageCodec} that HTTP servers can use to decrypt incoming
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">Oblivious HTTP</a> requests
 * and encrypt outgoing HTTP responses.
 * <br><br>
 * Both incoming and outgoing messages are {@link HttpObject}s.
 */
public class OHttpServerCodec extends MessageToMessageCodec<HttpObject, HttpObject> {

    private static final InternalLogger logger = InternalLoggerFactory.getInstance(OHttpServerCodec.class);

    // The first unusable OHttpCryptoParameters is logged at WARN so the problem is visible to the operator, all
    // further ones only at DEBUG. A client can trigger this for every request, so it must not flood the log.
    private static volatile boolean unusableParametersWarned;

    private final OHttpCryptoProvider provider;
    private final OHttpServerKeys serverKeys;
    private final int maxInitialLineSize;
    private final int maxFieldSectionSize;

    private HttpRequest request;
    private boolean sentResponse;
    private boolean discardingRequest;
    private OHttpServerRequestResponseContext oHttpContext;
    private ByteBuf cumulationBuffer = Unpooled.EMPTY_BUFFER;
    private boolean decodeCalled;
    private boolean producedMessage;
    private boolean destroyed;
    private int maxBufferLength;

    public OHttpServerCodec(OHttpCryptoProvider provider, OHttpServerKeys serverKeys) {
        this(new OHttpServerCodecBuilder()
                .setProvider(provider)
                .setServerKeys(serverKeys));
    }

    /**
     * Create a new instance with the given configuration.
     * @param builder The codec configuration to use.
     */
    OHttpServerCodec(OHttpServerCodecBuilder builder) {
        this(builder.getProvider(), builder.getServerKeys(),
                builder.getMaxInitialLineSize(), builder.getMaxFieldSectionSize(), builder.maxBufferLength());
    }

    /**
     * @deprecated use {@link #OHttpServerCodec(OHttpCryptoProvider, OHttpServerKeys, int, int, int)}
     */
    @Deprecated
    protected OHttpServerCodec(OHttpCryptoProvider provider, OHttpServerKeys serverKeys,
                               int maxInitialLineSize, int maxFieldSectionSize) {
        this(provider, serverKeys, maxInitialLineSize, maxFieldSectionSize, MAX_BUFFER_LENGTH);
    }
    /**
     * Create a new instance with the given configuration.
     */
    protected OHttpServerCodec(OHttpCryptoProvider provider, OHttpServerKeys serverKeys,
                               int maxInitialLineSize, int maxFieldSectionSize, int maxBufferLength) {
        this.provider = requireNonNull(provider, "provider");
        this.serverKeys = requireNonNull(serverKeys, "serverKeys");
        this.maxInitialLineSize = ObjectUtil.checkPositive(maxInitialLineSize, "maxInitialLineSize");
        maxFieldSectionSize = ObjectUtil.checkPositive(maxFieldSectionSize, "maxFieldSectionSize");
        if (maxFieldSectionSize > (Integer.MAX_VALUE >> 1)) {
            throw new IllegalArgumentException("Max field section size cannot be greater than " +
                    (Integer.MAX_VALUE >> 1));
        }
        this.maxFieldSectionSize = maxFieldSectionSize;
        this.maxBufferLength = ObjectUtil.checkPositive(maxBufferLength, "maxBufferLength");
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
     * Returns the {@link OHttpCryptoParameters} to use for a request. This method is called once per request, after
     * the {@link OHttpCiphersuite} was decoded and before the request is decrypted. A {@link RuntimeException}
     * thrown by this method, or parameters the {@link OHttpCryptoProvider} does not support, rejects the request.
     *
     * @param ctx           the {@link ChannelHandlerContext} of this handler.
     * @param request       the outer {@link HttpRequest}, which must be treated as read-only.
     * @param ciphersuite   the {@link OHttpCiphersuite} of the request.
     * @return              the parameters to use.
     */
    protected OHttpCryptoParameters cryptoParameters(
            @SuppressWarnings("unused") ChannelHandlerContext ctx, @SuppressWarnings("unused") HttpRequest request,
            @SuppressWarnings("unused") OHttpCiphersuite ciphersuite) {
        return OHttpCryptoParameters.DEFAULT;
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

    /**
     * Optional callback that allows replying to the outer HTTP request without encapsulating the inner
     * response. It is called for a {@link FullHttpResponse} that is written for an OHTTP request, as long as no
     * response was started yet, but not for the error responses that are generated by this codec itself.
     * <br><br>
     * If a non-{@code null} {@link FullHttpResponse} is returned it is written as the outer response as-is,
     * instead of encapsulating the inner response. It should therefore include all headers that are needed to
     * frame the response, like {@link HttpHeaderNames#CONTENT_LENGTH}. If the outer request was not fully
     * received yet when this happens, the remaining part of it is dropped.
     * <br><br>
     * <strong>Privacy:</strong> the returned response is sent <em>without</em> protection, so it is visible to the
     * Oblivious Relay Resource and to any other party on the path between the gateway and the client, and the
     * client can not authenticate it. It must therefore not depend on, or reveal anything about, the decrypted
     * request or the inner {@code response} (for example by copying its status, headers or content), as this
     * would defeat the confidentiality that OHTTP provides. Use it only for responses that are safe to expose
     * publicly. See
     * <a href="https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#section-5.2">section 5.2</a>
     * of the OHTTP draft.
     * <br><br>
     * If this method throws, an error response (see {@link #errorResponseStatus(Throwable, boolean)}) is sent,
     * the connection is closed and the failure of the write is reported to the caller of the write.
     *
     * @param request   Incoming outer {@link HttpRequest}.
     * @param response  Outgoing inner {@link FullHttpResponse}.
     * @return          the outer {@link FullHttpResponse} to write as-is, or {@code null} if the inner response
     *                  should be encapsulated.
     */
    protected FullHttpResponse unencapsulatedResponse(
            @SuppressWarnings("unused") HttpRequest request, @SuppressWarnings("unused") FullHttpResponse response) {
        return null;
    }

    /**
     * Returns the {@link HttpResponseStatus} of the response that is sent when processing an OHTTP request
     * failed.
     *
     * @param cause         the cause of the failure.
     * @param encapsulated  {@code true} if the response will be encapsulated, {@code false} if it will be sent
     *                      without encapsulation because the request encapsulation could not be removed.
     * @return              the status to use.
     */
    protected HttpResponseStatus errorResponseStatus(
            Throwable cause, @SuppressWarnings("unused") boolean encapsulated) {
        return defaultErrorResponseStatus(cause);
    }

    private static HttpResponseStatus defaultErrorResponseStatus(Throwable cause) {
        return cause instanceof OHttpServerDecoderException ?
                HttpResponseStatus.BAD_REQUEST : HttpResponseStatus.INTERNAL_SERVER_ERROR;
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
        decodeCalled = true;
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
                    HttpRequest outerRequest = new DefaultHttpRequest(
                            req.protocolVersion(), req.method(), req.uri(), req.headers());
                    request = outerRequest;
                    oHttpContext = new OHttpServerRequestResponseContext(
                            version, provider, serverKeys, maxInitialLineSize, maxFieldSectionSize,
                            ciphersuite -> cryptoParameters(ctx, outerRequest, ciphersuite));
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
                if (discardingRequest) {
                    // We already replied without encapsulation, so the remaining request is not of interest.
                    // MessageToMessageCodec will take care of releasing it.
                    if (msg instanceof LastHttpContent) {
                        discardingRequest = false;
                        destroyContext();
                    }
                } else if (msg instanceof HttpContent) {
                    boolean isLast = msg instanceof LastHttpContent;
                    try {
                        ByteBuf content = ((HttpContent) msg).content();
                        cumulationBuffer = MERGE_CUMULATOR.cumulate(
                                ctx.alloc(), cumulationBuffer, content.retain());
                        oHttpContext.parse(ctx.alloc(), cumulationBuffer, isLast, out);

                        // We check what is left after we parse to see if it will exceed the limit.
                        // parse(...) is expected to read as much as possible from the buffer.
                        if (cumulationBuffer.readableBytes() > maxBufferLength) {
                            throw new TooLongFrameException("max buffer length exceeded: " + maxBufferLength);
                        }
                    } finally {
                        if (isLast && oHttpContext.receivedLastHttpContent()) {
                            // Check if we can either free up some memory or release it all together.
                            if (cumulationBuffer.isReadable()) {
                                cumulationBuffer.discardSomeReadBytes();
                            } else {
                                cumulationBuffer.release();
                                cumulationBuffer = Unpooled.EMPTY_BUFFER;
                            }
                            destroyContext();
                        }
                    }
                }
            } else {
                // Just drop it on the floor. MessageToMessageCodec will take care of releasing it.
            }
        } catch (Exception e) {
            throw new OHttpServerDecoderException("failed to decode bytes", e);
        } finally {
            producedMessage |= !out.isEmpty();
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        if (decodeCalled && !producedMessage && !ctx.channel().config().isAutoRead()) {
            ctx.read();
        }
        decodeCalled = false;
        producedMessage = false;
        ctx.fireChannelReadComplete();
    }

    @Override
    public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (!sentResponse && request != null) {
            // we should send the response without encapsulation if the error is because of
            // removing encapsulation, otherwise we should encapsulate it.
            //
            // https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#section-5.2:
            // Errors detected by the Oblivious Relay Resource and errors detected by the Oblivious Gateway Resource
            // before removing protection (including being unable to remove encapsulation for any reason) result in the
            // status code being sent without protection in response to the POST request made to that resource.
            //
            boolean encapsulate = !(cause.getCause() instanceof CryptoException ||
                    // If we were not able to decode the prefix yet we also need to respond without encapsulation.
                    oHttpContext == null || !oHttpContext.isPrefixDecoded());
            sendErrorResponse(ctx, cause, encapsulate);
        } else {
            ctx.close();
        }
    }

    /**
     * Sends the error response and closes the connection afterwards. If sending the response fails, the connection
     * is closed anyway (as the write promise that would close it is never completed in this case) and the failure
     * is rethrown.
     */
    private void sendErrorResponse(ChannelHandlerContext ctx, Throwable cause, boolean encapsulate) throws Exception {
        sentResponse = true;
        try {
            // Respond with 4xx status code in case of unable to decode message:
            // See https://www.ietf.org/archive/id/draft-ietf-ohai-ohttp-10.html#section-5.2
            // The response must be binary, because we send it through the BinaryHttpSerializer.
            HttpResponseStatus status;
            try {
                status = requireNonNull(errorResponseStatus(cause, encapsulate), "errorResponseStatus(...)");
            } catch (Throwable t) {
                // Never fail to send a response and close the connection because of a faulty override.
                addSuppressed(cause, t);
                status = defaultErrorResponseStatus(cause);
            }
            FullHttpResponse response = new DefaultFullBinaryHttpResponse(
                    HttpVersion.HTTP_1_1, status, Unpooled.buffer(0));
            HttpUtil.setKeepAlive(response, false);
            onResponse(request, response);

            ChannelPromise promise = ctx.newPromise().addListener(ChannelFutureListener.CLOSE);
            if (encapsulate) {
                // Encapsulate and sent with protection. As sentResponse is already true
                // unencapsulatedResponse(...) will not be consulted.
                write(ctx, response, promise);
                flush(ctx);
            } else {
                // Not able to remove protection, sent without protection.
                ctx.writeAndFlush(response, promise);
            }
        } catch (Throwable t) {
            // The write failed synchronously, so the promise with the CLOSE listener will never be notified.
            ctx.close();
            throw t;
        }
    }

    private static void addSuppressed(Throwable cause, Throwable suppressed) {
        if (cause != suppressed) {
            cause.addSuppressed(suppressed);
        }
    }

    @Override
    protected final void encode(ChannelHandlerContext ctx, HttpObject msg, List<Object> out) {
        try {
            // Only consult the hook if no response was started yet, otherwise we would corrupt the framing.
            if (msg instanceof FullHttpResponse && oHttpContext != null && !sentResponse) {
                assert request != null;
                FullHttpResponse response;
                try {
                    response = unencapsulatedResponse(request, (FullHttpResponse) msg);
                } catch (Throwable t) {
                    // Send the error response (and close the connection) the same way as for any other failure.
                    // The request was decrypted already if the prefix was decoded, so encapsulate the response.
                    try {
                        sendErrorResponse(ctx, t, oHttpContext.isPrefixDecoded());
                    } catch (Throwable e) {
                        // Do not lose the original failure, the connection was closed by sendErrorResponse(...).
                        addSuppressed(t, e);
                    }
                    throw t;
                }
                if (response != null) {
                    sentResponse = true;
                    try {
                        onResponse(request, response);
                    } catch (Throwable t) {
                        if (response != msg) {
                            ReferenceCountUtil.release(response);
                        }
                        throw t;
                    }
                    // Retain the response if it is the msg as MessageToMessageEncoder will release on it.
                    out.add(response == msg ? response.retain() : response);
                    if (oHttpContext.sendLastHttpContent()) {
                        destroyContext();
                    } else {
                        // The request was not fully received yet. Drop what is left of it.
                        discardingRequest = true;
                        cumulationBuffer.release();
                        cumulationBuffer = Unpooled.EMPTY_BUFFER;
                    }
                    return;
                }
            }
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
                ByteBuf contentBytes = ctx.alloc().buffer();
                try {
                    oHttpContext.serialize(ctx.alloc(), msg, contentBytes);
                    // Use the correct version of HttpContent depending on if it was the last or not.
                    HttpContent content = isLast ? new DefaultLastHttpContent(contentBytes) :
                            new DefaultHttpContent(contentBytes);
                    out.add(content);
                    contentBytes = null;
                } finally {
                    if (contentBytes != null) {
                        contentBytes.release();
                    }
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
        private final Function<OHttpCiphersuite, OHttpCryptoParameters> cryptoParameters;
        private OHttpCryptoReceiver receiver;
        private boolean receivedLastHttpContent;
        private boolean sendLastHttpContent;

        OHttpServerRequestResponseContext(
                OHttpVersion version, OHttpCryptoProvider provider, OHttpServerKeys keys, int maxInitialLineSize,
                int maxFieldSectionSize, Function<OHttpCiphersuite, OHttpCryptoParameters> cryptoParameters) {
            super(version, maxInitialLineSize, maxFieldSectionSize);
            this.provider = provider;
            this.keys = keys;
            this.cryptoParameters = cryptoParameters;
        }

        private static void logUnusableParameters(Exception cause) {
            // Only log the message (no stack trace), the cause is a (constant) server configuration problem.
            // Best effort: a race between event loops may result in more than one WARN, which is harmless.
            if (!unusableParametersWarned) {
                unusableParametersWarned = true;
                logger.warn("Unable to use the OHttpCryptoParameters for a request, responding with 400. " +
                        "Further occurrences are only logged at DEBUG level: {}", String.valueOf(cause));
            } else if (logger.isDebugEnabled()) {
                logger.debug("Unable to use the OHttpCryptoParameters for a request: {}", String.valueOf(cause));
            }
        }

        private void checkPrefixDecoded()throws CryptoException {
            if (!isPrefixDecoded()) {
                throw new CryptoException("Prefix was not decoded yet");
            }
        }

        @Override
        public boolean decodePrefix(ByteBufAllocator alloc, ByteBuf in) throws CryptoException {
            final int initialReaderIndex = in.readerIndex();
            final OHttpCiphersuite ciphersuite;
            try {
                ciphersuite = OHttpCiphersuite.decode(in);
            } catch (IllegalArgumentException e) {
                throw new CryptoException(e);
            }
            if (ciphersuite == null) {
                return false;
            }
            final int encapsulatedKeyLength = ciphersuite.encapsulatedKeyLength();
            if (in.readableBytes() < encapsulatedKeyLength) {
                in.readerIndex(initialReaderIndex);
                return false;
            }

            AsymmetricCipherKeyPair pair = keys.getKeyPair(ciphersuite);
            if (pair == null) {
                throw new CryptoException("Unable to find private key for OHttpCiphersuite: " + ciphersuite);
            }

            final byte[] encapsulatedKey = new byte[encapsulatedKeyLength];
            in.readBytes(encapsulatedKey);

            // The client can only be told that the request could not be decrypted (400), so a failure that is caused
            // by the server configuration is made visible to the operator via the log.
            final OHttpCryptoParameters parameters;
            try {
                parameters = requireNonNull(cryptoParameters.apply(ciphersuite), "cryptoParameters");
                OHttpCrypto.checkRequestAad(version(), parameters);
                if (!provider.isSupported(parameters.mode())) {
                    throw new CryptoException("The OHttpCryptoProvider does not support " + parameters.mode());
                }
            } catch (CryptoException | RuntimeException e) {
                logUnusableParameters(e);
                throw e;
            }
            receiver = OHttpCryptoReceiver.newBuilder()
                    .setOHttpCryptoProvider(provider)
                    .setConfiguration(version())
                    .setPrivateKey(pair)
                    .setCiphersuite(ciphersuite)
                    .setEncapsulatedKey(encapsulatedKey)
                    .setCryptoParameters(parameters)
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

        boolean isPrefixDecoded() {
            return receiver != null;
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
