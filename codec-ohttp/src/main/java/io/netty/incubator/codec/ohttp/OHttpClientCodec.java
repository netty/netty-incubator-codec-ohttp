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
import io.netty.util.AsciiString;
import io.netty.util.ReferenceCountUtil;

import java.util.List;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;

/**
 * {@link MessageToMessageCodec} that HTTP clients can use to encrypt outgoing HTTP requests into
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">Oblivious HTTP</a> requests
 * and decrypt incoming OHTTP responses.
 * <br><br>
 * Both incoming and outgoing messages are {@link HttpObject}s.
 */
public abstract class OHttpClientCodec extends MessageToMessageCodec<HttpObject, HttpObject> {

    private OHttpContentSerializer serializer;
    private OHttpContentParser parser;

    private OHttpClientContext context;
    private ByteBuf cumulationBuffer = Unpooled.EMPTY_BUFFER;
    private boolean destroyed;

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
         * Update outer HTTP request headers, if necessary.
         * @param headers {@link HttpHeaders} to be updated.
         */
        default void outerRequestUpdateHeaders(HttpHeaders headers) {
        }

        /**
         * @return {@link OHttpClientContext}.
         */
        OHttpClientContext context();
    }

    /**
     * Get the parameters to encapsulate a {@link HttpRequest} into OHTTP.
     * <br>
     * @param request outbound {@link HttpRequest} intercepted by the handler.
     * @return {@link EncapsulationParameters} object if OHTTP encapsulation is required, or null otherwise.
     */
    protected abstract EncapsulationParameters encapsulationParameters(HttpRequest request);

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
            if (msg instanceof HttpResponse) {
                HttpResponse resp = (HttpResponse) msg;
                parser = null;
                if (context != null) {
                    if (resp.status() != HttpResponseStatus.OK) {
                        throw new DecoderException("OHTTP response status is not OK");
                    }
                    String contentTypeValue = resp.headers().get(HttpHeaderNames.CONTENT_TYPE);
                    AsciiString expectedContentType = context.version().responseContentType();
                    if (!expectedContentType.contentEqualsIgnoreCase(contentTypeValue)) {
                        throw new DecoderException("OHTTP response has unexpected content type");
                    }
                    parser = context.newContentParser();
                }
            }
            if (parser != null) {
                if (msg instanceof HttpContent) {
                    ByteBuf content = ((HttpContent) msg).content();
                    cumulationBuffer = MERGE_CUMULATOR.cumulate(content.alloc(), cumulationBuffer, content.retain());
                    parser.parse(cumulationBuffer, msg instanceof LastHttpContent, out);
                }
            } else {
                out.add(ReferenceCountUtil.retain(msg));
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
                context = null;
                serializer = null;
                EncapsulationParameters encapsulation = encapsulationParameters(innerRequest);
                if (encapsulation != null) {
                    context = encapsulation.context();
                    serializer = context.newContentSerializer();
                    HttpHeaders outerHeaders = new DefaultHttpHeaders();
                    DefaultHttpRequest outerRequest = new DefaultHttpRequest(
                            innerRequest.protocolVersion(),
                            HttpMethod.POST,
                            encapsulation.outerRequestUri(), outerHeaders);
                    encapsulation.outerRequestUpdateHeaders(outerHeaders);
                    outerHeaders
                            .set(HttpHeaderNames.HOST, encapsulation.outerRequestAuthority())
                            .add(HttpHeaderNames.CONTENT_TYPE, context.version().requestContentType());
                    HttpUtil.setTransferEncodingChunked(outerRequest, true);
                    out.add(outerRequest);
                }
            }
            if (serializer != null) {
                ByteBuf contentBytes = ctx.alloc().buffer();
                try {
                    boolean isLast = msg instanceof LastHttpContent;
                    serializer.serialize(msg, contentBytes);
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

            if (parser != null) {
                parser.destroy();
            }
        }
        super.handlerRemoved(ctx);
    }
}
