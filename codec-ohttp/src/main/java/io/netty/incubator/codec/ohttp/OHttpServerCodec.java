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
 */package io.netty.incubator.codec.ohttp;

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
import io.netty.util.ReferenceCountUtil;

import java.util.List;

import static io.netty.handler.codec.ByteToMessageDecoder.MERGE_CUMULATOR;

/**
 * {@link MessageToMessageCodec} that HTTP servers can use to decrypt incoming
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">Oblivious HTTP</a> requests
 * and encrypt outgoing HTTP responses.
 * <br><br>
 * Both incoming and outgoing messages are {@link HttpObject}s.
 */
public abstract class OHttpServerCodec extends MessageToMessageCodec<HttpObject, HttpObject> {

    private OHttpServerContext context;
    private HttpRequest request;
    private boolean sentResponse;
    private OHttpContentSerializer serializer;
    private OHttpContentParser parser;
    private ByteBuf cumulationBuffer = Unpooled.EMPTY_BUFFER;
    private boolean destroyed;

    /**
     * Create a {@link OHttpServerContext} to handle an inbound OHTTP request.
     * <br>
     * @param request inbound {@link HttpRequest}.
     * @param version {@link OHttpVersion} inferred from the Content-Type header.
     * @return {@link OHttpServerContext} instance, or null to reject the request with a 403 error.
     */
    protected abstract OHttpServerContext newServerContext(HttpRequest request, OHttpVersion version);

    /**
     * Optional callback to report the outer HTTP request and response.
     * @param request Incoming {@link HttpRequest}.
     * @param response Outgoing {@link HttpResponse}.
     */
    protected void onResponse(HttpRequest request, HttpResponse response) {
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
            if (msg instanceof HttpRequest) {
                HttpRequest req = (HttpRequest) msg;
                context = null;
                parser = null;
                sentResponse = false;
                if (req.method() == HttpMethod.POST) {
                    String contentTypeValue = req.headers().get(HttpHeaderNames.CONTENT_TYPE);
                    if (OHttpConstants.REQUEST_CONTENT_TYPE.contentEqualsIgnoreCase(contentTypeValue)) {
                        context = newServerContext(req, OHttpVersionDraft.INSTANCE);
                    } else if (OHttpConstants.CHUNKED_REQUEST_CONTENT_TYPE.contentEqualsIgnoreCase(contentTypeValue)) {
                        context = newServerContext(req, OHttpVersionChunkDraft.INSTANCE);
                    }
                }
                if (context != null) {
                    // Keep a copy of the request, which will be used to generate the response.
                    request = new DefaultHttpRequest(req.protocolVersion(), req.method(), req.uri(), req.headers());
                    parser = context.newContentParser();
                } else {
                    sentResponse = true;
                    FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.FORBIDDEN);
                    HttpUtil.setKeepAlive(response, false);
                    onResponse(req, response);
                    ctx.writeAndFlush(response)
                            .addListener(ChannelFutureListener.CLOSE);
                    return;
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
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        context = null;
        if (!sentResponse && request != null) {
            sentResponse = true;
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.INTERNAL_SERVER_ERROR);
            HttpUtil.setKeepAlive(response, false);
            onResponse(request, response);

            write(ctx, response, ctx.newPromise().addListener(ChannelFutureListener.CLOSE));
            flush(ctx);
        } else {
            ctx.close();
        }
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, HttpObject msg, List<Object> out) {
        try {
            if (msg instanceof HttpResponse) {
                serializer = null;
                if (context != null) {
                    assert request != null;
                    serializer = context.newContentSerializer();
                    sentResponse = true;
                    HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                    response.headers().set(HttpHeaderNames.CONTENT_TYPE, context.version().responseContentType());
                    HttpUtil.setTransferEncodingChunked(response, true);
                    HttpUtil.setKeepAlive(response, true);
                    onResponse(request, response);
                    out.add(response);
                }
            }
            if (serializer != null) {
                boolean isLast = msg instanceof LastHttpContent;
                ByteBuf contentBytes = ctx.alloc().buffer();
                serializer.serialize(msg, contentBytes);
                // Use the correct version of HttpContent depending on if it was the last or not.
                HttpContent content = isLast ? new DefaultLastHttpContent(contentBytes) :
                        new DefaultHttpContent(contentBytes);
                out.add(content);
            } else {
                // Retain the msg as MessageToMessageEncoder will release on it.
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
