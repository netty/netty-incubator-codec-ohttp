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
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.EncoderException;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.AsciiString;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Implementation of
 * <a href="https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html">the draft protocol</a>.
 */
public final class OHttpVersionDraft implements OHttpVersion {

    public static final OHttpVersion INSTANCE = new OHttpVersionDraft();

    private static final byte[] REQUEST_EXPORT_CONTEXT = "message/bhttp request".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] RESPONSE_EXPORT_CONTEXT = "message/bhttp response".getBytes(StandardCharsets.US_ASCII);

    private OHttpVersionDraft() {
    }

    @Override
    public byte[] requestExportContext() {
        return REQUEST_EXPORT_CONTEXT.clone();
    }

    @Override
    public byte[] responseExportContext() {
        return RESPONSE_EXPORT_CONTEXT.clone();
    }

    @Override
    public boolean useFinalAad() {
        return false;
    }

    @Override
    public AsciiString requestContentType() {
        return OHttpConstants.REQUEST_CONTENT_TYPE;
    }

    @Override
    public AsciiString responseContentType() {
        return OHttpConstants.RESPONSE_CONTENT_TYPE;
    }

    @Override
    public void parse(ByteBufAllocator alloc, ByteBuf in, boolean completeBodyReceived,
                      Decoder decoder, List<Object> out) throws CryptoException {
        if (completeBodyReceived) {
            if (decoder.isPrefixNeeded() && !decoder.decodePrefix(alloc, in)) {
                throw new CorruptedFrameException("Prefix is truncated");
            }
            decoder.decodeChunk(alloc, in, in.readableBytes(), true, out);
        }
    }

    @Override
    public void serialize(ByteBufAllocator alloc, HttpObject msg, Encoder<HttpObject> encoder, ByteBuf out)
            throws CryptoException {
        if (!(msg instanceof LastHttpContent)) {
            throw new EncoderException("OHTTP version only supports FullHttpMessage");
        }
        if (encoder.isPrefixNeeded()) {
            encoder.encodePrefix(alloc, out);
        }
        encoder.encodeChunk(alloc, msg, out);
    }
}
