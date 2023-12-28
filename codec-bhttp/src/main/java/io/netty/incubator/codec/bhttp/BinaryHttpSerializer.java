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
package io.netty.incubator.codec.bhttp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.codec.UnsupportedMessageTypeException;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpStatusClass;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.AsciiString;
import io.netty.util.internal.StringUtil;

import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;

import static io.netty.incubator.codec.bhttp.VarIntCodecUtils.writeVariableLengthInteger;

/**
 * Serializer that serialize {@link HttpObject}s to {@link ByteBuf}, implementing
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
public final class BinaryHttpSerializer {

    private enum State {
        INITIAL,
        CONTENT,
        CONTENT_DISPOSE
    }

    private State state = State.INITIAL;

    /**
     * Serialize binary {@link HttpObject}s into a {@link ByteBuf}.
     * It is important that the given {@link HttpObject}s are in a valid sequence like:
     * <pre>
     * 1 {@link BinaryHttpResponse} | {@link BinaryHttpRequest}, 0-n {@link HttpContent}, 1 {@link LastHttpContent}.
     * </pre>
     *
     * {@link FullBinaryHttpResponse} or {@link FullBinaryHttpRequest} can be used as a shortcut for such a valid
     * sequence.
     *
     * @param msg the {@link HttpObject} to serialize
     * @param out the {@link ByteBuf} into which to write.
     */
    public void serialize(HttpObject msg, ByteBuf out) {
        for (;;) {
            switch (state) {
                case INITIAL:
                    if (msg instanceof BinaryHttpRequest) {
                        encodeRequest(out.alloc(), out, (BinaryHttpRequest) msg);
                        state = State.CONTENT;
                    } else if (msg instanceof BinaryHttpResponse) {
                        BinaryHttpResponse response = (BinaryHttpResponse) msg;
                        encodeResponse(out.alloc(), out, response);
                        if (response.status().codeClass() == HttpStatusClass.INFORMATIONAL) {
                            state = State.CONTENT_DISPOSE;
                        } else {
                            state = State.CONTENT;
                        }
                    } else {
                        throwUnsupportedMessageTypeException(msg);
                    }
                    if (!(msg instanceof HttpContent)) {
                        return;
                    }
                    break;
                case CONTENT_DISPOSE:
                    if (!(msg instanceof HttpContent)) {
                        throwUnsupportedMessageTypeException(msg);
                    }
                    HttpContent disposableContent = (HttpContent) msg;
                    if (disposableContent.content().isReadable()) {
                        throw new IllegalArgumentException("HttpContent must be empty for INFORMATIONAL" +
                                " responses, state: " + state);
                    }
                    if (disposableContent instanceof LastHttpContent) {
                        if (!((LastHttpContent) disposableContent).trailingHeaders().isEmpty()) {
                            throw new IllegalArgumentException("LastHttpContent trailers must be empty for" +
                                    " INFORMATIONAL responses, state: " + state);
                        }
                        state = State.INITIAL;
                    }
                    return;
                case CONTENT:
                    if (!(msg instanceof HttpContent)) {
                        throwUnsupportedMessageTypeException(msg);
                    }
                    HttpContent content = (HttpContent) msg;
                    encodeContentChunk(content.content(), out);
                    if (content instanceof LastHttpContent) {
                        // Terminate body
                        writeVariableLengthInteger(out, 0);
                        encodeIndeterminateLengthFieldSection(out.alloc(), out,
                                ((LastHttpContent) content).trailingHeaders());
                        state = State.INITIAL;
                    }
                    return;
                default:
                    throw new IllegalStateException("Unknown state: " + state);
            }
        }
    }

    private void throwUnsupportedMessageTypeException(Object msg) {
        throw new UnsupportedMessageTypeException("Unexpected message type: " + StringUtil.simpleClassName(msg) +
                ", state: " + state);
    }

    private static void encodeRequest(ByteBufAllocator allocator, ByteBuf out,
                                      BinaryHttpRequest request) {
        // We always use Indeterminate-Length Request for now to keep things simple
        writeVariableLengthInteger(out, 2);
        encodeRequestControlData(out, request);
        encodeIndeterminateLengthFieldSection(allocator, out, request.headers());
    }

    private static void encodeResponse(ByteBufAllocator allocator, ByteBuf out, BinaryHttpResponse response) {
        // We always use Indeterminate-Length Response for now to keep things simple
        writeVariableLengthInteger(out, 3);
        encodeResponseControlData(out, response);
        encodeIndeterminateLengthFieldSection(allocator, out, response.headers());
    }

    private static void encodeResponseControlData(ByteBuf out, BinaryHttpResponse response) {
        writeVariableLengthInteger(out, response.status().code());
    }

    private static void writeVariableLengthCharSequence(ByteBuf out, CharSequence sequence) {
        writeVariableLengthInteger(out, sequence.length());
        out.writeCharSequence(sequence, StandardCharsets.US_ASCII);
    }

    private static void encodeRequestControlData(ByteBuf out, BinaryHttpRequest request) {
        AsciiString method = request.method().asciiName();
        writeVariableLengthCharSequence(out, method);
        writeVariableLengthCharSequence(out, request.scheme());
        CharSequence authority = request.authority();
        if (authority == null) {
            authority = AsciiString.EMPTY_STRING;
        }
        writeVariableLengthCharSequence(out, authority);
        writeVariableLengthCharSequence(out, request.uri());
    }

    private static void encodeIndeterminateLengthFieldSection(
            ByteBufAllocator allocator, ByteBuf out, HttpHeaders headers) {
        int writerIndex = out.writerIndex();
        ByteBuf nonPseudoHeaderBuffer = null;
        for (Iterator<Map.Entry<CharSequence, CharSequence>> it = headers.iteratorCharSequence(); it.hasNext();) {
            Map.Entry<CharSequence, CharSequence> header = it.next();
            if (PseudoHeaderName.hasPseudoHeaderFormat(header.getKey())) {
                if (nonPseudoHeaderBuffer == null) {
                    // We found our first pseudo-header which means we need to ensure
                    // we write the pseudo-header first and then the rest, reset
                    // the index and start writing. We store the non pseudo-headers to another
                    // buffer and copy them over after it.
                    nonPseudoHeaderBuffer = allocator.buffer();
                    nonPseudoHeaderBuffer.writeBytes(out, writerIndex, out.writerIndex() - writerIndex);
                    out.writerIndex(writerIndex);
                }
                writeVariableLengthCharSequence(out, header.getKey());
                writeVariableLengthCharSequence(out, header.getValue());
            } else if (nonPseudoHeaderBuffer == null) {
                // We didnt find a pseudo-header yet, just encode.
                writeVariableLengthCharSequence(out, header.getKey());
                writeVariableLengthCharSequence(out, header.getValue());
            } else {
                writeVariableLengthCharSequence(nonPseudoHeaderBuffer, header.getKey());
                writeVariableLengthCharSequence(nonPseudoHeaderBuffer, header.getValue());
            }
        }
        // We did write pseudo-headers first, now write the rest of the headers.
        if (nonPseudoHeaderBuffer != null) {
            out.writeBytes(nonPseudoHeaderBuffer);
            nonPseudoHeaderBuffer.release();
        }

        // Terminate with 0.
        writeVariableLengthInteger(out, 0);
    }

    private static void writeVariableLengthBuffer(ByteBuf out, ByteBuf buffer) {
        writeVariableLengthInteger(out, buffer.readableBytes());
        out.writeBytes(buffer);
    }

    private static void encodeContentChunk(ByteBuf content, ByteBuf out) {
        // Omit zero-length chunks.
        if (!content.isReadable()) {
            return;
        }

        writeVariableLengthBuffer(out, content);
    }
}
