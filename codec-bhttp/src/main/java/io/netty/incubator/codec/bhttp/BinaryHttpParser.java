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
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpStatusClass;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.ByteProcessor;
import io.netty.util.internal.ObjectUtil;

import java.nio.charset.StandardCharsets;

import static io.netty.incubator.codec.bhttp.VarIntCodecUtils.getVariableLengthInteger;
import static io.netty.incubator.codec.bhttp.VarIntCodecUtils.numBytesForVariableLengthIntegerFromByte;
import static io.netty.incubator.codec.bhttp.VarIntCodecUtils.readVariableLengthInteger;

/**
 * Parser that parse {@link ByteBuf} into {@link HttpObject}s, implementing
 * <a href="https://www.rfc-editor.org/rfc/rfc9292.html">Binary Representation of HTTP Messages</a>.
 */
public final class BinaryHttpParser {

    private enum State {
        READ_FRAME_TYPE(true),
        READ_KNOWN_LENGTH_REQUEST_HEAD(true),
        READ_KNOWN_LENGTH_RESPONSE_HEAD(true),

        READ_KNOWN_LENGTH_FIELD_SECTION_TRAILERS(true),
        READ_KNOWN_LENGTH_CONTENT(true),

        READ_INDETERMINATE_LENGTH_REQUEST_HEAD(false),
        READ_INDETERMINATE_LENGTH_RESPONSE_HEAD(false),

        READ_INDETERMINATE_LENGTH_CONTENT(false),
        READ_INDETERMINATE_LENGTH_FIELD_SECTION_TRAILERS(false),

        READ_PADDING(true),

        DISCARD(true);

        final boolean knownLength;

        State(boolean knownLength) {
            this.knownLength = knownLength;
        }
    }

    private static final boolean[] ALLOWED_TOKEN;
    private static final boolean[] ALLOWED_SCHEME;

    static {
        ALLOWED_TOKEN = new boolean[256];
        for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
            ALLOWED_TOKEN[128 + b] = !Character.isWhitespace(b);
        }

        // See https://www.rfc-editor.org/rfc/rfc3986.html
        //    scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        ALLOWED_SCHEME = new boolean[256];
        for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++) {
            ALLOWED_SCHEME[128 + b] = Character.isAlphabetic(b) || Character.isDigit(b) ||
                    b == (byte) '+' || b == (byte) '-' || b == (byte) '.';
        }
    }

    // See https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2
    private static final ByteProcessor TOKEN_VALIDATOR = b -> {
        // Is whitespace will match whitespaces and delimiters.
        if (ALLOWED_TOKEN[b + 128]) {
            return true;
        }
        throw new IllegalArgumentException(
                "Invalid char in token received: '" + b + "' (0x" + Integer.toHexString(b) + ")");
    };

    // See https://www.rfc-editor.org/rfc/rfc3986.html
    private static final ByteProcessor SCHEME_VALIDATOR = b -> {
        // Is whitespace will match whitespaces and delimiters.
        if (ALLOWED_SCHEME[b + 128]) {
            return true;
        }
        throw new IllegalArgumentException(
                "Invalid char in scheme received : '" + b + "' (0x" + Integer.toHexString(b) + ")");
    };

    private static final ByteProcessor PADDING_VALIDATOR = b -> {
        // Let's validate that only 0 is used for padding. While this is not strictly required
        // it can't harm to enforce it.
        // See https://www.rfc-editor.org/rfc/rfc9292.html#section-3.8
        if (b != 0) {
            throw new CorruptedFrameException(
                    "Invalid byte used for padding: '" + b + "' (0x" + Integer.toHexString(b) + ")");
        }
        return true;
    };

    private State state = State.READ_FRAME_TYPE;

    private boolean completeBodyReceived;
    private long contentLength = -1;

    private final int maxFieldSectionSize;

    /**
     * Creates a new instance
     *
     * @param maxFieldSectionSize   the maximum size of the field-section (in bytes)
     */
    public BinaryHttpParser(int maxFieldSectionSize) {
        this.maxFieldSectionSize = ObjectUtil.checkPositiveOrZero(maxFieldSectionSize, "maxFieldSectionSize");
    }

    /**
     * Parse the given {@link ByteBuf} and converts it to {@link HttpObject}s.
     * This method should be called in a loop until it returns {@code null}.
     * <pre>
     *    for (;;) {
     *        HttpObject msg = parser.parse(in, completeBodyReceived);
     *        if (msg == null) {
     *            // Try again later once there are more readable bytes in the input buffer.
     *            return;
     *        }
     *        // Do something with the msg.
     *    }
     * </pre>
     * <p>
     * The returned {@link HttpObject} will form a valid sequence like:
     * <pre>
     * 1 {@link io.netty.handler.codec.http.HttpMessage}, 0-n {@link HttpContent}, 1 {@link LastHttpContent}.
     * </pre>
     *
     * It might also use the shortcut of {@link io.netty.handler.codec.http.FullHttpMessage} to represent a full
     * sequence.
     *
     * @param in                    the {@link ByteBuf} to parse.
     * @param completeBodyReceived  {@code true} if we should consider the end of body to be received, {@code false}
     *                              otherwise.
     * @return                      the {@link HttpObject} or {@code null} if this method should be called again later
     *                              once there are
     *                              more readable bytes in the input {@link ByteBuf}.
     */
    public HttpObject parse(ByteBuf in, boolean completeBodyReceived) {
        try {
            if (!completeBodyReceived && this.completeBodyReceived) {
                throw new IllegalStateException("Body was already marked as complete before");
            }
            this.completeBodyReceived = completeBodyReceived;
            for (;;) {
                switch (state) {
                    case DISCARD:
                        in.skipBytes(in.readableBytes());
                        return null;
                    case READ_FRAME_TYPE:
                        assert contentLength == -1 : "contentLength should have been reset";

                        state = readFramingIndicator(in);
                        break;
                    case READ_KNOWN_LENGTH_REQUEST_HEAD:
                    case READ_INDETERMINATE_LENGTH_REQUEST_HEAD:
                        assert contentLength == -1 : "contentLength should have been reset";

                        HttpMessage request = readRequestHead(in, state.knownLength, maxFieldSectionSize);
                        if (request == null) {
                            throwIfNotReadAllAndBodyReceived(in, completeBodyReceived);

                            // Not enough readable bytes
                            return null;
                        }

                        if (state.knownLength) {
                            state = State.READ_KNOWN_LENGTH_CONTENT;
                        } else {
                            state = State.READ_INDETERMINATE_LENGTH_CONTENT;
                        }
                        return request;
                    case READ_KNOWN_LENGTH_RESPONSE_HEAD:
                    case READ_INDETERMINATE_LENGTH_RESPONSE_HEAD:
                        assert contentLength == -1 : "contentLength should have been reset";

                        BinaryHttpResponse response = readResponseHead(in, state.knownLength, maxFieldSectionSize);
                        if (response == null) {
                            throwIfNotReadAllAndBodyReceived(in, completeBodyReceived);

                            // Not enough readable bytes
                            return null;
                        }
                        boolean informational = response.status().codeClass() == HttpStatusClass.INFORMATIONAL;
                        if (informational) {
                            // There will be more responses to follow so just return a FullHttpResponse and NOT change
                            // the state.
                            // See https://www.rfc-editor.org/rfc/rfc9292.html#section-3.5.1
                            return new DefaultFullHttpResponse(response.protocolVersion(), response.status(),
                                    Unpooled.EMPTY_BUFFER, response.headers(), new DefaultHttpHeaders());
                        } else if (state.knownLength) {
                            state = State.READ_KNOWN_LENGTH_CONTENT;
                        } else {
                            state = State.READ_INDETERMINATE_LENGTH_CONTENT;
                        }
                        return response;
                    case READ_KNOWN_LENGTH_CONTENT:
                    case READ_INDETERMINATE_LENGTH_CONTENT:
                        assert contentLength >= -1;

                        if (contentLength == -1) {
                            if (in.readableBytes() == 0) {
                                if (completeBodyReceived) {
                                    // There is nothing left to read and the body was marked as receive.
                                    // Just move to the next state.
                                    if (state.knownLength) {
                                        state = State.READ_KNOWN_LENGTH_FIELD_SECTION_TRAILERS;
                                    } else {
                                        // This is the terminator of this content section, move on to the trailers.
                                        state = State.READ_INDETERMINATE_LENGTH_FIELD_SECTION_TRAILERS;
                                    }
                                    break;
                                } else {
                                    // Not enough readable bytes
                                    return null;
                                }
                            }
                            int numBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(in.readerIndex()));
                            if (in.readableBytes() < numBytes) {
                                throwIfNotReadAllAndBodyReceived(in, completeBodyReceived);

                                // Not enough readable bytes
                                return null;
                            }
                            contentLength = readVariableLengthInteger(in, numBytes);
                            if (contentLength == 0) {
                                if (state.knownLength) {
                                    state = State.READ_KNOWN_LENGTH_FIELD_SECTION_TRAILERS;
                                } else {
                                    // This is the terminator of this content section, move on to the trailers.
                                    state = State.READ_INDETERMINATE_LENGTH_FIELD_SECTION_TRAILERS;
                                }
                                contentLength = -1;
                                break;
                            }
                        }

                        int numBytes = (int) Math.min(contentLength, in.readableBytes());
                        contentLength -= numBytes;

                        if (contentLength == 0) {
                            contentLength = -1;
                            if (state.knownLength) {
                                // We did read the whole content, move on to the trailers.
                                state = State.READ_KNOWN_LENGTH_FIELD_SECTION_TRAILERS;
                            }
                        } else if (completeBodyReceived) {
                            throw new CorruptedFrameException("Closed input while still decoding the content");
                        } else if (numBytes == 0) {
                            return null;
                        }
                        return new DefaultHttpContent(in.readRetainedSlice(numBytes));
                    case READ_KNOWN_LENGTH_FIELD_SECTION_TRAILERS:
                    case READ_INDETERMINATE_LENGTH_FIELD_SECTION_TRAILERS:
                        assert contentLength == -1 : "contentLength should have been reset";

                        HttpHeaders trailers = readFieldSection(in, true, state.knownLength, maxFieldSectionSize);
                        if (trailers == null) {
                            if (completeBodyReceived) {
                                throwIfNotReadAllAndBodyReceived(in, true);

                                state = State.READ_PADDING;
                                return LastHttpContent.EMPTY_LAST_CONTENT;
                            }
                            return null;
                        }
                        state = State.READ_PADDING;
                        return new DefaultLastHttpContent(Unpooled.EMPTY_BUFFER, trailers);
                    case READ_PADDING:
                        assert contentLength == -1 : "contentLength should have been reset";
                        readPadding(in);
                        return null;
                    default:
                        throw new IllegalStateException();
                }
            }
        } catch (Exception e) {
            state = State.DISCARD;
            throw e;
        }
    }

    /**
     * Throw a {@link CorruptedFrameException} if decoding is still in progress but the body was marked as complete.
     *
     * @param in                    the {@link ByteBuf} to read from.
     * @param completeBodyReceived  {@code true} if the body was marked as received.
     */
    private static void throwIfNotReadAllAndBodyReceived(ByteBuf in, boolean completeBodyReceived) {
        if (in.isReadable() && completeBodyReceived) {
            throw new CorruptedFrameException("Closed input while still decoding");
        }
    }

    /**
     * Read the <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-padding-and-truncation">padding</a>.
     *
     * @param in                    the {@link ByteBuf} to read from.
     */
    private static void readPadding(ByteBuf in) {
        in.forEachByte(PADDING_VALIDATOR);
        in.skipBytes(in.readableBytes());
    }

    /**
     * Reads and returns the next {@link State} based on the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html#section-3.3">frame indicator</a>.
     *
     * @param in    the {@link ByteBuf} to read from.
     * @return      the next {@link State} to process.
     */
    private static State readFramingIndicator(ByteBuf in) {
        if (!in.isReadable()) {
            return State.READ_FRAME_TYPE;
        }

        int bytesNeeded = numBytesForVariableLengthIntegerFromByte(in.getByte(in.readerIndex()));
        if (bytesNeeded > in.readableBytes()) {
            return State.READ_FRAME_TYPE;
        }

        int framingIndicator = (int) readVariableLengthInteger(in, bytesNeeded);

        switch (framingIndicator) {
            case 0:
                return State.READ_KNOWN_LENGTH_REQUEST_HEAD;
            case 1:
                return State.READ_KNOWN_LENGTH_RESPONSE_HEAD;
            case 2:
                return State.READ_INDETERMINATE_LENGTH_REQUEST_HEAD;
            case 3:
                return State.READ_INDETERMINATE_LENGTH_RESPONSE_HEAD;
            default:
                throw new IllegalArgumentException("Unknown value for a FrameIndicator: " + framingIndicator);
        }
    }

    /**
     * Reads the request head which includes the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-request-control-data">control data</a>
     * and
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-header-and-trailer-field-li">headers field section</a>.
     *
     * @param in                    the {@link ByteBuf} to read from.
     * @param knownLength           {@code true} if the length is known, {@code false} otherwise.
     * @param maxFieldSectionSize   the maximum size of the field-section (in bytes)
     * @return                      {@link BinaryHttpRequest} or {@code null} if not enough bytes are readable yet.
     */
    private static BinaryHttpRequest readRequestHead(ByteBuf in, boolean knownLength, int maxFieldSectionSize) {
        if (!in.isReadable()) {
            return null;
        }

        // Check first if we can access all the control data for the request.
        int sumBytes = 0;
        final int methodLengthIdx = in.readerIndex() + sumBytes;
        final int methodLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(methodLengthIdx));
        sumBytes += methodLengthBytes;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }

        final long methodLength = getVariableLengthInteger(in, methodLengthIdx, methodLengthBytes);
        sumBytes += methodLength;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }
        final int methodIdx = methodLengthIdx + methodLengthBytes;

        final int schemeLengthIdx = in.readerIndex() + sumBytes;
        final int schemeLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(schemeLengthIdx));
        sumBytes += schemeLengthBytes;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }

        final long schemeLength = getVariableLengthInteger(in, schemeLengthIdx, schemeLengthBytes);
        sumBytes += schemeLength;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }
        final int schemeIdx = schemeLengthIdx + schemeLengthBytes;

        final int authorityLengthIdx = in.readerIndex() + sumBytes;
        final int authorityLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(authorityLengthIdx));
        sumBytes += authorityLengthBytes;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }

        final long authorityLength = getVariableLengthInteger(in, authorityLengthIdx, authorityLengthBytes);
        sumBytes += authorityLength;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }
        final int authorityIdx = authorityLengthIdx + authorityLengthBytes;

        final int pathLengthIdx = in.readerIndex() + sumBytes;
        final int pathLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(pathLengthIdx));
        sumBytes += pathLengthBytes;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }

        final long pathLength = getVariableLengthInteger(in, pathLengthIdx, pathLengthBytes);
        sumBytes += pathLength;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }
        final int pathIdx = pathLengthIdx + pathLengthBytes;

        // If we made it this far we had enough data for the whole control data.
        // Try to read the field section now.
        int fieldSectionIdx = in.readerIndex() + sumBytes;
        int fieldSectionLength = in.readableBytes() - sumBytes;
        ByteBuf fieldSectionSlice = in.slice(fieldSectionIdx, fieldSectionLength);

        int fieldSectionReadableBytes = fieldSectionSlice.readableBytes();
        BinaryHttpHeaders headers =
                readFieldSection(fieldSectionSlice, false, knownLength, maxFieldSectionSize);

        if (headers == null) {
            // We didn't have enough readable data to read the whole section, lets return and try again later.
            return null;
        }
        // Add the bytes of the field section as well.
        sumBytes += fieldSectionReadableBytes - fieldSectionSlice.readableBytes();

        // Let's validate method, scheme, authority and path.
        in.forEachByte(methodIdx, (int) methodLength, TOKEN_VALIDATOR);
        in.forEachByte(schemeIdx, (int) schemeLength, SCHEME_VALIDATOR);

        // We only do very limited validation for these to ensure there can nothing be injected.
        in.forEachByte(authorityIdx, (int) authorityLength, TOKEN_VALIDATOR);
        in.forEachByte(pathIdx, (int) pathLength, TOKEN_VALIDATOR);

        String method = in.toString(methodIdx, (int) methodLength, StandardCharsets.US_ASCII);
        String scheme = in.toString(schemeIdx, (int) schemeLength, StandardCharsets.US_ASCII);
        String authority = in.toString(authorityIdx, (int) authorityLength, StandardCharsets.US_ASCII);
        String path = in.toString(pathIdx, (int) pathLength, StandardCharsets.US_ASCII);

        BinaryHttpRequest request = new DefaultBinaryHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.valueOf(method),
                scheme, authority, path, headers);
        in.skipBytes(sumBytes);
        return request;
    }

    /**
     * Reads the response head which includes the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-response-control-data">control data</a>
     * and
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-header-and-trailer-field-li">headers field section</a>.
     *
     * @param in                    the {@link ByteBuf} to read from.
     * @param knownLength           {@code true} if the length is known, {@code false} otherwise.
     * @param maxFieldSectionSize   the maximum size of the field-section (in bytes)
     * @return                      {@link BinaryHttpResponse} or {@code null} if not enough bytes are readable yet.
     */
    private static BinaryHttpResponse readResponseHead(ByteBuf in, boolean knownLength, int maxFieldSectionSize) {
        if (!in.isReadable()) {
            return null;
        }
        int sumBytes = 0;
        final int statusLengthIdx = in.readerIndex();
        final int statusLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(statusLengthIdx));
        sumBytes += statusLengthBytes;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }

        final long status = getVariableLengthInteger(in, statusLengthIdx, statusLengthBytes);
        // If we made it this far we had enough data for the whole control data.
        // Try to read the field section now.
        int fieldSectionIdx = in.readerIndex() + sumBytes;
        int fieldSectionLength = in.readableBytes() - sumBytes;
        ByteBuf fieldSectionSlice = in.slice(fieldSectionIdx, fieldSectionLength);

        int fieldSectionReadableBytes = fieldSectionSlice.readableBytes();
        BinaryHttpHeaders headers = readFieldSection(fieldSectionSlice, false, knownLength, maxFieldSectionSize);

        if (headers == null) {
            // We didn't have enough readable bytes to read the whole section, lets return and try again later.
            return null;
        }
        // Add the bytes of the field section as well.
        sumBytes += fieldSectionReadableBytes - fieldSectionSlice.readableBytes();

        in.skipBytes(sumBytes);

        // Validate status code
        // See https://www.rfc-editor.org/rfc/rfc9292.html#section-3.5.1
        if (status < 100 || status > 599) {
            throw new IllegalArgumentException("Invalid status: " + status);
        }
        HttpResponseStatus responseStatus = HttpResponseStatus.valueOf((int) status);
        return new DefaultBinaryHttpResponse(HttpVersion.HTTP_1_1, responseStatus, headers);
    }

    /**
     * Get the
     * <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-indeterminate-length-messag">indeterminate length</a>
     * of the "section". This will return {@code -1} if the length was not found.
     *
     * @param in    the {@link ByteBuf} to search for the length.
     * @return      the length or {@code -1} if not found in the buffer.
     */
    private static int getIndeterminateLength(ByteBuf in) {
        if (!in.isReadable()) {
            return -1;
        }
        // Start with the name which can never be length of 0.
        boolean name = true;
        for (int sumBytes = 0; sumBytes < in.readableBytes();) {
            int idx = in.readerIndex() + sumBytes;
            int possibleTerminatorBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(idx));
            sumBytes += possibleTerminatorBytes;
            if (in.readableBytes() < sumBytes) {
                return -1;
            }
            long possibleTerminator = getVariableLengthInteger(in, idx, possibleTerminatorBytes);
            sumBytes += possibleTerminator;
            if (in.readableBytes() < sumBytes) {
                return -1;
            }
            if (name && possibleTerminator == 0) {
                // If we are currently parsing the name length and found 0 we know that it must be the terminator
                // as a name cane never be length of 0.
                return sumBytes - possibleTerminatorBytes;
            }
            // We flip between name and not name parsing, as after a name must always follow a value even if its
            // length of 0.
            name = !name;
        }
        return -1;
    }

    /**
     * Reads the field section <a href="https://www.rfc-editor.org/rfc/rfc9292.html#name-format">field section</a>.
     *
     * @param in                    the {@link ByteBuf} to read from.
     * @param knownLength           {@code true} if the length is known, {@code false} otherwise.
     * @param maxFieldSectionSize   the maximum size of the field-section (in bytes)
     * @return                      {@link BinaryHttpHeaders} or {@code null} if not enough bytes are readable yet.
     */
    private static BinaryHttpHeaders readFieldSection(
            ByteBuf in, boolean trailers, boolean knownLength, int maxFieldSectionSize) {
        if (!in.isReadable()) {
            return null;
        }

        final int fieldSectionBytes;
        long fieldSectionLength;
        int sumBytes = 0;
        if (knownLength) {
            fieldSectionBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(in.readerIndex()));
            sumBytes += fieldSectionBytes;
            if (in.readableBytes() < sumBytes) {
                checkFieldSectionTooLarge(in.readableBytes(), maxFieldSectionSize);
                return null;
            }
            fieldSectionLength = getVariableLengthInteger(in, in.readerIndex(), fieldSectionBytes);
            sumBytes += fieldSectionLength;
        } else {
            int indeterminateLength = getIndeterminateLength(in);
            assert indeterminateLength >= -1;
            if (indeterminateLength == -1) {
                checkFieldSectionTooLarge(in.readableBytes(), maxFieldSectionSize);
                return null;
            }
            fieldSectionBytes = 0;
            fieldSectionLength = indeterminateLength;
            // We add +1 for the terminator.
            sumBytes = (int) fieldSectionLength + 1;
        }

        checkFieldSectionTooLarge(fieldSectionLength, maxFieldSectionSize);

        if (in.readableBytes() < sumBytes) {
            // We could read in a more incremental way but let us keep it simple for now so we don't need
            // any extra state.
            return null;
        }
        in.skipBytes(fieldSectionBytes);

        BinaryHttpHeaders headers = trailers ?
                BinaryHttpHeaders.newTrailers(true) : BinaryHttpHeaders.newHeaders(true);
        HeaderType lastType = HeaderType.PSEUDO_HEADER;
        while (fieldSectionLength != 0) {
            int readableBytes = in.readableBytes();
            lastType = readFieldLine(in, headers, lastType, trailers);
            assert lastType != null;
            int read = readableBytes - in.readableBytes();
            assert read > 0;
            fieldSectionLength -= read;
        }
        if (!knownLength) {
            // Skip the 0 terminator as well.
            int terminator = in.readByte();
            assert terminator == 0;
        }

        return headers;
    }

    private static void checkFieldSectionTooLarge(long fieldSectionSize, int maxFieldSectionSize) {
        if (fieldSectionSize > maxFieldSectionSize) {
            // Guard against buffering too much bytes.
            // See https://www.rfc-editor.org/rfc/rfc9292.html#section-8
            throw new TooLongFrameException("field-section length exceeds configured maximum: "
                    + fieldSectionSize + " > " + maxFieldSectionSize);
        }
    }

    /**
     * Read a <a href="https://www.rfc-editor.org/rfc/rfc9292.html#section-3.6">Field line</a> and add it to the
     * {@link HttpHeaders}.
     *
     * @param in        the {@link ByteBuf} to read from.
     * @param headers   the {@link HttpHeaders} to which we add the field line.
     * @param trailers  {@code true} if parsing the trailers, {@code false} otherwise.
     * @return          the number of bytes for this field line or {@code -1} if there are not enough readable bytes.
     */
    private static HeaderType readFieldLine(ByteBuf in, HttpHeaders headers, HeaderType lastType, boolean trailers) {
        if (!in.isReadable()) {
            return null;
        }

        int sumBytes = 0;
        final int nameLengthIdx = in.readerIndex();
        final int nameLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(in.readerIndex()));
        sumBytes += nameLengthBytes;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }

        final long nameLength = getVariableLengthInteger(in, in.readerIndex(), nameLengthBytes);
        sumBytes += nameLength;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }
        final int nameIdx = nameLengthIdx + nameLengthBytes;

        final int valueLengthIdx = nameIdx + (int) nameLength;
        final int valueLengthBytes = numBytesForVariableLengthIntegerFromByte(in.getByte(valueLengthIdx));
        sumBytes += valueLengthBytes;

        final long valueLength = getVariableLengthInteger(in, valueLengthIdx, valueLengthBytes);
        sumBytes += valueLength;
        if (sumBytes >= in.readableBytes()) {
            return null;
        }
        final int valueIdx = valueLengthIdx + valueLengthBytes;

        CharSequence name = in.getCharSequence(nameIdx, (int) nameLength, StandardCharsets.US_ASCII);

        // Validate fields for pseudo-fields:
        // https://www.rfc-editor.org/rfc/rfc9292.html#section-3.6
        boolean pseudo = PseudoHeaderName.hasPseudoHeaderFormat(name);
        if (pseudo) {
            if (trailers) {
                throw new DecoderException("pseudo-fields are not allowed in trailers: " + name);
            }
            if (PseudoHeaderName.isPseudoHeader(name)) {
                throw new DecoderException("pseudo-field not allowed in headers: " + name);
            }
            if (lastType == HeaderType.REGULAR_HEADER) {
                throw new DecoderException("pseudo-field must not follow non pseudo-field");
            }
        }

        CharSequence value = in.getCharSequence(valueIdx, (int) valueLength, StandardCharsets.US_ASCII);
        headers.add(name, value);

        in.skipBytes(sumBytes);
        return pseudo ? HeaderType.PSEUDO_HEADER : HeaderType.REGULAR_HEADER;
    }

    private enum HeaderType {
        REGULAR_HEADER,
        PSEUDO_HEADER,
    }
}
