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
package io.netty.incubator.codec.hpke.boringssl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.incubator.codec.hpke.AEADContext;
import io.netty.incubator.codec.hpke.CryptoException;

/**
 * BoringSSL based implementation of an {@link AEADContext}.
 */
final class BoringSSLAEADContext extends BoringSSLCryptoContext implements AEADContext {

    private final ByteBuf nonce;
    private final long nonceAddress;
    private final int nonceLen;
    private final byte[] baseNonce;
    private final int aeadMaxOverhead;

    private int seq;

    private final BoringSSLCryptoOperation seal = new BoringSSLCryptoOperation() {
        @Override
        int maxOutLen(long ctx, int inReadable) {
            return aeadMaxOverhead + inReadable;
        }

        @Override
        int execute(long ctx, long ad, int adLen, long in, int inLen, long out, int outLen) {
            return BoringSSL.EVP_AEAD_CTX_seal(ctx, out, outLen, computeNonce(), nonceLen, in, inLen, ad, adLen);
        }
    };

    private final BoringSSLCryptoOperation open = new BoringSSLCryptoOperation() {
        @Override
        int maxOutLen(long ctx, int inReadable) {
            return inReadable;
        }

        @Override
        int execute(long ctx, long ad, int adLen, long in, int inLen, long out, int outLen) {
            return BoringSSL.EVP_AEAD_CTX_open(ctx, out, outLen, computeNonce(), nonceLen, in, inLen, ad, adLen);
        }
    };

    BoringSSLAEADContext(long ctx, int aeadMaxOverhead, byte[] baseNonce) {
        super(ctx);
        this.baseNonce = baseNonce.clone();

        nonce = Unpooled.directBuffer(baseNonce.length).writeBytes(baseNonce);
        this.nonceAddress = BoringSSL.memory_address(nonce);
        this.nonceLen = nonce.readableBytes();
        this.aeadMaxOverhead = aeadMaxOverhead;
    }

    @Override
    protected void destroyCtx(long ctx) {
        nonce.release();
        BoringSSL.EVP_AEAD_CTX_cleanup_and_free(ctx);
    }

    @Override
    public void open(ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException {
        if (!open.execute(checkClosedAndReturnCtx(), aad, ct, out)) {
            throw new CryptoException("open(...) failed");
        }
        seq++;
    }

    @Override
    public void seal(ByteBuf aad, ByteBuf pt, ByteBuf out) throws CryptoException {
        if (!seal.execute(checkClosedAndReturnCtx(), aad, pt, out)) {
            throw new CryptoException("seal(...) failed");
        }
        seq++;
    }

    /**
     * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2">Compute the nonce to use</a>
     * @return memory address of the nonce buffer.
     */
    private long computeNonce() {
        for(int idx = 0, idx2 = baseNonce.length - 8 ; idx < 8; ++idx, ++idx2) {
            nonce.setByte(idx2, baseNonce[idx2] ^ bigEndianByteAt(idx, seq));
        }
        return nonceAddress;
    }

    private static byte bigEndianByteAt(int idx, long value) {
        switch (idx) {
            case 0:
                return (byte) (value >>> 56);
            case 1:
                return (byte) (value >>> 48);
            case 2:
                return (byte) (value >>> 40);
            case 3:
                return (byte) (value >>> 32);
            case 4:
                return (byte) (value >>> 24);
            case 5:
                return (byte) (value >>> 16);
            case 6:
                return (byte) (value >>> 8);
            case 7:
                return (byte) value;
            default:
                throw new IndexOutOfBoundsException();
        }
    }
}
