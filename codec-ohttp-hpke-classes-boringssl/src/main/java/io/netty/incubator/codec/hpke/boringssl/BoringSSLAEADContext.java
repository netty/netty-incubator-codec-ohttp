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

final class BoringSSLAEADContext extends BoringSSLCryptoContext implements AEADContext {

    private final ByteBuf baseNonce;
    private final long baseNonceAddress;
    private final int baseNonceLen;
    private final int AEAD_max_overhead;

    private final BoringSSLCryptoOperation seal = new BoringSSLCryptoOperation() {
        @Override
        int maxOutLen(long ctx, int inReadable) {
            return AEAD_max_overhead + inReadable;
        }

        @Override
        int execute(long ctx, long ad, int adLen, long in, int inLen, long out, int outLen) {
            return BoringSSL.EVP_AEAD_CTX_seal(ctx, out, outLen, baseNonceAddress, baseNonceLen, in, inLen, ad, adLen);
        }
    };

    private final BoringSSLCryptoOperation open = new BoringSSLCryptoOperation() {
        @Override
        int maxOutLen(long ctx, int inReadable) {
            return inReadable;
        }

        @Override
        int execute(long ctx, long ad, int adLen, long in, int inLen, long out, int outLen) {
            return BoringSSL.EVP_AEAD_CTX_open(ctx, out, outLen, baseNonceAddress, baseNonceLen, in, inLen, ad, adLen);
        }
    };

    BoringSSLAEADContext(long ctx, int AEAD_max_overhead, byte[] baseNonce) {
        super(ctx);
        this.baseNonce = Unpooled.directBuffer(baseNonce.length).writeBytes(baseNonce);
        this.baseNonceAddress = BoringSSL.memory_address(this.baseNonce);
        this.baseNonceLen = this.baseNonce.readableBytes();
        this.AEAD_max_overhead = AEAD_max_overhead;
    }

    @Override
    protected void destroyCtx(long ctx) {
        baseNonce.release();
        BoringSSL.EVP_AEAD_CTX_cleanup_and_free(ctx);
    }

    @Override
    public void open(ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException {
        if (!open.execute(checkClosedAndReturnCtx(), aad, ct, out)) {
            throw new CryptoException("open(...) failed");
        }
    }

    @Override
    public void seal(ByteBuf aad, ByteBuf pt, ByteBuf out) throws CryptoException {
        if (!seal.execute(checkClosedAndReturnCtx(), aad, pt, out)) {
            throw new CryptoException("seal(...) failed");
        }
    }
}
