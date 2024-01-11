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
import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKERecipientContext;

/**
 * BoringSSL based {@link HPKERecipientContext}.
 */
final class BoringSSLHPKERecipientContext extends BoringSSLHPKEContext implements HPKERecipientContext {
    // See https://github.com/google/boringssl/blob/ac45226f8d8223d70ed37cf81df5f03aea1d533c/include/openssl/hpke.h#L290
    private static final BoringSSLCryptoOperation OPEN = new BoringSSLCryptoOperation() {
        @Override
        int maxOutLen(long ctx, int inReadable) {
            return inReadable;
        }

        @Override
        int execute(long ctx, long ad, int adLen, long in, int inLen, long out, int outLen) {
            return BoringSSL.EVP_HPKE_CTX_open(ctx, out, outLen, in, inLen, ad, adLen);
        }
    };

    BoringSSLHPKERecipientContext(long hpkeCtx) {
        super(hpkeCtx);
    }

    @Override
    public void open(ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException {
        if (!OPEN.execute(checkClosedAndReturnCtx(), aad, ct, out)) {
            throw new CryptoException("open(...) failed");
        }
    }

    @Override
    public boolean isDirectBufferPreferred() {
        return true;
    }
}
