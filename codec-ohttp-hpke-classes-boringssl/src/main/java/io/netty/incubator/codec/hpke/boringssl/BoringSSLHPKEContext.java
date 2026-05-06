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

import io.netty.incubator.codec.hpke.CryptoException;
import io.netty.incubator.codec.hpke.HPKEContext;

/**
 * BoringSSL based {@link HPKEContext}.
 */
class BoringSSLHPKEContext extends BoringSSLCryptoContext implements HPKEContext {

    private final long digest;

    BoringSSLHPKEContext(long hpkeCtx) {
        super(hpkeCtx);
        digest = BoringSSL.EVP_HPKE_KDF_hkdf_md(BoringSSL.EVP_HPKE_CTX_kdf(hpkeCtx));
    }

    @Override
    public final byte[] export(byte[] exportContext, int length) throws CryptoException {
        long ctx = checkClosedAndReturnCtx();
        byte[] exported = BoringSSL.EVP_HPKE_CTX_export(ctx, length, exportContext);
        if (exported == null) {
            throw new CryptoException("Unable to export secret");
        }
        return exported;
    }

    @Override
    public final byte[] extract(byte[] salt, byte[] ikm) throws CryptoException {
        byte[] extracted = BoringSSL.HKDF_extract(digest, ikm, salt);
        if (extracted == null) {
            throw new CryptoException("Unable to extract a pseudorandom secret");
        }
        return extracted;
    }

    @Override
    public final byte[] expand(byte[] prk, byte[] info, int length) throws CryptoException {
        byte[] expanded = BoringSSL.HKDF_expand(digest, length, prk, info);
        if (expanded == null) {
            throw new CryptoException("Unable to expand pseudorandom key");
        }
        return expanded;
    }

    @Override
    protected final void destroyCtx(long ctx) {
        BoringSSL.EVP_HPKE_CTX_cleanup_and_free(ctx);
    }
}
