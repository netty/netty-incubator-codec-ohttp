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

import io.netty.incubator.codec.hpke.HPKEContext;

/**
 * BoringSSL based {@link HPKEContext}.
 */
class BoringSSLHPKEContext extends BoringSSLCryptoContext implements HPKEContext {

    private final long digest;

    BoringSSLHPKEContext(BoringSSLOHttpCryptoProvider cryptoProvider, long hpkeCtx) {
        super(cryptoProvider, hpkeCtx);
        digest = BoringSSL.EVP_HPKE_KDF_hkdf_md(BoringSSL.EVP_HPKE_CTX_kdf(hpkeCtx));
    }

    @Override
    public final byte[] export(byte[] exportContext, int length) {
        long ctx = checkClosedAndReturnCtx();
        return BoringSSL.EVP_HPKE_CTX_export(ctx, length, exportContext);
    }

    @Override
    public final byte[] extract(byte[] salt, byte[] ikm) {
        return BoringSSL.HKDF_extract(digest, ikm, salt);
    }

    @Override
    public final byte[] expand(byte[] prk, byte[] info, int length) {
        return BoringSSL.HKDF_expand(digest, length, prk, info);
    }

    @Override
    protected final void destroyCtx(long ctx) {
        BoringSSL.EVP_HPKE_CTX_cleanup_and_free(ctx);
    }
}
