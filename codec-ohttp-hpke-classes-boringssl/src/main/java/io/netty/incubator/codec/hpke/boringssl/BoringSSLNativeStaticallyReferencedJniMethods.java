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

final class BoringSSLNativeStaticallyReferencedJniMethods {
    static native long EVP_hpke_x25519_hkdf_sha256();
    static native long EVP_hpke_hkdf_sha256();
    static native long EVP_hpke_aes_128_gcm();
    static native long EVP_hpke_aes_256_gcm();
    static native long EVP_hpke_chacha20_poly1305();

    static native long EVP_aead_aes_128_gcm();
    static native long EVP_aead_aes_256_gcm();
    static native long EVP_aead_chacha20_poly1305();

    static native int EVP_AEAD_DEFAULT_TAG_LENGTH();

    private BoringSSLNativeStaticallyReferencedJniMethods() { }
}
