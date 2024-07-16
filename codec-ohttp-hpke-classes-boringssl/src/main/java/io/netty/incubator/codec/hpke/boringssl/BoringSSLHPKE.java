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

/**
 * Helper class to check if the native BoringSSL based crypto can be used.
 */
public final class BoringSSLHPKE {

    private static final Throwable UNAVAILABILITY_CAUSE;

    static {
        Throwable cause = null;

        try {
            long ctx = BoringSSL.EVP_HPKE_KEY_new();
            BoringSSL.EVP_HPKE_CTX_cleanup_and_free(ctx);
        } catch (Throwable error) {
            cause = error;
        }

        UNAVAILABILITY_CAUSE = cause;
    }

    /**
     * Returns {@code true} if and only if the HPKE implementation is usable on the running platform is available.
     *
     * @return {@code true} if this HPKE implementation can be used on the current platform, {@code false} otherwise.
     */
    public static boolean isAvailable() {
        return UNAVAILABILITY_CAUSE == null;
    }

    /**
     * Ensure that HPKE implementation is usable on the running platform is available.
     *
     * @throws UnsatisfiedLinkError if unavailable
     */
    public static void ensureAvailability() {
        if (UNAVAILABILITY_CAUSE != null) {
            throw (Error) new UnsatisfiedLinkError(
                    "failed to load the required native library").initCause(UNAVAILABILITY_CAUSE);
        }
    }

    /**
     * Returns the cause of unavailability.
     *
     * @return the cause if unavailable. {@code null} if available.
     */
    public static Throwable unavailabilityCause() {
        return UNAVAILABILITY_CAUSE;
    }

    private BoringSSLHPKE() { }
}
