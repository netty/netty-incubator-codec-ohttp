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

import io.netty.incubator.codec.hpke.CryptoContext;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Abstract base class for BoringSSL based {@link CryptoContext}.
 */
abstract class BoringSSLCryptoContext implements CryptoContext {

    // We use an AtomicLong to reduce the possibility of crashing after the user called close().
    private final AtomicLong ctxRef;

    BoringSSLCryptoContext(long ctx) {
        assert ctx != -1;
        this.ctxRef = new AtomicLong(ctx);
    }
    protected final long checkClosedAndReturnCtx() {
        long ctx = ctxRef.get();
        if (ctx == -1) {
            throw new IllegalStateException(getClass().getSimpleName() + " closed");
        }
        return ctx;
    }

    @Override
    public final void close()  {
       long ctx = ctxRef.getAndSet(-1);
       if (ctx != -1) {
           destroyCtx(ctx);
       }
    }
    
    protected abstract void destroyCtx(long ctx);
}
