/*
 * Copyright 2024 The Netty Project
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
package io.netty.incubator.codec.hpke;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.concurrent.FastThreadLocal;
import io.netty.util.concurrent.FastThreadLocalThread;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicReference;

import static io.netty.util.internal.ObjectUtil.checkPositiveOrZero;
import static java.util.Objects.requireNonNull;

/**
 * {@link OHttpCryptoProvider} implementation which will re-use existing {@link HPKERecipientContext} and
 * {@link HPKESenderContext} instances if possible to reduce overhead.
 * <strong>Important:</strong> As the {@link HPKESenderContext} contains an ephemeral key, so this has security
 * implications which you should be aware of.
 *
 * <p>
 * Be aware only {@link FastThreadLocalThread}s will use a cache.
 */
public final class CachingOHttpCryptoProvider implements OHttpCryptoProvider {
    private final int maxCachedRecipientContexts;
    private final int maxCachedSenderContexts;
    private final OHttpCryptoProvider provider;

    private static final CachedHPKERecipientContextHolder[] EMPTY_RECIPIENT_HOLDERS =
            new CachedHPKERecipientContextHolder[0];
    private static final CachedHPKESenderContextHolder[] EMPTY_SENDER_HOLDERS =
            new CachedHPKESenderContextHolder[0];
    private final FastThreadLocal<CachedHPKERecipientContextHolder[]> recipientContexts =
            new FastThreadLocal<CachedHPKERecipientContextHolder[]>() {
        @Override
        protected CachedHPKERecipientContextHolder[] initialValue() {
            if (FastThreadLocalThread.willCleanupFastThreadLocals(Thread.currentThread())) {
                return new CachedHPKERecipientContextHolder[maxCachedRecipientContexts];
            }
            // No caching as we can not guarantee cleanup of resources
            return EMPTY_RECIPIENT_HOLDERS;
        }

        @Override
        protected void onRemoval(CachedHPKERecipientContextHolder[] value) {
            if (value != null) {
                for (CachedHPKERecipientContextHolder h: value) {
                    h.release();
                }
            }
        }
    };

    private final FastThreadLocal<CachedHPKESenderContextHolder[]> senderContexts =
            new FastThreadLocal<CachedHPKESenderContextHolder[]>() {
        @Override
        protected CachedHPKESenderContextHolder[] initialValue() {
            if (FastThreadLocalThread.willCleanupFastThreadLocals(Thread.currentThread())) {
                return new CachedHPKESenderContextHolder[maxCachedSenderContexts];
            }
            // No caching as we can not guarantee cleanup of resources
            return EMPTY_SENDER_HOLDERS;
        }

        @Override
        protected void onRemoval(CachedHPKESenderContextHolder[] value) {
            if (value != null) {
                for (CachedHPKESenderContextHolder h: value) {
                    h.release();
                }
            }
        }
    };

    /**
     * Create a new instance
     * @param provider                      the {@link OHttpCryptoProvider} that is used.
     * @param maxCachedRecipientContexts    the maximum number of {@link HPKERecipientContext}s that will be cached
     *                                      per thread.
     * @param maxCachedSenderContexts       the maximum number of {@link HPKESenderContext}s that will be cached
     *      *                               per thread.
     */
    public CachingOHttpCryptoProvider(OHttpCryptoProvider provider,
                                      int maxCachedRecipientContexts, int maxCachedSenderContexts) {
        this.provider = requireNonNull(provider, "provider");
        this.maxCachedRecipientContexts = checkPositiveOrZero(maxCachedRecipientContexts, "maxCachedRecipientContexts");
        this.maxCachedSenderContexts = checkPositiveOrZero(maxCachedSenderContexts, "maxCachedSenderContexts");
    }

    @Override
    public AEADContext setupAEAD(AEAD aead, byte[] key, byte[] baseNonce) {
        return provider.setupAEAD(aead, key, baseNonce);
    }

    @Override
    public HPKESenderContext setupHPKEBaseS(KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR, byte[] info,
                                            AsymmetricCipherKeyPair kpE) {
        CachedHPKESenderContextHolder[] array = senderContexts.get();
        for (int i = 0; i < array.length; i++) {
            CachedHPKESenderContextHolder h = array[i];
            if (h == null) {
                return createNewCachedHPKESenderContext(array, i, kem, kdf, aead, pkR, info, kpE);
            } else if (h.isMatch(kem, kdf, aead, pkR, info, kpE)) {
                h.retain();
                return h.ctx;
            }
        }
        if (array.length != 0) {
            // Just replace something that was cached randomly.
            return createNewCachedHPKESenderContext(array,
                    ThreadLocalRandom.current().nextInt(0, array.length), kem, kdf, aead, pkR, info, kpE);
        }
        return provider.setupHPKEBaseS(kem, kdf, aead, pkR, info, kpE);
    }

    private HPKESenderContext createNewCachedHPKESenderContext(
            CachedHPKESenderContextHolder[] array, int idx, KEM kem, KDF kdf, AEAD aead,
            AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE) {
        HPKESenderContext ctx = provider.setupHPKEBaseS(kem, kdf, aead, pkR, info, kpE);

        CachedHPKESenderContextHolder old = array[idx];
        if (old == null || old.refCnt() <= 10) {
            CachedHPKESenderContextHolder h = new CachedHPKESenderContextHolder(ctx,
                    kem, kdf, aead, pkR, info, kpE);
            array[idx] = h;
            if (old != null) {
                old.release();
            }
            h.retain();
            return h.ctx;
        }
        return ctx;
    }

    @Override
    public HPKERecipientContext setupHPKEBaseR(KEM kem, KDF kdf, AEAD aead, byte[] enc, AsymmetricCipherKeyPair skR,
                                               byte[] info) {
        CachedHPKERecipientContextHolder[] array = recipientContexts.get();
        for (int i = 0; i < array.length; i++) {
            CachedHPKERecipientContextHolder h = array[i];
            if (h == null) {
                return createNewCachedHPKERecipientContext(array, i, kem, kdf, aead, enc, skR, info);
            } else if (h.isMatch(kem, kdf, aead, enc, skR, info)) {
                h.retain();
                return h.ctx;
            }
        }
        if (array.length != 0) {
            // Just replace something that was cached randomly
            return createNewCachedHPKERecipientContext(array,
                    ThreadLocalRandom.current().nextInt(0, array.length), kem, kdf, aead, enc, skR, info);
        }
        return provider.setupHPKEBaseR(kem, kdf, aead, enc, skR, info);
    }

    private HPKERecipientContext createNewCachedHPKERecipientContext(
            CachedHPKERecipientContextHolder[] array, int idx, KEM kem, KDF kdf, AEAD aead, byte[] enc,
            AsymmetricCipherKeyPair skR, byte[] info) {
        HPKERecipientContext ctx = provider.setupHPKEBaseR(kem, kdf, aead, enc, skR, info);

        CachedHPKERecipientContextHolder old = array[idx];
        if (old == null || old.refCnt() <= 10) {
            CachedHPKERecipientContextHolder h = new CachedHPKERecipientContextHolder(ctx,
                    kem, kdf, aead, enc, skR, info);
            array[idx] = h;
            if (old != null) {
                old.release();
            }
            h.retain();
            return h.ctx;
        }
        return ctx;
    }

    @Override
    public AsymmetricCipherKeyPair deserializePrivateKey(KEM kem, byte[] privateKeyBytes, byte[] publicKeyBytes) {
        return provider.deserializePrivateKey(kem, privateKeyBytes, publicKeyBytes);
    }

    @Override
    public AsymmetricKeyParameter deserializePublicKey(KEM kem, byte[] publicKeyBytes) {
        return provider.deserializePublicKey(kem, publicKeyBytes);
    }

    @Override
    public AsymmetricCipherKeyPair newRandomPrivateKey(KEM kem) {
        return provider.newRandomPrivateKey(kem);
    }

    @Override
    public boolean isSupported(AEAD aead) {
        return provider.isSupported(aead);
    }

    @Override
    public boolean isSupported(KEM kem) {
        return provider.isSupported(kem);
    }

    @Override
    public boolean isSupported(KDF kdf) {
        return provider.isSupported(kdf);
    }

    private abstract static class CachedHPKEContextHolder<T extends HPKEContext> extends AbstractReferenceCounted {

        abstract T context();

        @Override
        protected void deallocate() {
            context().close();
        }

        @Override
        public CachedHPKEContextHolder<T> touch(Object o) {
            return this;
        }
    }

    private static final class CachedHPKERecipientContextHolder extends CachedHPKEContextHolder<HPKERecipientContext> {
        private final HPKERecipientContext ctx;
        private final KEM kem;
        private final KDF kdf;
        private final AEAD aead;
        private final byte[] enc;
        private final AsymmetricCipherKeyPair skR;
        private final byte[] info;

        CachedHPKERecipientContextHolder(HPKERecipientContext ctx, KEM kem, KDF kdf, AEAD aead, byte[] enc,
                                         AsymmetricCipherKeyPair skR, byte[] info) {
            this.kem = kem;
            this.kdf = kdf;
            this.aead = aead;
            this.enc = enc;
            this.skR = skR;
            this.info = info;
            this.ctx = new PooledHPKERecipientContext(ctx, this);
        }

        @Override
        HPKERecipientContext context() {
            return ctx;
        }

        boolean isMatch(KEM kem, KDF kdf, AEAD aead, byte[] enc, AsymmetricCipherKeyPair skR, byte[] info) {
            return this.kem == kem &&
                    this.kdf == kdf &&
                    this.aead == aead &&
                    Objects.equals(this.skR, skR) &&
                    Arrays.equals(this.enc, enc) &&
                    Arrays.equals(this.info, info);
        }
    }

    private static final class PooledHPKERecipientContext extends PooledHPKEContext<HPKERecipientContext>
            implements HPKERecipientContext {

        PooledHPKERecipientContext(HPKERecipientContext ctx, CachedHPKEContextHolder<HPKERecipientContext> holder) {
            super(ctx, holder);
        }

        @Override
        public void open(ByteBufAllocator alloc, ByteBuf aad, ByteBuf ct, ByteBuf out) throws CryptoException {
            getCtxChecked().open(alloc, aad, ct, out);
        }

        @Override
        public boolean isDirectBufferPreferred() {
            return getCtxChecked().isDirectBufferPreferred();
        }
    }

    private static final class CachedHPKESenderContextHolder extends CachedHPKEContextHolder<HPKESenderContext> {
        private final HPKESenderContext ctx;
        private final KEM kem;
        private final KDF kdf;
        private final AEAD aead;
        private final AsymmetricKeyParameter pkR;
        private final byte[] info;
        private final AsymmetricCipherKeyPair kpE;

        CachedHPKESenderContextHolder(HPKESenderContext ctx, KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR,
                                      byte[] info, AsymmetricCipherKeyPair kpE) {
            this.kem = kem;
            this.kdf = kdf;
            this.aead = aead;
            this.pkR = pkR;
            this.info = info;
            this.kpE = kpE;
            this.ctx = new PooledHPKESenderContext(ctx, this);
        }

        boolean isMatch(KEM kem, KDF kdf, AEAD aead, AsymmetricKeyParameter pkR, byte[] info,
                               AsymmetricCipherKeyPair kpE) {
            return this.kem == kem &&
                    this.kdf == kdf &&
                    this.aead == aead &&
                    Objects.equals(this.pkR, pkR) &&
                    Objects.equals(this.kpE, kpE) &&
                    Arrays.equals(this.info, info);
        }

        @Override
        HPKESenderContext context() {
            return ctx;
        }
    }

    private static final class PooledHPKESenderContext extends PooledHPKEContext<HPKESenderContext>
            implements HPKESenderContext {
        PooledHPKESenderContext(HPKESenderContext ctx, CachedHPKEContextHolder<HPKESenderContext> holder) {
            super(ctx, holder);
        }

        @Override
        public void seal(ByteBufAllocator alloc, ByteBuf aad, ByteBuf pt, ByteBuf out) throws CryptoException {
            getCtxChecked().seal(alloc, aad, pt, out);
        }

        @Override
        public boolean isDirectBufferPreferred() {
            return getCtxChecked().isDirectBufferPreferred();
        }

        @Override
        public byte[] encapsulation() {
            return getCtxChecked().encapsulation();
        }
    }

    private abstract static class PooledHPKEContext<T extends HPKEContext> implements HPKEContext {

        private final AtomicReference<CachedHPKEContextHolder<T>> ref = new AtomicReference<>();

        private final T ctx;

        PooledHPKEContext(T ctx, CachedHPKEContextHolder<T> holder) {
            this.ctx = ctx;
            this.ref.set(holder);
        }

        @Override
        public final void close() {
            CachedHPKEContextHolder<T> h = ref.getAndSet(null);
            if (h != null) {
                h.release();
            }
        }

        protected final T getCtxChecked() {
            if (ref.get() == null) {
                throw new IllegalStateException(getClass().getSimpleName() + " closed");
            }
            return ctx;
        }

        @Override
        public final byte[] export(byte[] exportContext, int length) {
            return getCtxChecked().export(exportContext, length);
        }

        @Override
        public final byte[] extract(byte[] salt, byte[] ikm) {
            return getCtxChecked().extract(salt, ikm);
        }

        @Override
        public final byte[] expand(byte[] prk, byte[] info, int length) {
            return getCtxChecked().expand(prk, info, length);
        }
    }
}
