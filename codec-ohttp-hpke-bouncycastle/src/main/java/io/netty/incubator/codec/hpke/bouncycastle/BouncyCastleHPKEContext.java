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
package io.netty.incubator.codec.hpke.bouncycastle;

import io.netty.incubator.codec.hpke.HPKEContext;

abstract class BouncyCastleHPKEContext implements HPKEContext {
    protected final org.bouncycastle.crypto.hpke.HPKEContext context;
    private boolean closed;

    BouncyCastleHPKEContext(org.bouncycastle.crypto.hpke.HPKEContext context) {
        this.context = context;
    }

    @Override
    public byte[] export(byte[] exportContext, int length) {
        checkClosed();
        return context.export(exportContext, length);
    }

    @Override
    public byte[] extract(byte[] salt, byte[] ikm) {
        checkClosed();
        return context.extract(salt, ikm);
    }

    @Override
    public byte[] expand(byte[] prk, byte[] info, int length) {
        checkClosed();
        return context.expand(prk, info, length);
    }

    protected void checkClosed() {
        if (closed) {
            throw new IllegalStateException("AEADContext closed");
        }
    }

    @Override
    public void close() {
        closed = true;
    }
}
