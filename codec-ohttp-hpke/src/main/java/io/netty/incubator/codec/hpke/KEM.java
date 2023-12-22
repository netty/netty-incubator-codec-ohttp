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
package io.netty.incubator.codec.hpke;

/**
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1">Key Encapsulation Mechanism</a>
 */
public enum KEM {
    P256_SHA256((short) 16, 65, 65),
    P384_SHA348((short) 17, 97, 97),
    P521_SHA512((short) 18, 133, 133),
    X25519_SHA256((short) 32, 32, 32),
    X448_SHA512((short) 33, 56, 56);

    public static KEM forId(short id) {
        for (KEM val : values()) {
            if (val.id == id) {
                return val;
            }
        }
        throw new IllegalArgumentException("unknown KEM id " + id);
    }

    KEM(short id, int nenc, int npk) {
        this.id = id;
        this.nenc = nenc;
        this.npk = npk;
    }

    private final short id;
    private final int nenc;
    private final int npk;

    public short id() {
        return id;
    }

    public int nenc() {
        return nenc;
    }

    public int npk() {
        return npk;
    }
}
