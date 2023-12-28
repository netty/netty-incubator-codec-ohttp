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
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd">
 *     Key Derivation Functions (KDFs)</a>
 */
public enum KDF {
    HKDF_SHA256((short) 0x0001),
    HKDF_SHA384((short) 0x0002),
    HKDF_SHA512((short) 0x0003);

    public static KDF forId(short id) {
        for (KDF val : values()) {
            if (val.id == id) {
                return val;
            }
        }
        throw new IllegalArgumentException("unknown KDF id " + id);
    }

    private final short id;

    KDF(short id) {
        this.id = id;
    }

    public short id() {
        return id;
    }
}
