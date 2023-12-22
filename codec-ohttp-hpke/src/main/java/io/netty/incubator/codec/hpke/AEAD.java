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
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi">Authenticated Encryption with Associated Data (AEAD) Functions</a>
 */
public enum AEAD {
    AES_GCM128((short) 0x0001, 16, 12),
    AES_GCM256((short) 0x0002, 32, 12),
    CHACHA20_POLY1305((short) 0x0003, 32, 12);

    public static AEAD forId(short id) {
        for (AEAD val : values()) {
            if (val.id == id) {
                return val;
            }
        }
        throw new IllegalArgumentException("unknown AEAD id " + id);
    }

    private final short id;
    private final int nk;
    private final int nn;

    AEAD(short id, int nk, int nn) {
        this.id = id;
        this.nk = nk;
        this.nn = nn;
    }

    public short id() {
        return id;
    }

    public int nk() {
        return nk;
    }

    public int nn() {
        return nn;
    }
}
