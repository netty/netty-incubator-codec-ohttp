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
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-hybrid-public-key-encryptio">Hybrid Public Key Encryption</a>
 */
public enum HPKEMode {
    Base((byte) 0x00),
    Psk((byte) 0x01),
    Auth((byte) 0x02),
    AuthPsk((byte) 0x03);

    private final byte id;

    HPKEMode(byte id) {
        this.id = id;
    }

    public byte value() {
        return id;
    }

    public static HPKEMode forId(byte id) {
        for (HPKEMode val : values()) {
            if (val.id == id) {
                return val;
            }
        }
        throw new IllegalArgumentException("unknown Mode id " + id);
    }
}
