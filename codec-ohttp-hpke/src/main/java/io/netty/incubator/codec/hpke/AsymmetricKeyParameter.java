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
 * The key parameter.
 */
public interface AsymmetricKeyParameter {

    /**
     * Returns the parameter as byte encoded or {@code null}
     * if not supported by the used implementation or parameter type.
     *
     * @return encoded.
     */
    byte[] encoded();

    /**
     * Returns {@code true} if this is the private key, {@code false} otherwise.
     *
     * @return {@code true} if this is the private key.
     */
    boolean isPrivate();
}
