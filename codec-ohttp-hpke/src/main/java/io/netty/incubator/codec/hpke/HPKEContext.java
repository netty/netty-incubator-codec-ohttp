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
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1">The context for HPKE</a>.
 */
public interface HPKEContext extends CryptoContext {

    /**
     * Export a secret using the given parameters.
     *
     * @param exportContext the context used for exporting.
     * @param length        the desired length
     * @return              the exported secret.
     */
    byte[] export(byte[] exportContext, int length);

    /**
     * Extract a pseudorandom key of fixed length Nh bytes from input keying material ikm and an optional byte
     * string salt.
     *
     * @param salt  the salt to use.
     * @param ikm   the key material
     * @return      the extracted kex.
     */
    byte[] extract(byte[] salt, byte[] ikm);

    /**
     * Expand a pseudorandom key prk using optional string info into L bytes of output keying material.
     *
     * @param prk   the key.
     * @param info  the info.
     * @param length the number of bytes.
     * @return      the expanded key.
     */
    byte[] expand(byte[] prk, byte[] info, int length);
}
