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
package io.netty.incubator.codec.bhttp;

import io.netty.handler.codec.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class BinaryHttpHeadersTest {

    @ParameterizedTest
    @MethodSource("io.netty.incubator.codec.bhttp.PseudoHeaderName#values")
    public void nonCustomPseudoHeaderName(PseudoHeaderName name) {
       HttpHeaders headers = BinaryHttpHeaders.newHeaders(true);
       assertThrows(IllegalArgumentException.class, () -> headers.set(name.value(), "x"));
    }

    @Test
    public void customPseudoHeaderName() {
        HttpHeaders headers = BinaryHttpHeaders.newHeaders(true);
        headers.set(":custom", "x");
    }

    @ParameterizedTest
    @MethodSource("io.netty.incubator.codec.bhttp.PseudoHeaderName#values")
    public void nonCustomPseudoHeaderNameInTrailer(PseudoHeaderName name) {
        HttpHeaders headers = BinaryHttpHeaders.newTrailers(true);
        assertThrows(IllegalArgumentException.class, () -> headers.set(name.value(), "x"));
    }

    @Test
    public void customPseudoHeaderNameInTrailer() {
        HttpHeaders headers = BinaryHttpHeaders.newTrailers(true);
        assertThrows(IllegalArgumentException.class, () -> headers.set(":custom", "x"));
    }
}
