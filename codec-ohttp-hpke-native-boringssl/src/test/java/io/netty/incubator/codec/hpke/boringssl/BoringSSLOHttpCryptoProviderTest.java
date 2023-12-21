package io.netty.incubator.codec.hpke.boringssl;

import org.junit.jupiter.api.Test;

public class BoringSSLOHttpCryptoProviderTest {

    @Test
    void canBeLoaded() {
        BoringSSLHPKE.ensureAvailability();
    }
}
