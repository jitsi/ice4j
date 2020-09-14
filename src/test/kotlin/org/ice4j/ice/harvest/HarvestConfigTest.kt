/*
 * Copyright @ 2020 - present 8x8, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ice4j.ice.harvest

import io.kotest.matchers.shouldBe
import org.ice4j.ConfigTest
import org.ice4j.ice.harvest.HarvestConfig.Companion.config
import org.jitsi.utils.secs

class HarvestConfigTest : ConfigTest() {
    init {
        context("Default values") {
            config.timeout shouldBe 15.secs
            config.useDynamicPorts shouldBe true
            config.useIpv6 shouldBe true
            config.useLinkLocalAddresses shouldBe true
            config.udpReceiveBufferSize shouldBe null
        }
        context("Setting via legacy config (system properties)") {
            withLegacyConfig(legacyConfig) {
                config.timeout shouldBe 555.secs
                config.useDynamicPorts shouldBe false
                config.useIpv6 shouldBe false
                config.useLinkLocalAddresses shouldBe false
                config.udpReceiveBufferSize shouldBe 555
            }
        }
        context("Setting via new config") {
            withNewConfig(newConfigNonDefault) {
                config.timeout shouldBe 666.secs
                config.useDynamicPorts shouldBe false
                config.useIpv6 shouldBe false
                config.useLinkLocalAddresses shouldBe false
                config.udpReceiveBufferSize shouldBe 666
            }
        }
        context("Legacy config must take precedence") {
            withLegacyConfig(legacyConfig) {
                withNewConfig(newConfigDefault) {
                    config.timeout shouldBe 555.secs
                    config.useDynamicPorts shouldBe false
                    config.useIpv6 shouldBe false
                    config.useLinkLocalAddresses shouldBe false
                    config.udpReceiveBufferSize shouldBe 555
                }
            }
        }
    }
}

private val legacyConfig = mapOf(
    "org.ice4j.ice.harvest.HARVESTING_TIMEOUT" to "555",
    "org.ice4j.ice.harvest.USE_DYNAMIC_HOST_HARVESTER" to "false",
    "org.ice4j.ipv6.DISABLED" to "true",
    "org.ice4j.ice.harvest.DISABLE_LINK_LOCAL_ADDRESSES" to "true",
    "org.ice4j.ice.harvest.AbstractUdpListener.SO_RCVBUF" to "555"
)

// New config which overrides the default
private val newConfigNonDefault = """
    ice4j {
      harvest {
        timeout = 666 seconds
        use-ipv6 = false
        use-link-local-addresses = false
        udp {
            receive-buffer-size = 666
            use-dynamic-ports = false
        }
     }
    }
""".trimIndent()

// New config which does not override the defaults (to test precedence).
private val newConfigDefault = """
    ice4j {
      harvest {
        timeout = 666 seconds
        use-ipv6 = true
        use-link-local-addresses = true
        udp {
            receive-buffer-size = 666
            use-dynamic-ports = true
        }
     }
    }
""".trimIndent()
