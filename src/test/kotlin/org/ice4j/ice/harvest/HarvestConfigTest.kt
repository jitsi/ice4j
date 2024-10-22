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

import io.kotest.assertions.throwables.shouldThrow
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
            config.udpSocketPoolSize shouldBe 0
            config.stunMappingCandidateHarvesterAddresses shouldBe emptyList()
        }
        context("Setting via legacy config (system properties)") {
            withLegacyConfig(legacyConfig) {
                config.timeout shouldBe 555.secs
                config.useDynamicPorts shouldBe false
                config.useIpv6 shouldBe false
                config.useLinkLocalAddresses shouldBe false
                config.udpReceiveBufferSize shouldBe 555
                config.udpSocketPoolSize shouldBe 0
                config.stunMappingCandidateHarvesterAddresses shouldBe listOf("stun1.legacy:555", "stun2.legacy")
            }
        }
        context("Setting via new config") {
            withNewConfig(newConfigNonDefault) {
                config.timeout shouldBe 666.secs
                config.useDynamicPorts shouldBe false
                config.useIpv6 shouldBe false
                config.useLinkLocalAddresses shouldBe false
                config.udpReceiveBufferSize shouldBe 666
                config.udpSocketPoolSize shouldBe 3
                config.stunMappingCandidateHarvesterAddresses shouldBe listOf("stun1.new:666", "stun2.new")
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
                    config.udpSocketPoolSize shouldBe 0
                    config.stunMappingCandidateHarvesterAddresses shouldBe listOf("stun1.legacy:555", "stun2.legacy")
                }
            }
        }
        context("Static mappings") {
            context("With all fields present") {
                withNewConfig(
                    """
                ice4j.harvest.mapping.static-mappings = [
                    {
                        local-address = "10.0.0.1"
                        local-port = 10000
                        public-address = "192.168.255.255"
                        public-port = 33333
                        name = "my-mapping"
                    }
                ]
                    """.trimIndent()
                ) {
                    HarvestConfig().staticMappings shouldBe listOf(
                        HarvestConfig.StaticMapping(
                            localAddress = "10.0.0.1",
                            localPort = 10000,
                            publicAddress = "192.168.255.255",
                            publicPort = 33333,
                            name = "my-mapping"
                        )
                    )
                }
            }
            context("With optional fields missing") {
                withNewConfig(
                    """
                ice4j.harvest.mapping.static-mappings = [
                    {
                        local-address = "10.0.0.1"
                        public-address = "192.168.255.255"
                    }
                ]
                    """.trimIndent()
                ) {
                    HarvestConfig().staticMappings shouldBe listOf(
                        HarvestConfig.StaticMapping(
                            localAddress = "10.0.0.1",
                            localPort = null,
                            publicAddress = "192.168.255.255",
                            publicPort = null,
                            name = null
                        )
                    )
                }
            }
            context("With inconsistent local-port and public-port") {
                withNewConfig(
                    """
                ice4j.harvest.mapping.static-mappings = [
                    {
                        local-address = "10.0.0.1"
                        public-address = "192.168.255.255"
                        local-port = 10000
                        //public-port = 33333
                    }
                ]
                    """.trimIndent()
                ) {
                    shouldThrow<Throwable> {
                        HarvestConfig().staticMappings
                    }
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
    "org.ice4j.ice.harvest.AbstractUdpListener.SO_RCVBUF" to "555",
    "org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES" to "stun1.legacy:555,stun2.legacy"
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
            socket-pool-size = 3
        }
        mapping {
          stun {
            addresses = [ "stun1.new:666", "stun2.new" ]
          }
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
        mapping {
          stun {
            addresses = [ "stun1.new:666", "stun2.new" ]
          }
        }
     }
    }
""".trimIndent()
