/*
 * Copyright @ 2020 - Present, 8x8 Inc
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

import com.typesafe.config.Config
import org.jitsi.metaconfig.config
import org.jitsi.metaconfig.optionalconfig
import java.time.Duration
import org.jitsi.config.JitsiConfig.Companion.newConfig as configSource

class HarvestConfig {
    val useLinkLocalAddresses: Boolean by config {
        "org.ice4j.ice.harvest.DISABLE_LINK_LOCAL_ADDRESSES".from(configSource)
            .transformedBy { !it }
        "ice4j.harvest.use-link-local-addresses".from(configSource)
    }
    fun useLinkLocalAddresses() = useLinkLocalAddresses

    val udpReceiveBufferSize: Int? by optionalconfig {
        "org.ice4j.ice.harvest.AbstractUdpListener.SO_RCVBUF".from(configSource)
        "ice4j.harvest.udp.receive-buffer-size".from(configSource)
    }
    fun udpReceiveBufferSize() = udpReceiveBufferSize

    val useIpv6: Boolean by config {
        "org.ice4j.ipv6.DISABLED".from(configSource)
            .transformedBy { !it }
        "ice4j.harvest.use-ipv6".from(configSource)
    }
    fun useIpv6() = useIpv6

    val useDynamicPorts: Boolean by config {
        "org.ice4j.ice.harvest.USE_DYNAMIC_HOST_HARVESTER".from(configSource)
        "ice4j.harvest.udp.use-dynamic-ports".from(configSource)
    }
    fun useDynamicPorts() = useDynamicPorts

    val timeout: Duration by config {
        "org.ice4j.ice.harvest.HARVESTING_TIMEOUT".from(configSource)
            .convertFrom<Long> { Duration.ofSeconds(it) }
        "ice4j.harvest.timeout".from(configSource)
    }
    fun timeout() = timeout

    val stunMappingCandidateHarvesterAddresses: List<String> by config {
        "org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES".from(configSource)
            .convertFrom<String> { it.split(",") }
        "ice4j.harvest.mapping.stun.addresses".from(configSource)
    }
    fun stunMappingCandidateHarvesterAddresses() = stunMappingCandidateHarvesterAddresses

    val enableAwsHarvester: Boolean by config {
        "org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER".from(configSource).transformedBy { !it }
        "ice4j.harvest.mapping.aws.enabled".from(configSource)
    }
    fun enableAwsHarvester() = enableAwsHarvester

    val forceAwsHarvester: Boolean by config {
        "org.ice4j.ice.harvest.FORCE_AWS_HARVESTER".from(configSource).transformedBy { !it }
        "ice4j.harvest.mapping.aws.force".from(configSource)
    }
    fun forceAwsHarvester() = enableAwsHarvester

    private val legacyNatHarvesterLocalAddress: String? by optionalconfig {
        "org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS".from(configSource)
    }

    private val legacyNatHarvesterPublicAddress: String? by optionalconfig {
        "org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS".from(configSource)
    }

    private val staticMappingsFromNewConfig: Set<StaticMapping> by config {
        "ice4j.harvest.mapping.static-mappings".from(configSource)
            .convertFrom<List<Config>> { cfg ->
                cfg.map { StaticMapping(it.getString("localAddress"), it.getString("publicAddress")) }.toSet()
            }
    }

    val staticMappings: Set<StaticMapping> = let {
        if (legacyNatHarvesterLocalAddress != null && legacyNatHarvesterPublicAddress != null)
        {
            setOf(
                StaticMapping(legacyNatHarvesterLocalAddress!!, legacyNatHarvesterPublicAddress!!),
                *staticMappingsFromNewConfig.toTypedArray())
        }
        else {
            staticMappingsFromNewConfig
        }
    }

    data class StaticMapping(val localAddress: String, val publicAddress: String)

    companion object {
        @JvmField
        val config = HarvestConfig()
    }
}
