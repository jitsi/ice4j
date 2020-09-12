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

import org.jitsi.metaconfig.config
import org.jitsi.metaconfig.optionalconfig

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

    companion object {
        @JvmField
        val config = HarvestConfig()
    }
}