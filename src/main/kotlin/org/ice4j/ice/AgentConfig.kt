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

package org.ice4j.ice

import org.jitsi.metaconfig.config
import java.time.Duration
import org.jitsi.config.JitsiConfig.Companion.newConfig as configSource

class AgentConfig {
    val consentFreshnessInterval: Duration by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_INTERVAL".from(configSource)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.consent-freshness.interval".from(configSource)
    }

    val consentFreshnessOriginalWaitInterval: Duration by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_WAIT_INTERVAL".from(configSource)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.consent-freshness.original-wait-interval".from(configSource)
    }

    val consentFreshnessMaxWaitInterval: Duration by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_MAX_WAIT_INTERVAL".from(configSource)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.consent-freshness.max-wait-interval".from(configSource)
    }

    val maxConsentFreshnessRetransmissions: Int by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_MAX_RETRANSMISSIONS".from(configSource)
        "ice4j.consent-freshness.max-retransmissions".from(configSource)
    }

    val terminationDelay: Duration by config {
        "org.ice4j.TERMINATION_DELAY".from(configSource)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.ice.termination-delay".from(configSource)
    }

    val maxCheckListSize: Int by config {
        "org.ice4j.MAX_CHECK_LIST_SIZE".from(configSource)
        "ice4j.ice.max-check-list-size".from(configSource)
    }

    companion object {
        @JvmField
        val config = AgentConfig()
    }
}
