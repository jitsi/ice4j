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
import org.ice4j.config.Ice4jConfig
import java.time.Duration

class AgentConfig {
    val consentFreshnessInterval: Duration by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_INTERVAL".from(Ice4jConfig.legacyConfig)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.consent-freshness.interval".from(Ice4jConfig.newConfig)
    }

    val consentFreshnessOriginalWaitInterval: Duration by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_WAIT_INTERVAL".from(Ice4jConfig.legacyConfig)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.consent-freshness.original-wait-interval".from(Ice4jConfig.newConfig)
    }

    val consentFreshnessMaxWaitInterval: Duration by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_MAX_WAIT_INTERVAL".from(Ice4jConfig.legacyConfig)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.consent-freshness.max-wait-interval".from(Ice4jConfig.newConfig)
    }

    val maxConsentFreshnessRetransmissions: Int by config {
        "org.ice4j.ice.CONSENT_FRESHNESS_MAX_RETRANSMISSIONS".from(Ice4jConfig.legacyConfig)
        "ice4j.consent-freshness.max-retransmissions".from(Ice4jConfig.newConfig)
    }

    val terminationDelay: Duration by config {
        "org.ice4j.TERMINATION_DELAY".from(Ice4jConfig.legacyConfig)
            .convertFrom<Long> { Duration.ofMillis(it) }
        "ice4j.ice.termination-delay".from(Ice4jConfig.newConfig)
    }

    val maxCheckListSize: Int by config {
        "org.ice4j.MAX_CHECK_LIST_SIZE".from(Ice4jConfig.legacyConfig)
        "ice4j.ice.max-check-list-size".from(Ice4jConfig.newConfig)
    }

    companion object {
        @JvmField
        val config = AgentConfig()
    }
}