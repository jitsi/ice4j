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

package org.ice4j.ice

import io.kotest.matchers.shouldBe
import org.ice4j.ConfigTest
import org.ice4j.ice.AgentConfig.Companion.config
import org.jitsi.utils.ms
import org.jitsi.utils.secs

class AgentConfigTest : ConfigTest() {
    init {
        context("Default values") {
            config.consentFreshnessInterval shouldBe 15.secs
            config.consentFreshnessMaxWaitInterval shouldBe 500.ms
            config.consentFreshnessOriginalWaitInterval shouldBe 500.ms
            config.maxConsentFreshnessRetransmissions shouldBe 30
            config.maxCheckListSize shouldBe 100
            config.terminationDelay shouldBe 3.secs
        }
        context("Setting via legacy config (system properties)") {
            withLegacyConfig(legacyConfig) {
                config.consentFreshnessInterval shouldBe 5.secs
                config.consentFreshnessMaxWaitInterval shouldBe 5.secs
                config.consentFreshnessOriginalWaitInterval shouldBe 5.secs
                config.maxConsentFreshnessRetransmissions shouldBe 5000
                config.terminationDelay shouldBe 5.secs
                config.maxCheckListSize shouldBe 5000
            }
        }
        context("Setting via new config") {
            withNewConfig(newConfig) {
                config.consentFreshnessInterval shouldBe 6.secs
                config.consentFreshnessMaxWaitInterval shouldBe 6.secs
                config.consentFreshnessOriginalWaitInterval shouldBe 6.secs
                config.maxConsentFreshnessRetransmissions shouldBe 6000
                config.terminationDelay shouldBe 6.secs
                config.maxCheckListSize shouldBe 6000
            }
        }
        context("Legacy config must take precedence") {
            withLegacyConfig(legacyConfig) {
                withNewConfig(newConfig) {
                    config.consentFreshnessInterval shouldBe 5.secs
                    config.consentFreshnessMaxWaitInterval shouldBe 5.secs
                    config.consentFreshnessOriginalWaitInterval shouldBe 5.secs
                    config.maxConsentFreshnessRetransmissions shouldBe 5000
                    config.terminationDelay shouldBe 5.secs
                    config.maxCheckListSize shouldBe 5000
                }
            }
        }
    }
}

private val legacyConfig = mapOf(
    "org.ice4j.ice.CONSENT_FRESHNESS_INTERVAL" to "5000",
    "org.ice4j.ice.CONSENT_FRESHNESS_MAX_WAIT_INTERVAL" to "5000",
    "org.ice4j.ice.CONSENT_FRESHNESS_WAIT_INTERVAL" to "5000",
    "org.ice4j.ice.CONSENT_FRESHNESS_MAX_RETRANSMISSIONS" to "5000",
    "org.ice4j.TERMINATION_DELAY" to "5000",
    "org.ice4j.MAX_CHECK_LIST_SIZE" to "5000")

private val newConfig = """
    ice4j.consent-freshness.interval = 6 seconds
    ice4j.consent-freshness.original-wait-interval = 6 seconds
    ice4j.consent-freshness.max-wait-interval = 6 seconds
    ice4j.consent-freshness.max-retransmissions = 6000 
    ice4j.ice.max-check-list-size = 6000
    ice4j.ice.termination-delay = 6 seconds
    
""".trimIndent()
