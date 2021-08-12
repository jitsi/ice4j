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
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import org.ice4j.Transport
import org.ice4j.TransportAddress
import org.ice4j.ice.Component
import org.ice4j.ice.HostCandidate
import org.ice4j.ice.ServerReflexiveCandidate
import org.ice4j.ice.harvest.MappingCandidateHarvester
import org.jitsi.utils.logging2.createLogger

class StaticMappingCandidateHarvesterTest : ShouldSpec() {
    val component = mockk<Component>()

    init {
        val hostCandidate1 = createHostCandidate("10.0.0.1", 10000)
        val hostCandidate2 = createHostCandidate("10.0.0.111", 10000)
        val hostCandidate3 = createHostCandidate("10.0.0.1", 11111)
        val srflxCandidate1 = mockk<ServerReflexiveCandidate>().apply {
            every { hostAddress } returns ta("10.10.0.1", 22222)
        }
        val srflxCandidate2 = mockk<ServerReflexiveCandidate>().apply {
            every { hostAddress } returns ta("192.168.0.1", 1234)
        }

        component.apply {
            every { logger } returns createLogger()
            every { componentID } returns Component.RTP
            every { localCandidates } returns listOf(
                hostCandidate1, hostCandidate2, hostCandidate3, srflxCandidate1, srflxCandidate2
            )
            every { addLocalCandidate(any()) } returns true
        }

        context("Harvesting") {
            val publicHostname = "192.168.255.255"
            val harvester = MappingCandidateHarvester(
                ta(publicHostname, 20000),
                ta("10.0.0.1", 10000)
            )

            val candidatesAdded = harvester.harvest(component)
            should("Add a candidate corresponding to hostCandidate1") {
                val addedCandidate = candidatesAdded.find { it.base == hostCandidate1 }!!
                addedCandidate.transportAddress shouldBe ta(publicHostname, hostCandidate1.transportAddress.port)
            }
            should("Not add a candidate corresponding to hostCandidate2 (hostname does not match)") {
                candidatesAdded.find { it.base == hostCandidate2 } shouldBe null
            }
            should("Add a candidate corresponding to hostCandidate3") {
                val addedCandidate = candidatesAdded.find { it.base == hostCandidate3 }!!
                addedCandidate.transportAddress shouldBe ta(publicHostname, hostCandidate3.transportAddress.port)
            }
            should("Not add a candidate corresponding to any of the srflx candidateS (they are not HostCandidate)") {
                candidatesAdded.find { it.base == srflxCandidate1 } shouldBe null
                candidatesAdded.find { it.base == srflxCandidate2 } shouldBe null
            }
            should("Not add any other candidates") {
                candidatesAdded.size shouldBe 2
            }
        }
    }

    private fun createHostCandidate(hostname: String, port: Int) = mockk<HostCandidate>().apply {
        val localAddress = ta(hostname, port)
        every { hostAddress } returns localAddress
        every { transportAddress } returns localAddress
        every { transport } returns localAddress.transport
        every { stunServerAddress } returns null
        every { parentComponent } returns component
        every { isSSL } returns false
    }
}

/** Create a UDP TransportAddress */
private fun ta(hostname: String, port: Int) = TransportAddress(hostname, port, Transport.UDP)

