/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
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

import org.ice4j.TransportAddress
import org.ice4j.ice.CandidateExtendedType
import org.ice4j.ice.Component
import org.ice4j.ice.HostCandidate
import org.ice4j.ice.LocalCandidate
import org.ice4j.ice.ServerReflexiveCandidate

/**
 * A [CandidateHarvester] which maps existing local [HostCandidate]s to new candidates.
 */
abstract class MappingCandidateHarvester : AbstractCandidateHarvester() {
    abstract val face: TransportAddress?
    abstract val mask: TransportAddress?

    /**
     * Looks for existing [HostCandidate]s in [component] which match our local address ([face]) and creates
     * associated [ServerReflexiveCandidate]s substituting [mask] for the address.
     *
     * @param component the [Component] that we'd like to harvest candidates for.
     * @return the [LocalCandidate]s created and added to [component].
     */
    override fun harvest(component: Component) = harvest(component, false)

    protected fun harvest(component: Component, matchPort: Boolean = false): Collection<LocalCandidate> {
        val localAddress = face ?: return emptyList()
        val publicAddress = mask ?: return emptyList()

        // Report the LocalCandidates gathered by this CandidateHarvester so
        // that the harvest is sure to be considered successful.
        val candidates = mutableSetOf<LocalCandidate>()
        component.localCandidates
            .filter {
                it is HostCandidate &&
                    it.transportAddress.hostAddress == localAddress.hostAddress &&
                    it.transport == localAddress.transport &&
                    (!matchPort || it.transportAddress.port == localAddress.port)
            }.forEach { hostCandidate ->
                hostCandidate as HostCandidate

                val mappedAddress = TransportAddress(
                    publicAddress.hostAddress,
                    if (matchPort) publicAddress.port else hostCandidate.hostAddress.port,
                    hostCandidate.hostAddress.transport
                )
                val mappedCandidate = ServerReflexiveCandidate(
                    mappedAddress,
                    hostCandidate,
                    hostCandidate.stunServerAddress,
                    CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE
                )
                if (hostCandidate.isSSL) mappedCandidate.isSSL = true

                // Try to add the candidate to the component and only then add it to the harvest.
                if (!candidates.contains(mappedCandidate) && component.addLocalCandidate(mappedCandidate)) {
                    candidates.add(mappedCandidate)
                }
            }

        return candidates
    }
}
