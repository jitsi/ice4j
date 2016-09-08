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
package org.ice4j.ice.harvest;

import java.util.*;

import org.ice4j.ice.*;

/**
 * A <tt>CandidateHarvester</tt> gathers a certain kind of <tt>Candidate</tt>s
 * (e.g. host, reflexive, or relayed) for a specified {@link
 * org.ice4j.ice.Component}.
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 * @author Boris Grozev
 */
public interface CandidateHarvester
{
    /**
     * Gathers all candidate addresses of the type that this
     * <tt>CandidateHarvester</tt> supports. The gathered candidate addresses
     * are to be added by this <tt>CandidateHarvester</tt> to the specified
     * <tt>Component</tt> using
     * {@link Component#addLocalCandidate(LocalCandidate)} as soon as they are
     * discovered.
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * addresses for.
     * @return  the <tt>LocalCandidate</tt>s gathered by this
     * <tt>CandidateHarvester</tt>. Though they are to be added by this
     * <tt>CandidateHarvester</tt> to the specified <tt>component</tt> as soon
     * as they are discovered, they should also be returned in order to make
     * sure that the gathering will be considered successful.
     */
    Collection<LocalCandidate> harvest(Component component);

    /**
     * Returns the statistics describing how well the various harvests of this
     * harvester went.
     *
     * @return The {@link HarvestStatistics} describing this harvester's
     * harvests.
     */
    HarvestStatistics getHarvestStatistics();

    /**
     * Returns <tt>true</tt> if this <tt>CandidateHarvester</tt> is to be
     * considered a harvester for host candidates. Such a harvester should
     * 1. Create local candidates of type <tt>HOST_CANDIDATE</tt>.
     * 2. Not depend on other local candidates, already harvested for the
     *      component for which it is called.
     * 3. Not perform blocking operations while harvesting.
     *
     * @return <tt>true</tt> if this <tt>CandidateHarvester</tt> is a harvester
     * for host candidates.
     */
    boolean isHostHarvester();
}
