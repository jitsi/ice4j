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

import org.ice4j.ice.*;

import java.util.*;

/**
 * We use this callback to feed candidates to ice4j user applications that
 * support trickle ICE. The interface provides two methods that allow passing
 * candidates to applications either one-by-one or in batches. The former would
 * typically be used for harvesters such as STUN, where candidates are learned
 * one per message. Discovering batches of candidates is possible when querying
 * a TURN server, which in many cases would return both server reflexive (STUN)
 * and relayed (TURN) candidates.
 *
 * @author Emil Ivov
 */
public interface TrickleCallback
{

    /**
     * Notifies the callback that a new batch of <tt>LocalCandidate</tt>s has
     * been discovered and should be advertised to the remove party.
     *
     * @param iceCandidates the newly discovered list of candidates or,
     * similarly to WebRTC, <tt>null</tt> in case all candidate harvesting is
     * now completed.
     */
    public void onIceCandidates(Collection<LocalCandidate> iceCandidates);

    /**
     * Notifies the callback that harvesting has completed for a specific
     * stream. This may allow for optimizations in cases where all checks for
     * a specific stream have failed and no candidate has been found, so a
     * failure is due and we wouldn't won't to waist any more time.
     *
     * @param stream the {@link IceMediaStream}, for which we have just
     * completed harvesting.
     */
    // we don't currently support this but we might do it one day.
    //public void streamCompleted(IceMediaStream stream);
}
