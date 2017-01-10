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
package org.ice4j.ice;

import org.ice4j.*;
import org.ice4j.socket.*;

/**
 * Peer Reflexive Candidates are candidates whose IP address and port are a
 * binding explicitly allocated by a NAT for an agent when it sent a STUN
 * Binding request through the NAT to its peer.
 * <p>
 * Peer Reflexive Candidates are generally allocated by NATs with endpoint
 * dependent mapping also known as Symmetric NATs. PeerReflexiveCandidates
 * are generally preferred to relayed ones. RFC 5245 explains this with
 * better security ... although simply avoiding a relay would probably be
 * enough of a reason for many.
 *
 * @author Emil Ivov
 */
public class PeerReflexiveCandidate
    extends LocalCandidate
{
    /**
     * Creates a <tt>PeerReflexiveCandidate</tt> instance for the specified
     * transport address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param base the base of a peer reflexive candidate base is the local
     * candidate of the candidate pair from which the STUN check was sent.
     * @param priority the priority of the candidate.
     */
    public PeerReflexiveCandidate(TransportAddress transportAddress,
                                  Component        parentComponent,
                                  LocalCandidate   base,
                                  long             priority)
    {
        super(
                transportAddress,
                parentComponent,
                CandidateType.PEER_REFLEXIVE_CANDIDATE,
                CandidateExtendedType.STUN_PEER_REFLEXIVE_CANDIDATE,
                base);
        super.setBase(base);
        super.priority = priority;
        super.setTcpType(base.getTcpType());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IceSocketWrapper getCandidateIceSocketWrapper()
    {
        return getBase().getCandidateIceSocketWrapper();
    }
}
