/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2026 8x8, Inc
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

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.net.*;
import java.util.*;

import org.ice4j.*;
import org.ice4j.socket.*;
import org.junit.jupiter.api.*;

/**
 * Tests the maintenance of the set of keep-alive pairs of a {@link Component}.
 */
public class ComponentKeepAliveTest
{
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    private Agent agent;
    private IceMediaStream stream;
    private Component component;
    private DatagramSocket localSocket;

    /** A host candidate. */
    private HostCandidate host;
    /** A mapped candidate whose base is {@link #host}, i.e. it uses the same socket. */
    private ServerReflexiveCandidate mapped;

    private int nextRemotePort = 20000;

    private void setUp(KeepAliveStrategy strategy)
        throws IOException
    {
        localSocket = new DatagramSocket(0, LOOPBACK);

        agent = new Agent("test", null);
        agent.setControlling(true);
        stream = agent.createMediaStream("stream");
        // Create the component directly on the stream rather than via Agent.createComponent(), which would harvest
        // candidates on the real network interfaces.
        component = stream.createComponent(strategy, false);

        host = new HostCandidate(new IceUdpSocketWrapper(localSocket), component);
        component.addLocalCandidate(host);
        mapped = new ServerReflexiveCandidate(
                new TransportAddress("198.51.100.1", localSocket.getLocalPort(), Transport.UDP),
                host,
                null,
                CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
        component.addLocalCandidate(mapped);
    }

    @AfterEach
    public void tearDown()
    {
        if (agent != null)
        {
            agent.free();
        }
        if (localSocket != null)
        {
            localSocket.close();
        }
    }

    private RemoteCandidate createRemoteCandidate(long priority)
    {
        return new RemoteCandidate(
                new TransportAddress("203.0.113.1", nextRemotePort++, Transport.UDP),
                component,
                CandidateType.PEER_REFLEXIVE_CANDIDATE,
                "foundation" + priority,
                priority,
                null);
    }

    private CandidatePair createPair(LocalCandidate local, RemoteCandidate remote)
    {
        return agent.createCandidatePair(local, remote);
    }

    private Set<CandidatePair> keepAlivePairs()
    {
        return new HashSet<>(component.getKeepAlivePairs());
    }

    @Test
    public void testAllSucceededAddsSucceededPairs()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        CandidatePair pairA = createPair(host, createRemoteCandidate(1000));
        CandidatePair pairB = createPair(host, createRemoteCandidate(2000));

        pairA.setStateSucceeded();
        pairB.setStateSucceeded();

        assertEquals(new HashSet<>(Arrays.asList(pairA, pairB)), keepAlivePairs());
    }

    /**
     * The pair with the host candidate and the pair with the mapped candidate derived from it both use the same
     * socket to reach the same remote address. Only one of them should be kept alive.
     */
    @Test
    public void testEquivalentPairsAreDeduplicated()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        RemoteCandidate remote = createRemoteCandidate(1000);
        CandidatePair hostPair = createPair(host, remote);
        CandidatePair mappedPair = createPair(mapped, remote);

        hostPair.setStateSucceeded();
        mappedPair.setStateSucceeded();

        assertEquals(Collections.singleton(hostPair), keepAlivePairs());

        // Pairs to a different remote address are not equivalent.
        CandidatePair otherPair = createPair(mapped, createRemoteCandidate(2000));
        otherPair.setStateSucceeded();
        assertEquals(new HashSet<>(Arrays.asList(hostPair, otherPair)), keepAlivePairs());
    }

    /**
     * When a pair is selected it replaces any equivalent pair already in the set.
     */
    @Test
    public void testSelectedPairReplacesEquivalentPair()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        RemoteCandidate remote = createRemoteCandidate(1000);
        CandidatePair hostPair = createPair(host, remote);
        CandidatePair mappedPair = createPair(mapped, remote);
        CandidatePair otherPair = createPair(host, createRemoteCandidate(2000));

        hostPair.setStateSucceeded();
        otherPair.setStateSucceeded();
        assertEquals(new HashSet<>(Arrays.asList(hostPair, otherPair)), keepAlivePairs());

        mappedPair.setStateSucceeded();
        component.setSelectedPair(mappedPair);

        assertEquals(new HashSet<>(Arrays.asList(mappedPair, otherPair)), keepAlivePairs());
    }

    @Test
    public void testSelectedOnlyKeepsOnlySelectedPair()
        throws IOException
    {
        setUp(KeepAliveStrategy.SELECTED_ONLY);
        CandidatePair pairA = createPair(host, createRemoteCandidate(1000));
        CandidatePair pairB = createPair(host, createRemoteCandidate(2000));

        pairA.setStateSucceeded();
        pairB.setStateSucceeded();
        assertTrue(keepAlivePairs().isEmpty());

        component.setSelectedPair(pairA);
        assertEquals(Collections.singleton(pairA), keepAlivePairs());
    }
}
