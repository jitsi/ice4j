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
import java.time.*;
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

    /** The current time as seen by the component. */
    private Instant now = Instant.parse("2026-01-01T00:00:00Z");

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
        component.setClock(Clock.fixed(now, ZoneOffset.UTC));

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

    private void advance(Duration duration)
    {
        now = now.plus(duration);
        component.setClock(Clock.fixed(now, ZoneOffset.UTC));
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

    @Test
    public void testHasKeepAlivePairForRemoteAddress()
        throws IOException
    {
        setUp(KeepAliveStrategy.SELECTED_ONLY);
        RemoteCandidate remoteA = createRemoteCandidate(1000);
        RemoteCandidate remoteB = createRemoteCandidate(2000);
        CandidatePair pairA = createPair(host, remoteA);
        CandidatePair pairB = createPair(host, remoteB);
        pairA.setStateSucceeded();
        pairB.setStateSucceeded();
        assertFalse(component.hasKeepAlivePairForRemoteAddress(remoteA.getTransportAddress()));

        component.setSelectedPair(pairA);
        assertTrue(component.hasKeepAlivePairForRemoteAddress(remoteA.getTransportAddress()));
        assertFalse(component.hasKeepAlivePairForRemoteAddress(remoteB.getTransportAddress()));

        // The equivalent pair with the mapped candidate has the same remote address.
        createPair(mapped, remoteA).setStateSucceeded();
        assertTrue(component.hasKeepAlivePairForRemoteAddress(remoteA.getTransportAddress()));
    }

    /**
     * A non-selected pair which stays failed for the configured timeout (30 seconds by default) is removed. Failures
     * are reported on every keep-alive interval while the pair is failed.
     */
    @Test
    public void testFailedPairIsRemovedAfterTimeout()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        CandidatePair selected = createPair(host, createRemoteCandidate(1000));
        CandidatePair backup = createPair(host, createRemoteCandidate(2000));
        selected.setStateSucceeded();
        backup.setStateSucceeded();
        component.setSelectedPair(selected);
        assertEquals(new HashSet<>(Arrays.asList(selected, backup)), keepAlivePairs());

        backup.setStateFailed();
        assertTrue(keepAlivePairs().contains(backup), "Not removed on first failure");

        advance(Duration.ofSeconds(15));
        backup.setStateFailed();
        assertTrue(keepAlivePairs().contains(backup), "Not removed before the timeout");

        advance(Duration.ofSeconds(15));
        backup.setStateFailed();
        assertEquals(Collections.singleton(selected), keepAlivePairs(), "Removed once failed for the timeout");
    }

    @Test
    public void testSelectedPairIsNeverRemoved()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        CandidatePair selected = createPair(host, createRemoteCandidate(1000));
        selected.setStateSucceeded();
        component.setSelectedPair(selected);

        for (int i = 0; i < 10; i++)
        {
            selected.setStateFailed();
            advance(Duration.ofSeconds(15));
        }
        assertEquals(Collections.singleton(selected), keepAlivePairs());
    }

    /**
     * A pair which recovers (succeeds again) before the timeout is kept, and the timer restarts on its next failure.
     */
    @Test
    public void testRecoveredPairIsKept()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        CandidatePair selected = createPair(host, createRemoteCandidate(1000));
        CandidatePair backup = createPair(host, createRemoteCandidate(2000));
        selected.setStateSucceeded();
        backup.setStateSucceeded();
        component.setSelectedPair(selected);

        backup.setStateFailed();
        advance(Duration.ofSeconds(15));
        backup.setStateSucceeded();
        advance(Duration.ofSeconds(15));

        // 30 seconds since the first failure, but it recovered in between.
        backup.setStateFailed();
        assertTrue(keepAlivePairs().contains(backup));
        advance(Duration.ofSeconds(15));
        backup.setStateFailed();
        assertTrue(keepAlivePairs().contains(backup));
        advance(Duration.ofSeconds(15));
        backup.setStateFailed();
        assertFalse(keepAlivePairs().contains(backup));
    }

    /**
     * A failed pair which is not a keep-alive pair (it never succeeded) is not affected.
     */
    @Test
    public void testFailedNonKeepAlivePairIsIgnored()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        CandidatePair pair = createPair(host, createRemoteCandidate(1000));
        pair.setStateFailed();
        advance(Duration.ofMinutes(5));
        pair.setStateFailed();
        assertTrue(keepAlivePairs().isEmpty());

        pair.setStateSucceeded();
        assertEquals(Collections.singleton(pair), keepAlivePairs());
    }

    @Test
    public void testWantsKeepAlive()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        assertTrue(component.wantsKeepAlive(createPair(host, createRemoteCandidate(1000))));
        tearDown();

        setUp(KeepAliveStrategy.SELECTED_ONLY);
        assertFalse(component.wantsKeepAlive(createPair(host, createRemoteCandidate(1000))));
        tearDown();

        setUp(KeepAliveStrategy.SELECTED_AND_TCP);
        assertFalse(component.wantsKeepAlive(createPair(host, createRemoteCandidate(1000))), "UDP pair");
    }

    /**
     * A pair which is not SUCCEEDED can be added explicitly (this is used to re-check a pair on which the remote side
     * sends a check after ICE has terminated). It is subject to the same removal once it has been failed for too
     * long, and equivalent pairs are still deduplicated.
     */
    @Test
    public void testExplicitlyAddedFailedPair()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        CandidatePair selected = createPair(host, createRemoteCandidate(1000));
        selected.setStateSucceeded();
        component.setSelectedPair(selected);

        RemoteCandidate remote = createRemoteCandidate(2000);
        CandidatePair failed = createPair(host, remote);
        failed.setStateFailed();
        assertFalse(keepAlivePairs().contains(failed));

        assertTrue(component.addKeepAlivePair(failed));
        assertFalse(component.addKeepAlivePair(failed), "Already present");
        assertFalse(component.addKeepAlivePair(createPair(mapped, remote)), "Equivalent pair present");
        assertEquals(new HashSet<>(Arrays.asList(selected, failed)), keepAlivePairs());

        // If the check we send fails, the pair is removed again after the timeout.
        failed.setStateFailed();
        advance(Duration.ofSeconds(15));
        failed.setStateFailed();
        advance(Duration.ofSeconds(15));
        failed.setStateFailed();
        assertEquals(Collections.singleton(selected), keepAlivePairs());

        // It is not added again for re-checking until the timeout has passed since it was removed.
        assertFalse(component.addKeepAlivePair(failed), "Recently removed");
        advance(Duration.ofSeconds(29));
        assertFalse(component.addKeepAlivePair(failed), "Recently removed");
        advance(Duration.ofSeconds(1));

        // If the check succeeds, it stays.
        assertTrue(component.addKeepAlivePair(failed));
        failed.setStateSucceeded();
        advance(Duration.ofMinutes(5));
        assertEquals(new HashSet<>(Arrays.asList(selected, failed)), keepAlivePairs());
    }

    /** Creates {@code count} pairs with distinct remote addresses and increasing priorities, and succeeds them. */
    private List<CandidatePair> fillKeepAlivePairs(int count)
    {
        List<CandidatePair> pairs = new ArrayList<>();
        for (int i = 1; i <= count; i++)
        {
            CandidatePair pair = createPair(host, createRemoteCandidate(1000L * i));
            pair.setStateSucceeded();
            pairs.add(pair);
        }
        assertEquals(new HashSet<>(pairs), keepAlivePairs());
        return pairs;
    }

    /**
     * At most ice4j.keep-alive.max-pairs (10 by default) pairs are kept alive. When the set is full, a new pair with
     * a higher priority than the lowest-priority pair replaces it, and a new pair with a lower priority is not added.
     */
    @Test
    public void testMaxPairsEvictsLowestPriority()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        List<CandidatePair> pairs = fillKeepAlivePairs(10);
        assertTrue(pairs.get(0).getPriority() < pairs.get(9).getPriority());

        CandidatePair low = createPair(host, createRemoteCandidate(500));
        low.setStateSucceeded();
        assertFalse(keepAlivePairs().contains(low), "Lower priority than all existing pairs, not added");
        assertEquals(10, keepAlivePairs().size());

        CandidatePair high = createPair(host, createRemoteCandidate(20000));
        high.setStateSucceeded();
        Set<CandidatePair> expected = new HashSet<>(pairs.subList(1, 10));
        expected.add(high);
        assertEquals(expected, keepAlivePairs(), "Lowest priority pair evicted");
    }

    /**
     * A failed pair is evicted before any succeeded pair, regardless of priority.
     */
    @Test
    public void testMaxPairsEvictsFailedFirst()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        List<CandidatePair> pairs = fillKeepAlivePairs(10);
        CandidatePair failed = pairs.get(5);
        failed.setStateFailed();
        assertTrue(keepAlivePairs().contains(failed), "Still present, not failed for long enough");

        CandidatePair low = createPair(host, createRemoteCandidate(500));
        low.setStateSucceeded();
        Set<CandidatePair> expected = new HashSet<>(pairs);
        expected.remove(failed);
        expected.add(low);
        assertEquals(expected, keepAlivePairs());
    }

    /**
     * The selected pair is always kept alive, even if the set is full and its priority is the lowest.
     */
    @Test
    public void testSelectedPairAlwaysAdded()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        List<CandidatePair> pairs = fillKeepAlivePairs(10);

        CandidatePair selected = createPair(host, createRemoteCandidate(50));
        selected.setStateSucceeded();
        assertFalse(keepAlivePairs().contains(selected));

        component.setSelectedPair(selected);
        Set<CandidatePair> expected = new HashSet<>(pairs.subList(1, 10));
        expected.add(selected);
        assertEquals(expected, keepAlivePairs());

        // And it is not evicted by a higher priority pair.
        CandidatePair high = createPair(host, createRemoteCandidate(20000));
        high.setStateSucceeded();
        assertTrue(keepAlivePairs().contains(selected));
        assertTrue(keepAlivePairs().contains(high));
        assertEquals(10, keepAlivePairs().size());
    }

    /**
     * A pair which has not succeeded (added for re-checking) may only displace a failed pair, never a succeeded one,
     * regardless of its priority.
     */
    @Test
    public void testRecheckedPairDoesNotEvictSucceededPair()
        throws IOException
    {
        setUp(KeepAliveStrategy.ALL_SUCCEEDED);
        List<CandidatePair> pairs = fillKeepAlivePairs(10);

        CandidatePair high = createPair(host, createRemoteCandidate(20000));
        assertFalse(component.addKeepAlivePair(high), "Set full of succeeded pairs");
        assertEquals(new HashSet<>(pairs), keepAlivePairs());

        pairs.get(3).setStateFailed();
        assertTrue(component.addKeepAlivePair(high), "Failed pair can be displaced");
        Set<CandidatePair> expected = new HashSet<>(pairs);
        expected.remove(pairs.get(3));
        expected.add(high);
        assertEquals(expected, keepAlivePairs());
    }
}
