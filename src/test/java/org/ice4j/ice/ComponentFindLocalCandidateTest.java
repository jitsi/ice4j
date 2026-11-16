/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2026 - present 8x8, Inc.
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

import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import org.ice4j.*;
import org.junit.jupiter.api.*;

/**
 * Tests {@link Component#findLocalCandidate(TransportAddress, LocalCandidate)} when another thread adds a local
 * candidate at the same time, e.g. a peer reflexive candidate discovered while processing a different connectivity
 * check response.
 */
public class ComponentFindLocalCandidateTest
{
    private static final long TIMEOUT_MS = 5000;

    /** The address of the mapped candidates in the tests with two candidates that have the same address. */
    private static final TransportAddress MAPPED_ADDRESS = new TransportAddress("203.0.113.1", 10000, Transport.UDP);

    private Agent agent;
    private Component component;

    /** The thread which adds the second candidate, checked by the pausing candidate. */
    private volatile Thread pausedAdder;

    @BeforeEach
    public void setUp()
    {
        agent = new Agent("test", null);
        IceMediaStream stream = agent.createMediaStream("stream");
        // Create the component directly on the stream rather than via Agent.createComponent(), which would harvest
        // candidates on the real network interfaces.
        component = stream.createComponent(KeepAliveStrategy.SELECTED_ONLY, false);
    }

    @AfterEach
    public void tearDown()
    {
        if (agent != null)
        {
            agent.free();
        }
    }

    /**
     * Adds a local candidate from a second thread while the test thread is in the middle of iterating over the local
     * candidates in {@code findLocalCandidate}. The lookup must not fail, and the add must take effect.
     */
    @Test
    public void testAddLocalCandidateDuringFind()
        throws Exception
    {
        CountDownLatch inIteration = new CountDownLatch(1);
        CountDownLatch added = new CountDownLatch(1);
        AtomicReference<Thread> pausedThread = new AtomicReference<>();

        // A candidate which pauses the first time the test thread reads its address, which only happens inside
        // findLocalCandidate's iteration once pausedThread is set.
        HostCandidate pausing = new HostCandidate(
                new TransportAddress("192.0.2.1", 10000, Transport.UDP),
                component)
        {
            @Override
            public TransportAddress getTransportAddress()
            {
                if (pausedThread.compareAndSet(Thread.currentThread(), null))
                {
                    inIteration.countDown();
                    awaitAddedOrBlocked(added, pausedAdder);
                }
                return super.getTransportAddress();
            }
        };
        assertTrue(component.addLocalCandidate(pausing));

        HostCandidate other = new HostCandidate(new TransportAddress("192.0.2.2", 10000, Transport.UDP), component);
        AtomicReference<Throwable> adderError = new AtomicReference<>();
        Thread adder = new Thread(() ->
        {
            try
            {
                inIteration.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (!component.addLocalCandidate(other))
                {
                    throw new IllegalStateException("addLocalCandidate returned false");
                }
                added.countDown();
            }
            catch (Throwable t)
            {
                adderError.set(t);
            }
        }, "adder");
        pausedAdder = adder;

        pausedThread.set(Thread.currentThread());
        adder.start();

        TransportAddress unknown = new TransportAddress("198.51.100.1", 10000, Transport.UDP);
        LocalCandidate found = assertDoesNotThrow(() -> component.findLocalCandidate(unknown, null));
        assertNull(found);

        adder.join(TIMEOUT_MS);
        assertFalse(adder.isAlive(), "The adding thread did not finish");
        assertNull(adderError.get(), () -> "The adding thread failed: " + adderError.get());
        assertEquals(2, component.getLocalCandidateCount());
    }

    /**
     * When two candidates have the same address, {@code findLocalCandidate} returns the one with the requested base,
     * even if it is not the first one in the list.
     */
    @Test
    public void testBaseMatchIsPreferred()
    {
        HostCandidate hostA = addHostCandidate("192.0.2.1");
        HostCandidate hostB = addHostCandidate("192.0.2.2");
        ServerReflexiveCandidate mappedA = addMappedCandidate(hostA);
        ServerReflexiveCandidate mappedB = addMappedCandidate(hostB);

        assertTrue(
                indexOf(mappedA) < indexOf(mappedB),
                "Test precondition: the candidate with the other base must come first");

        assertSame(mappedB, component.findLocalCandidate(MAPPED_ADDRESS, hostB));
        assertSame(mappedA, component.findLocalCandidate(MAPPED_ADDRESS, hostA));
        assertSame(hostA, component.findLocalCandidate(hostA.getTransportAddress()));
    }

    /**
     * When no candidate has both the requested address and the requested base, {@code findLocalCandidate} returns the
     * first candidate with the requested address. Without a base, it also returns the first candidate with the
     * requested address.
     */
    @Test
    public void testFallbackToAddressMatch()
    {
        HostCandidate hostA = addHostCandidate("192.0.2.1");
        HostCandidate hostB = addHostCandidate("192.0.2.2");
        ServerReflexiveCandidate mappedA = addMappedCandidate(hostA);
        ServerReflexiveCandidate mappedB = addMappedCandidate(hostB);

        assertTrue(
                indexOf(mappedA) < indexOf(mappedB),
                "Test precondition: the candidates must stay in the order in which they were added");

        // A base which is not in the component.
        HostCandidate otherBase
                = new HostCandidate(new TransportAddress("192.0.2.3", 10000, Transport.UDP), component);

        assertSame(mappedA, component.findLocalCandidate(MAPPED_ADDRESS, otherBase));
        assertSame(mappedA, component.findLocalCandidate(MAPPED_ADDRESS));
    }

    private HostCandidate addHostCandidate(String address)
    {
        HostCandidate host = new HostCandidate(new TransportAddress(address, 10000, Transport.UDP), component);
        assertTrue(component.addLocalCandidate(host));
        return host;
    }

    private ServerReflexiveCandidate addMappedCandidate(HostCandidate base)
    {
        ServerReflexiveCandidate mapped = new ServerReflexiveCandidate(
                MAPPED_ADDRESS,
                base,
                null,
                CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);
        assertTrue(component.addLocalCandidate(mapped));
        return mapped;
    }

    private int indexOf(LocalCandidate candidate)
    {
        return component.getLocalCandidates().indexOf(candidate);
    }

    /**
     * Waits until the adding thread either completes the add or blocks on a monitor (normally the lock which the
     * iterating thread holds).
     */
    private static void awaitAddedOrBlocked(CountDownLatch added, Thread adder)
    {
        long deadline = System.currentTimeMillis() + TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline)
        {
            if (added.getCount() == 0)
            {
                return;
            }
            if (adder != null && adder.getState() == Thread.State.BLOCKED)
            {
                return;
            }
            try
            {
                Thread.sleep(1);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
                return;
            }
        }
        fail("The adding thread neither completed nor blocked");
    }
}
