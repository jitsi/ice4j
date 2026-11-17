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
 * Tests that the candidate lookups of {@link Component}, {@link IceMediaStream} and {@link Agent} do not fail when
 * another thread adds a candidate, a component or a media stream while the lookup iterates. Each test pauses the
 * lookup in the middle of its iteration (inside {@code getTransportAddress()} of the first candidate it visits), makes
 * the change from a second thread, and then lets the lookup continue.
 */
public class FindCandidateConcurrencyTest
{
    private static final long TIMEOUT_MS = 5000;

    /** An address that no candidate in the tests has, so that a lookup visits every candidate. */
    private static final TransportAddress UNKNOWN = new TransportAddress("198.51.100.1", 10000, Transport.UDP);

    private Agent agent;

    /** The thread that pauses the next time that it reads the address of a pausing candidate. */
    private final AtomicReference<Thread> pausedThread = new AtomicReference<>();
    private final CountDownLatch inIteration = new CountDownLatch(1);
    private final CountDownLatch changed = new CountDownLatch(1);
    private volatile Thread changer;

    @BeforeEach
    public void setUp()
    {
        agent = new Agent("test", null);
    }

    @AfterEach
    public void tearDown()
    {
        agent.free();
    }

    @Test
    public void testComponentFindRemoteCandidate()
        throws Exception
    {
        Component component = createComponent(agent.createMediaStream("stream"));
        component.addRemoteCandidate(createPausingRemoteCandidate(component, "192.0.2.1"));

        runWhileChanging(
                () -> assertNull(component.findRemoteCandidate(UNKNOWN)),
                () -> component.addRemoteCandidate(createRemoteCandidate(component, "192.0.2.2")));

        assertEquals(2, component.getRemoteCandidateCount());
    }

    @Test
    public void testStreamFindLocalCandidate()
        throws Exception
    {
        IceMediaStream stream = agent.createMediaStream("stream");
        addPausingLocalCandidate(createComponent(stream));
        createComponent(stream);

        runWhileChanging(() -> assertNull(stream.findLocalCandidate(UNKNOWN, null)), () -> createComponent(stream));

        assertEquals(3, stream.getComponentCount());
    }

    @Test
    public void testStreamFindRemoteCandidate()
        throws Exception
    {
        IceMediaStream stream = agent.createMediaStream("stream");
        Component first = createComponent(stream);
        first.addRemoteCandidate(createPausingRemoteCandidate(first, "192.0.2.1"));
        createComponent(stream);

        runWhileChanging(() -> assertNull(stream.findRemoteCandidate(UNKNOWN)), () -> createComponent(stream));

        assertEquals(3, stream.getComponentCount());
    }

    @Test
    public void testAgentFindLocalCandidate()
        throws Exception
    {
        addPausingLocalCandidate(createComponent(agent.createMediaStream("a")));
        createComponent(agent.createMediaStream("b"));

        runWhileChanging(() -> assertNull(agent.findLocalCandidate(UNKNOWN, null)), () -> agent.createMediaStream("c"));

        assertEquals(3, agent.getStreamCount());
    }

    @Test
    public void testAgentFindRemoteCandidate()
        throws Exception
    {
        Component first = createComponent(agent.createMediaStream("a"));
        first.addRemoteCandidate(createPausingRemoteCandidate(first, "192.0.2.1"));
        createComponent(agent.createMediaStream("b"));

        runWhileChanging(() -> assertNull(agent.findRemoteCandidate(UNKNOWN)), () -> agent.createMediaStream("c"));

        assertEquals(3, agent.getStreamCount());
    }

    /**
     * Runs {@code lookup} on the current thread and {@code change} on a second thread. The change starts when the
     * lookup is paused in the middle of its iteration, and the lookup continues when the change is complete or when
     * the second thread is blocked (by a lock which the lookup holds).
     */
    private void runWhileChanging(Runnable lookup, Runnable change)
        throws Exception
    {
        AtomicReference<Throwable> changeError = new AtomicReference<>();
        Thread thread = new Thread(() ->
        {
            try
            {
                if (!inIteration.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))
                {
                    throw new IllegalStateException("The lookup did not pause");
                }
                change.run();
            }
            catch (Throwable t)
            {
                changeError.set(t);
            }
            finally
            {
                changed.countDown();
            }
        }, "changer");
        changer = thread;

        pausedThread.set(Thread.currentThread());
        thread.start();

        assertDoesNotThrow(lookup::run);

        thread.join(TIMEOUT_MS);
        assertFalse(thread.isAlive(), "The changing thread did not finish");
        assertNull(changeError.get(), () -> "The changing thread failed: " + changeError.get());
    }

    /** Pauses the thread that is selected in {@code pausedThread}, once. */
    private void pauseIfSelected()
    {
        if (pausedThread.compareAndSet(Thread.currentThread(), null))
        {
            inIteration.countDown();
            awaitChangedOrBlocked();
        }
    }

    private void awaitChangedOrBlocked()
    {
        long deadline = System.currentTimeMillis() + TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline)
        {
            Thread thread = changer;
            if (changed.getCount() == 0 || (thread != null && thread.getState() == Thread.State.BLOCKED))
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
        fail("The changing thread neither completed nor blocked");
    }

    private static Component createComponent(IceMediaStream stream)
    {
        // Create the component directly on the stream rather than via Agent.createComponent(), which would harvest
        // candidates on the real network interfaces.
        return stream.createComponent(KeepAliveStrategy.SELECTED_ONLY, false);
    }

    private void addPausingLocalCandidate(Component component)
    {
        HostCandidate candidate = new HostCandidate(new TransportAddress("192.0.2.1", 10000, Transport.UDP), component)
        {
            @Override
            public TransportAddress getTransportAddress()
            {
                pauseIfSelected();
                return super.getTransportAddress();
            }
        };
        assertTrue(component.addLocalCandidate(candidate));
    }

    private RemoteCandidate createRemoteCandidate(Component component, String address)
    {
        return new RemoteCandidate(
                new TransportAddress(address, 20000, Transport.UDP),
                component,
                CandidateType.HOST_CANDIDATE,
                "1",
                1000,
                null);
    }

    private RemoteCandidate createPausingRemoteCandidate(Component component, String address)
    {
        return new RemoteCandidate(
                new TransportAddress(address, 20000, Transport.UDP),
                component,
                CandidateType.HOST_CANDIDATE,
                "1",
                1000,
                null)
        {
            @Override
            public TransportAddress getTransportAddress()
            {
                pauseIfSelected();
                return super.getTransportAddress();
            }
        };
    }
}
