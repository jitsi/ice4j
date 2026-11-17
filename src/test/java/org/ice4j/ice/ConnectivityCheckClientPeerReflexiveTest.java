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

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;
import org.junit.jupiter.api.*;

/**
 * Tests how {@link ConnectivityCheckClient} handles a success response with a mapped address that matches no local
 * candidate, when another thread adds an equivalent peer reflexive candidate to the component at the same time.
 */
public class ConnectivityCheckClientPeerReflexiveTest
{
    private static final TransportAddress MAPPED_ADDRESS = new TransportAddress("203.0.113.1", 10000, Transport.UDP);

    private TestAgent agent;
    private Component component;
    private ScheduledExecutorService scheduler;
    private ExecutorService executor;

    @BeforeEach
    public void setUp()
    {
        agent = new TestAgent();
        IceMediaStream stream = agent.createMediaStream("stream");
        // Create the component directly on the stream rather than via Agent.createComponent(), which would harvest
        // candidates on the real network interfaces.
        component = stream.createComponent(KeepAliveStrategy.SELECTED_ONLY, false);
        scheduler = Executors.newSingleThreadScheduledExecutor();
        executor = Executors.newSingleThreadExecutor();
    }

    @AfterEach
    public void tearDown()
    {
        scheduler.shutdownNow();
        executor.shutdownNow();
        agent.free();
    }

    /**
     * Two responses with the same mapped address are processed at the same time. Each one finds no local candidate
     * for the mapped address, so each one creates a peer reflexive candidate. {@code Component.addLocalCandidate}
     * rejects the second one as redundant. The valid pair of the second response must refer to the candidate which
     * is in the component, not to the rejected one.
     */
    @Test
    public void testValidPairUsesCandidateOfComponentWhenPeerReflexiveCandidateIsRedundant()
        throws Exception
    {
        HostCandidate host = new HostCandidate(new TransportAddress("192.0.2.1", 10000, Transport.UDP), component);
        assertTrue(component.addLocalCandidate(host));
        RemoteCandidate remote = new RemoteCandidate(
                new TransportAddress("192.0.2.50", 20000, Transport.UDP),
                component,
                CandidateType.HOST_CANDIDATE,
                "1",
                1000,
                null);

        // The candidate which the other thread adds in the time between the lookup and the add of this thread.
        PeerReflexiveCandidate concurrentlyAdded = new PeerReflexiveCandidate(MAPPED_ADDRESS, component, host, 1000);
        concurrentlyAdded.setBase(host);
        agent.beforeLookupReturnsNull = () -> assertTrue(component.addLocalCandidate(concurrentlyAdded));

        ConnectivityCheckClient client = new ConnectivityCheckClient(agent, scheduler, executor);
        client.processResponse(createSuccessResponseEvent(host, remote));

        assertEquals(1, agent.validatedPairs.size(), "Exactly one pair must have been validated");
        LocalCandidate validLocal = agent.validatedPairs.get(0).getLocalCandidate();
        assertSame(concurrentlyAdded, validLocal, "The valid pair must use the candidate that is in the component");
        assertTrue(component.getLocalCandidates().contains(validLocal));
        assertEquals(2, component.getLocalCandidateCount());
    }

    private StunResponseEvent createSuccessResponseEvent(HostCandidate local, RemoteCandidate remote)
        throws Exception
    {
        CandidatePair checkedPair = agent.createCandidatePair(local, remote);

        TransactionID transactionID = TransactionID.createNewTransactionID();
        transactionID.setApplicationData(checkedPair);

        Request request = MessageFactory.createBindingRequest(1000);
        request.setTransactionID(transactionID.getBytes());
        Response response = MessageFactory.createBindingResponse(request, MAPPED_ADDRESS);
        response.setTransactionID(transactionID.getBytes());

        RawMessage rawMessage = RawMessage.build(
                new byte[0],
                0,
                remote.getTransportAddress(),
                local.getTransportAddress());

        return new StunResponseEvent(agent.getStunStack(), rawMessage, response, request, transactionID);
    }

    /**
     * An agent which can simulate that a lookup of a local candidate ran before another thread added a candidate,
     * and which records the pairs that are validated.
     */
    private static class TestAgent
        extends Agent
    {
        /** Run once, before the first lookup returns {@code null} for the mapped address. */
        volatile Runnable beforeLookupReturnsNull;

        final List<CandidatePair> validatedPairs = Collections.synchronizedList(new ArrayList<>());

        private final AtomicBoolean lookupDone = new AtomicBoolean();

        TestAgent()
        {
            super("test", null);
        }

        @Override
        public LocalCandidate findLocalCandidate(TransportAddress address, LocalCandidate base)
        {
            Runnable hook = beforeLookupReturnsNull;
            if (hook != null && MAPPED_ADDRESS.equals(address) && lookupDone.compareAndSet(false, true))
            {
                // Simulate that the lookup finished before the other thread added its candidate.
                hook.run();
                return null;
            }
            return super.findLocalCandidate(address, base);
        }

        @Override
        protected void validatePair(CandidatePair validPair)
        {
            validatedPairs.add(validPair);
            super.validatePair(validPair);
        }
    }
}
