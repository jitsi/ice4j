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
import java.nio.charset.*;

import org.ice4j.*;
import org.ice4j.socket.*;
import org.junit.jupiter.api.*;

/**
 * Tests the choice of {@link CandidatePair} in {@link Component#send(byte[], int, int)}.
 */
public class ComponentSendTest
{
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    private Agent agent;
    private IceMediaStream stream;
    private Component component;

    /** The local socket which the component sends from. */
    private DatagramSocket localSocket;
    /** Sockets standing in for two different remote addresses of the same peer. */
    private DatagramSocket remoteA;
    private DatagramSocket remoteB;

    private CandidatePair pairA;
    private CandidatePair pairB;

    @BeforeEach
    public void setUp()
        throws IOException
    {
        localSocket = new DatagramSocket(0, LOOPBACK);
        remoteA = new DatagramSocket(0, LOOPBACK);
        remoteB = new DatagramSocket(0, LOOPBACK);
        remoteA.setSoTimeout(200);
        remoteB.setSoTimeout(200);

        agent = new Agent("test", null);
        agent.setControlling(true);
        stream = agent.createMediaStream("stream");
        // Create the component directly on the stream rather than via Agent.createComponent(), which would harvest
        // candidates on the real network interfaces. We only need the loopback host candidate created below.
        component = stream.createComponent(KeepAliveStrategy.SELECTED_ONLY, false);

        HostCandidate local = new HostCandidate(new IceUdpSocketWrapper(localSocket), component);
        component.addLocalCandidate(local);

        // B has a higher priority than A, so it sorts first in the valid list.
        RemoteCandidate remoteCandidateA = createRemoteCandidate(remoteA, 1000);
        RemoteCandidate remoteCandidateB = createRemoteCandidate(remoteB, 2000);

        pairA = agent.createCandidatePair(local, remoteCandidateA);
        pairB = agent.createCandidatePair(local, remoteCandidateB);
        assertTrue(pairB.getPriority() > pairA.getPriority());
    }

    @AfterEach
    public void tearDown()
    {
        if (agent != null)
        {
            agent.free();
        }
        for (DatagramSocket socket : new DatagramSocket[] { localSocket, remoteA, remoteB })
        {
            if (socket != null)
            {
                socket.close();
            }
        }
    }

    private RemoteCandidate createRemoteCandidate(DatagramSocket socket, long priority)
    {
        return new RemoteCandidate(
                new TransportAddress(LOOPBACK, socket.getLocalPort(), Transport.UDP),
                component,
                CandidateType.PEER_REFLEXIVE_CANDIDATE,
                "foundation" + priority,
                priority,
                null);
    }

    private void send(String payload)
        throws IOException
    {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        component.send(bytes, 0, bytes.length);
    }

    private static String receive(DatagramSocket socket)
        throws IOException
    {
        DatagramPacket p = new DatagramPacket(new byte[1500], 1500);
        socket.receive(p);
        return new String(p.getData(), p.getOffset(), p.getLength(), StandardCharsets.UTF_8);
    }

    private static void assertNothingReceived(DatagramSocket socket)
        throws IOException
    {
        DatagramPacket p = new DatagramPacket(new byte[1500], 1500);
        try
        {
            socket.receive(p);
            fail("Unexpected packet received on " + socket.getLocalSocketAddress());
        }
        catch (SocketTimeoutException expected)
        {
        }
    }

    /**
     * Before any pair is selected we may fall back to sending to a valid pair. Once a pair is selected, we must
     * switch to it, even if the pair we used before was different.
     */
    @Test
    public void testSwitchesToSelectedPairAfterNomination()
        throws IOException
    {
        // A is validated first, then B (which has a higher priority).
        pairA.setStateSucceeded();
        stream.addToValidList(pairA);
        pairB.setStateSucceeded();
        stream.addToValidList(pairB);
        assertNull(component.getSelectedPair());

        // Sending before nomination falls back to the highest-priority valid pair.
        send("pre-nomination");
        assertEquals("pre-nomination", receive(remoteB));
        assertNothingReceived(remoteA);

        // Now A is nominated and selected.
        component.setSelectedPair(pairA);

        send("post-nomination");
        assertEquals("post-nomination", receive(remoteA));
        assertNothingReceived(remoteB);

        // And it stays on the selected pair.
        send("post-nomination-2");
        assertEquals("post-nomination-2", receive(remoteA));
        assertNothingReceived(remoteB);
    }

    /**
     * When there is a selected pair from the start, it is used.
     */
    @Test
    public void testSendsToSelectedPair()
        throws IOException
    {
        pairA.setStateSucceeded();
        stream.addToValidList(pairA);
        pairB.setStateSucceeded();
        stream.addToValidList(pairB);
        component.setSelectedPair(pairA);

        send("hello");
        assertEquals("hello", receive(remoteA));
        assertNothingReceived(remoteB);
    }

    /**
     * If the selected pair changes, sending follows it.
     */
    @Test
    public void testFollowsSelectedPairChange()
        throws IOException
    {
        pairA.setStateSucceeded();
        stream.addToValidList(pairA);
        pairB.setStateSucceeded();
        stream.addToValidList(pairB);

        component.setSelectedPair(pairA);
        send("to-a");
        assertEquals("to-a", receive(remoteA));

        component.setSelectedPair(pairB);
        send("to-b");
        assertEquals("to-b", receive(remoteB));
        assertNothingReceived(remoteA);
    }

    @Test
    public void testNoValidPair()
    {
        assertThrows(IOException.class, () -> send("nowhere"));
    }
}
