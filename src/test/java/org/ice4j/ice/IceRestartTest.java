/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2024 - present 8x8, Inc.
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

import org.ice4j.*;
import org.junit.jupiter.api.*;

/**
 * Tests {@link Agent#restartIce()} — the in-place ICE restart on an existing,
 * already-concluded agent. This exercises the state-machine re-arm (un-terminate,
 * reset the check list, un-stop the check client, re-nominate) and, crucially,
 * verifies that the previously selected pair is kept in use throughout so media
 * never has to stop (make-before-break).
 *
 * The two agents connect over loopback using host candidates only (no STUN/UPnP,
 * so the test is hermetic). Because an {@link Agent}'s local credentials are
 * immutable, the "remote" side keeps its credentials across the restart; this is
 * sufficient to drive the full re-arm/re-validate/re-nominate path — the point of
 * the primitive is the state-machine reset, which is credential-independent.
 */
public class IceRestartTest
{
    private Agent localAgent;
    private Agent remotePeer;

    @BeforeEach
    public void setUp()
    {
        // Terminate a few seconds after completion: long enough that, once both
        // (ice4j) agents restart, they both re-complete before either re-enters
        // the terminated state (where its check client stops and would reject the
        // peer's in-flight checks), short enough to keep the test quick. In the
        // real (flavor B) scenario the peer is libwebrtc and never "terminates",
        // so this coupling does not exist.
        System.setProperty("org.ice4j.TERMINATION_DELAY", "3000");
    }

    @AfterEach
    public void tearDown()
    {
        System.clearProperty("org.ice4j.TERMINATION_DELAY");
        if (localAgent != null)
        {
            localAgent.free();
        }
        if (remotePeer != null)
        {
            remotePeer.free();
        }
    }

    @Test
    public void inPlaceRestartKeepsSelectedPair() throws Exception
    {
        localAgent = createAgent();
        remotePeer = createAgent();

        localAgent.setControlling(true);
        remotePeer.setControlling(false);

        // Exchange candidates and credentials both ways.
        transferRemoteCandidates(localAgent, remotePeer);
        transferRemoteCandidates(remotePeer, localAgent);

        localAgent.startConnectivityEstablishment();
        remotePeer.startConnectivityEstablishment();

        // Wait until the (controlling) local agent completes ICE.
        assertTrue(
            waitForState(localAgent, IceProcessingState.COMPLETED, 10000),
            "local agent should complete ICE");

        Component rtp = localAgent.getStream("audio").getComponent(Component.RTP);
        CandidatePair originalPair = rtp.getSelectedPair();
        assertNotNull(originalPair, "a pair should be selected after completion");

        // Wait for the agent to terminate (which stops its connectivity check
        // client) so the restart has to re-arm it.
        assertTrue(
            waitForState(localAgent, IceProcessingState.TERMINATED, 8000),
            "local agent should terminate after the termination delay");
        // Also wait for the peer to terminate so both are re-armed from the
        // stopped state by their respective restarts.
        assertTrue(
            waitForState(remotePeer, IceProcessingState.TERMINATED, 8000),
            "remote peer should terminate after the termination delay");
        // The selected pair must survive termination (media keeps flowing).
        CandidatePair pairBeforeRestart = rtp.getSelectedPair();
        assertNotNull(pairBeforeRestart, "selected pair must survive termination");

        // --- Restart ICE in place ---
        localAgent.restartIce();

        // The re-arm invariants (peer-independent, these are the landmines the
        // primitive has to get right):
        //  - the agent is moved out of TERMINATED back to RUNNING;
        //  - the check list is RUNNING again (so checks are actually scheduled);
        //  - the previously selected pair is STILL in use — media keeps flowing on
        //    it while the new generation is validated (make-before-break);
        //  - the component is flagged as restarting so the first pair nominated
        //    during the restart replaces (rather than being rejected by the
        //    set-once guard on) the selected pair.
        assertEquals(IceProcessingState.RUNNING, localAgent.getState(),
            "agent should be RUNNING again right after restartIce()");
        assertEquals(CheckListState.RUNNING,
            localAgent.getStream("audio").getCheckList().getState(),
            "check list should be RUNNING again after restartIce()");
        assertSame(pairBeforeRestart, rtp.getSelectedPair(),
            "the same selected pair must be preserved across the restart (make-before-break)");
        assertTrue(rtp.isIceRestarting(),
            "component should be flagged as ICE-restarting until a new pair is nominated");

        // The selected pair must never go null while checks re-run for a while.
        // (Full re-nomination/swap against a live peer is covered end-to-end by
        // the boris2 deployment test; here the peer is a terminated ice4j agent
        // whose role after a mutual restart is non-deterministic due to ICE
        // role-conflict resolution, so we don't assert on re-completion.)
        long deadline = System.currentTimeMillis() + 1000;
        while (System.currentTimeMillis() < deadline)
        {
            assertNotNull(rtp.getSelectedPair(),
                "selected pair must never be null during re-establishment");
            Thread.sleep(20);
        }
    }

    /**
     * Creates a host-candidate-only agent with a single "audio" stream and one
     * (RTP) component on an ephemeral port.
     */
    private Agent createAgent() throws Exception
    {
        Agent agent = new Agent();
        // No harvesters added -> host candidates only (hermetic).
        IceMediaStream stream = agent.createMediaStream("audio");
        agent.createComponent(stream, KeepAliveStrategy.SELECTED_ONLY, true);

        return agent;
    }

    private static void transferRemoteCandidates(Agent to, Agent from)
    {
        for (IceMediaStream toStream : to.getStreams())
        {
            IceMediaStream fromStream = from.getStream(toStream.getName());
            if (fromStream == null)
            {
                continue;
            }
            toStream.setRemoteUfrag(from.getLocalUfrag());
            toStream.setRemotePassword(from.getLocalPassword());

            for (Component toComponent : toStream.getComponents())
            {
                Component fromComponent = fromStream.getComponent(toComponent.getComponentID());
                if (fromComponent == null)
                {
                    continue;
                }
                for (LocalCandidate lc : fromComponent.getLocalCandidates())
                {
                    toComponent.addRemoteCandidate(new RemoteCandidate(
                        lc.getTransportAddress(),
                        toComponent,
                        lc.getType(),
                        lc.getFoundation(),
                        lc.getPriority(),
                        null));
                }
            }
        }
    }

    private static boolean waitForState(Agent agent, IceProcessingState target, long timeoutMs)
        throws InterruptedException
    {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline)
        {
            if (agent.getState() == target)
            {
                return true;
            }
            Thread.sleep(20);
        }
        return agent.getState() == target;
    }
}
