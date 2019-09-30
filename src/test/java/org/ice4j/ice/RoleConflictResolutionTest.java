/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2019 8x8, Inc
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
import org.junit.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * RoleConflictResolutionTest set of tests which does end-to-end test
 * of ICE role conflict recovery.
 *
 * @author Yura Yaroshevich
 */
public class RoleConflictResolutionTest
{
    protected static final Logger logger
        = Logger.getLogger(RoleConflictResolutionTest.class.getName());

    @Test
    public void testRecoveryFromBothControlledConflict()
        throws Throwable
    {
        testRecoveryFromRoleConflict(false);
    }

    @Test
    public void testRecoveryFromBothControllingConflict()
        throws Throwable
    {
        testRecoveryFromRoleConflict(true);
    }

    private static void testRecoveryFromRoleConflict(boolean bothControlling)
        throws Throwable
    {
        final Agent peer1 = createPeer("[peer-1]", bothControlling);
        // Set explicit tie-breakers to avoid automatic conflict resolution
        peer1.setTieBreaker(1);

        final Agent peer2 = createPeer("[peer-2]", bothControlling);
        peer1.setTieBreaker(2);

        final CountDownLatch countDownLatch = new CountDownLatch(2);

        for (Agent peer : Arrays.asList(peer1, peer2))
        {
            peer.addStateChangeListener(evt ->
            {
                logger.info(peer.toString() + ": state changed to "
                    + evt.toString());
                if (peer.getState().isEstablished())
                {
                    countDownLatch.countDown();
                }
            });
        }

        exchangeCredentials(peer1, peer2);
        exchangeCandidates(peer1, peer2);

        peer1.startConnectivityEstablishment();
        peer2.startConnectivityEstablishment();

        boolean isConnected = countDownLatch.await(20, TimeUnit.SECONDS);

        logSelectedPairs(peer1);
        logSelectedPairs(peer2);

        Assert.assertTrue("Expected connection established within time out",
            isConnected);
        Assert.assertTrue("peer 1 connectivity",
            peer1.getState().isEstablished());
        Assert.assertTrue("peer 2 connectivity",
            peer2.getState().isEstablished());

        disposePeer(peer1);
        disposePeer(peer2);
    }

    private static Agent createPeer(String label, boolean iceControlling)
        throws IOException
    {
        final Agent agent = new Agent(label, null);
        agent.setUseHostHarvester(true);
        agent.setControlling(iceControlling);
        IceMediaStream iceStream
            = agent.createMediaStream("media-stream");

        agent.createComponent(
            iceStream,
            Transport.UDP,
            0x400, 0x400, 0xFFFF,
            KeepAliveStrategy.ALL_SUCCEEDED,
            true);

        return agent;
    }

    private static void disposePeer(Agent peer)
    {
        peer.free();
    }

    private static void logSelectedPairs(Agent peer)
    {
        for (IceMediaStream stream : peer.getStreams())
        {
            for (Component component : stream.getComponents())
            {
                CandidatePair selectedPair = component.getSelectedPair();
                if (selectedPair != null)
                {
                    logger.info( peer.toString() + ": selected pair for " +
                        "component " + component.getName() + " :" +
                        selectedPair.toString());
                }
            }
        }
    }

    private static void exchangeCredentials(Agent peer1, Agent peer2)
    {
        for(IceMediaStream stream : peer2.getStreams())
        {
            stream.setRemoteUfrag(peer1.getLocalUfrag());
            stream.setRemotePassword(peer1.getLocalPassword());
        }

        for(IceMediaStream stream : peer1.getStreams())
        {
            stream.setRemoteUfrag(peer2.getLocalUfrag());
            stream.setRemotePassword(peer2.getLocalPassword());
        }
    }

    private static void exchangeCandidates(Agent peer1, Agent peer2)
    {
        for (String streamName : peer1.getStreamNames())
        {
            IceMediaStream peer1Stream = peer1.getStream(streamName);
            IceMediaStream peer2Stream = peer2.getStream(streamName);
            if (peer1Stream == null || peer2Stream == null)
            {
                continue;
            }

            for (Integer id : peer1Stream.getComponentIDs())
            {
                Component peer1Component = peer1Stream.getComponent(id);
                Component peer2Component = peer2Stream.getComponent(id);
                if (peer1Component == null || peer2Component == null)
                {
                    continue;
                }

                copyRemoteCandidates(peer1Component, peer2Component);
                copyRemoteCandidates(peer2Component, peer1Component);
            }
        }
    }

    private static void copyRemoteCandidates(Component localComponent,
                                             Component remoteComponent)
    {
        for(LocalCandidate candidate : remoteComponent.getLocalCandidates())
        {
            localComponent.addRemoteCandidate(
                new RemoteCandidate(
                    candidate.getTransportAddress(),
                    localComponent,
                    candidate.getType(),
                    candidate.getFoundation(),
                    candidate.getPriority(),
                    null));
        }
    }
}
