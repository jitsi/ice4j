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
package org.ice4j.stack;

import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;
import org.ice4j.socket.*;
import org.junit.jupiter.api.*;

/**
 * Tests that {@link NetAccessManager#stop()} does not hold the connector map
 * locks while stopping connectors (and hence closing their sockets).
 *
 * A {@link RelayedCandidateDatagramSocket}'s send thread sends through
 * {@link NetAccessManager#sendMessage}, which takes the connector map lock,
 * while holding the socket's own send lock, which {@code close()} needs.
 * If {@code stop()} closed sockets under the map lock, that would be a lock
 * order inversion and {@code Agent.free()} could deadlock (ice4j issue #320).
 */
public class NetAccessManagerStopTest
{
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    @Test
    public void stopDoesNotHoldConnectorLockWhileClosingSockets()
        throws Exception
    {
        StunStack stunStack = new StunStack();
        DatagramSocket datagramSocket = new DatagramSocket(0, LOOPBACK);
        TransportAddress localAddress
            = new TransportAddress(LOOPBACK, datagramSocket.getLocalPort(), Transport.UDP);
        TransportAddress remoteAddress = new TransportAddress(LOOPBACK, 1, Transport.UDP);

        AtomicBoolean closeCalled = new AtomicBoolean(false);
        // Whether the sending thread finished while close() was still running, i.e. without waiting for stop() to
        // release the connector lock. It is recorded inside close(): checking it after shutDown() returns would race
        // with the sender being released once stop() exits its synchronized block.
        AtomicBoolean sendCompletedDuringClose = new AtomicBoolean(false);
        AtomicReference<Throwable> sendException = new AtomicReference<>();

        // A socket whose close() does what a RelayedCandidateDatagramSocket's close() effectively does: waits for
        // another thread which is in the middle of sending through the NetAccessManager.
        IceUdpSocketWrapper socket = new IceUdpSocketWrapper(datagramSocket)
        {
            @Override
            public void close()
            {
                closeCalled.set(true);
                Thread sender = new Thread(() ->
                {
                    try
                    {
                        stunStack.getNetAccessManager().sendMessage(new byte[1], localAddress, remoteAddress);
                    }
                    catch (Exception e)
                    {
                        // What matters is that the call returns, but keep the exception for diagnostics.
                        sendException.set(e);
                    }
                });
                sender.setDaemon(true);
                sender.start();
                try
                {
                    // On the unfixed code the sender blocks on the connector lock held by stop() until this times out.
                    sender.join(TimeUnit.SECONDS.toMillis(5));
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
                sendCompletedDuringClose.set(!sender.isAlive());
                super.close();
            }
        };

        stunStack.addSocket(socket);
        try
        {
            stunStack.shutDown();
        }
        finally
        {
            datagramSocket.close();
        }

        assertTrue(closeCalled.get(), "The socket should have been closed by shutDown()");
        assertTrue(sendCompletedDuringClose.get(),
            "sendMessage() blocked on the connector lock while stop() was closing the socket");
        // The connector is still registered while it is being stopped, so the send went through it.
        assertNull(sendException.get(), "sendMessage() failed: " + sendException.get());
    }
}
