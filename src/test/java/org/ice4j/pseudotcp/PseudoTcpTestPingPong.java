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
package org.ice4j.pseudotcp;

import java.io.*;
import java.util.logging.*;

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.pseudotcp.util.*;
import org.junit.jupiter.api.*;

/**
 * This class implements test for two way transfers
 *
 * @author Pawel Domas
 */
public class PseudoTcpTestPingPong extends PseudoTcpTestBase
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(PseudoTCPBase.class.getName());
    /**
     * The sender
     */
    private PseudoTCPBase sender;
    /**
     * The receiver
     */
    private PseudoTCPBase receiver;
    /**
     * How much data is sent per ping
     */
    private int bytesPerSend;
    /**
     * Iterations count
     */
    private int iterationsRemaining;

    public void setBytesPerSend(int bytes_per_send)
    {
        this.bytesPerSend = bytes_per_send;
    }
    /**
     * The send stream buffer
     */
    ByteFifoBuffer send_stream;
    /**
     * The receive stream buffer
     */
    ByteFifoBuffer recv_stream;

    /**
     * Performs ping-pong test for <tt>iterations</tt> with packets of
     * <tt>size</tt> bytes
     */
    private void doTestPingPong(int size, int iterations)
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        long start;
        iterationsRemaining = iterations;
        receiver = getRemoteTcp();
        sender = getLocalTcp();
        // Create some dummy data
        byte[] dummy = createDummyData(size);
        send_stream = new ByteFifoBuffer(size);
        send_stream.write(dummy, size);
        //Prepare the receive stream
        recv_stream = new ByteFifoBuffer(size);
        //Connect and wait until connected
        start = PseudoTCPBase.now();
        startClocks();
        try
        {
            connect();
        }
        catch (IOException ex)
        {
            ex.printStackTrace();
            fail(ex.getMessage());
        }
        //assert Connect() == 0;
        assert_Connected_wait(kConnectTimeoutMs);
        // Sending will start from OnTcpWriteable and stop when the required
        // number of iterations have completed.
        assert_Disconnected_wait(kMinTransferRate);
        long elapsed = PseudoTCPBase.now() - start;
        stopClocks();
        logger.log(Level.INFO,
                   "Performed " + iterations + " pings in " + elapsed + " ms");
    }

    /**
     * Catches onTcpReadable event for receiver
     */
    @Override
    public void onTcpReadable(PseudoTCPBase tcp)
    {
        assertEquals(receiver, tcp, "Unexpected onTcpReadable");
        try
        {
            // Stream bytes to the recv stream as they arrive.
            readData();
        }
        catch (IOException ex)
        {
            //will be caught by default handler and test will fail
            throw new RuntimeException(ex);
        }
        // If we've received the desired amount of data, rewind things
        // and send it back the other way!
        int recvd = recv_stream.getBuffered();
        int required = send_stream.length();
        if (logger.isLoggable(Level.FINER))
        {
            logger.log(Level.FINER,
                       "test - receivied: " + recvd + " required: " + required);
        }

        if (recvd == required)
        {
            if (receiver == getLocalTcp() && --iterationsRemaining == 0)
            {
                close();
                // TODO: Fake OnTcpClosed() on the receiver for now.
                onTcpClosed(getRemoteTcp(), null);
                return;
            }
            //switches receivier with sender and performs test the other way
            PseudoTCPBase tmp = receiver;
            receiver = sender;
            sender = tmp;
            send_stream.resetReadPosition();
            send_stream.consumeWriteBuffer(send_stream.getWriteRemaining());
            recv_stream.resetWritePosition();
            onTcpWriteable(sender);
        }

    }

    /**
     * Catches the ontcpWriteable event for sender
     */
    @Override
    public void onTcpWriteable(PseudoTCPBase tcp)
    {
        if (tcp != sender)
        {
            return;
        }
        // Write bytes from the send stream when we can.
        // Shut down when we've sent everything.
        logger.log(Level.FINER, "Flow Control Lifted");
        try
        {
            writeData();
        }
        catch (IOException ex)
        {
            throw new RuntimeException(ex);
        }

    }

    /**
     * Reads the data in loop until is something available
     */
    private void readData() throws IOException
    {
        byte[] block = new byte[kBlockSize];
        int rcvd;
        do
        {
            rcvd = receiver.recv(block, block.length);
            if (rcvd > 0)
            {
                recv_stream.write(block, rcvd);
                if (logger.isLoggable(Level.FINE))
                {
                    logger.log(Level.FINE,
                               "Receivied: " + recv_stream.getBuffered());
                }
            }
        }
        while (rcvd > 0);
    }

    /**
     * Writes all data to the receiver
     */
    private void writeData() throws IOException
    {
        int tosend;
        int sent;
        byte[] block = new byte[kBlockSize];
        do
        {
            tosend = bytesPerSend != 0 ? bytesPerSend : block.length;
            tosend = send_stream.read(block, tosend);
            if (tosend > 0)
            {
                sent = sender.send(block, tosend);
                updateLocalClock();
                if (sent != -1)
                {
                    if(logger.isLoggable(Level.FINE))
                    {
                        logger.log(Level.FINE, "Sent: " + sent);
                    }
                }
                else
                {
                    logger.log(Level.FINE, "Flow controlled");
                }
            }
            else
            {
                sent = tosend = 0;
            }
        }
        while (sent > 0);
    }

    /*
     *
     * Ping-pong (request/response) tests
     *
     */
    /**
     * Test sending <= 1x MTU of data in each ping/pong. Should take <10ms.
     */
    @Test
    public void testPingPong1xMtu()
    {
        //logger.log(Level.INFO, "Test ping - pong 1xMTU");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.doTestPingPong(100, 100);
    }

    /**
     * Test sending 2x-3x MTU of data in each ping/pong. Should take <10ms.
     */
    @Test
    public void testPingPong3xMtu()
    {
        //logger.log(Level.INFO, "Test ping - pong 3xMTU");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.doTestPingPong(400, 100);
    }

    /**
     * Test sending 1x-2x MTU of data in each ping/pong. Should take ~1s, due to
     * interaction between Nagling and Delayed ACK.
     */
    @Test
    public void testPingPong2xMtu()
    {
        //logger.log(Level.INFO, "Test ping - pong 2xMTU");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.doTestPingPong(2000, 5);
    }

    /**
     * Test sending 1x-2x MTU of data in each ping/pong with Delayed ACK off.
     * Should take <10ms.
     */
    @Test
    public void testPingPong2xMtuWithAckDelayOff()
    {
        //logger.log(Level.INFO, "Test ping - pong 2xMTU ack delay off");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptAckDelay(0);
        test.doTestPingPong(2000, 100);
    }

    /**
     * Test sending 1x-2x MTU of data in each ping/pong with Nagling off. Should
     * take <10ms.
     */
    @Test
    public void testPingPong2xMtuWithNaglingOff()
    {
        //logger.log(Level.INFO, "Test ping - pong 2xMTU nagling off");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptNagling(false);
        test.doTestPingPong(2000, 5);
    }

    /**
     * Test sending a ping as pair of short (non-full) segments. Should take
     * ~1s, due to Delayed ACK interaction with Nagling.
     */
    @Test
    public void testPingPongShortSegments()
    {
        //logger.log(Level.INFO, "Test ping - pong short segments");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptAckDelay(5000);
        test.setBytesPerSend(50); // i.e. two Send calls per payload
        test.doTestPingPong(100, 5);
    }

    /**
     * Test sending ping as a pair of short (non-full) segments, with Nagling
     * off. Should take <10ms.
     */
    @Test
    public void testPingPongShortSegmentsWithNaglingOff()
    {
        //logger.log(Level.INFO, "Test ping - pong short segments nagling off");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptNagling(false);
        test.setBytesPerSend(50); // i.e. two Send calls per payload
        test.doTestPingPong(100, 5);
    }

    /**
     * Test sending <= 1x MTU of data ping/pong, in two segments, no Delayed
     * ACK. Should take ~1s.
     */
    @Test
    public void testPingPongShortSegmentsWithAckDelayOff()
    {
        //logger.log(Level.INFO, "Test ping - pong short segments nagling off");
        PseudoTcpTestPingPong test = new PseudoTcpTestPingPong();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setBytesPerSend(50); // i.e. two Send calls per payload
        test.setOptAckDelay(0);
        test.doTestPingPong(100, 5);
    }
}
