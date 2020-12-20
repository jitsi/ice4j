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

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.util.logging.*;
import org.junit.jupiter.api.*;

/**
 * Implements one way transfer test
 *
 * @author Pawel Domas
 */
public class PseudoTcpTestTransfer extends PseudoTcpTestBase
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(PseudoTCPBase.class.getName());

    /**
     * The send data
     */
    private byte[] sendData;
    /**
     * Send stream size
     */
    private int sendStreamSize;
    /**
     * Total bytes sent counter
     */
    private int totalSent;
    /**
     * Receive stream
     */
    private ByteArrayOutputStream recvStream;

    /**
     * Transfers the data of <tt>size</tt> bytes
     */
    private void doTestTransfer(int size)
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        long start, elapsed;
        int received;
        // Create some dummy data to send
        sendData = createDummyData(size);
        sendStreamSize = size;

        // Prepare the receive stream.
        recvStream = new ByteArrayOutputStream(size);
        // Connect and wait until connected.
        start = PseudoTCPBase.now();
        startClocks();
        try
        {
            connect();
        }
        catch (IOException ex)
        {
            fail(ex.getMessage());
        }

        assert_Connected_wait(kConnectTimeoutMs);
        // Sending will start from OnTcpWriteable and complete when all data has
        // been received.
        long transferTout = maxTransferTime(sendData.length, kMinTransferRate);
        boolean transferInTime = assert_Disconnected_wait(transferTout);
        elapsed = PseudoTCPBase.now() - start;
        stopClocks();
        received = recvStream.size();
        assertTrue(transferInTime,"Transfer timeout, transferred: " + received
            + " required: " + sendData.length
            + " elapsed: "
            + elapsed + " limit: " + transferTout);

        // Ensure we closed down OK and we got the right data.
        assertEquals(size, received);
        byte[] recvdArray = recvStream.toByteArray();
        assertArrayEquals(sendData, recvdArray);

        logger.log(Level.INFO,
                   "Transferred " + received + " bytes in " + elapsed
            + " ms (" + (size * 8 / elapsed) + " Kbps");

    }

    /**
     * Reads all data available at remote peer's buffer
     */
    void readData() throws IOException
    {
        byte[] block = new byte[kBlockSize];
        int rcvd;
        do
        {
            rcvd = remoteRecv(block, block.length);
            updateRemoteClock();
            if (rcvd != -1)
            {
                recvStream.write(block, 0, rcvd);
            }
        }
        while (rcvd > 0);
    }

    /**
     * Writes the data until there's space available
     *
     * @return true if there's no more data left to write
     */
    boolean writeData() throws IOException
    {
        int tosend;
        int sent;
        byte[] block = new byte[kBlockSize];
        do
        {
            tosend = Math.min(sendStreamSize - totalSent, block.length);
            System.arraycopy(sendData, totalSent, block, 0, tosend);
            if (tosend > 0)
            {
                sent = localSend(block, tosend);
                updateLocalClock();
                if (sent != -1)
                {
                    totalSent += sent;
                }
                else
                {
                    logger.log(Level.FINE, "Flow Controlled");
                }
            }
            else
            {
                sent = tosend = 0;
            }
        }
        while (sent > 0);

        if (logger.isLoggable(Level.FINER))
        {
            logger.log(Level.FINER, "Sent: " + totalSent
                + " remaining: " + (sendStreamSize - totalSent));
        }

        return tosend == 0;
    }

    /**
     * Catches TCP readable event for remote peer and reads the data. When total
     * read count equals send data size the test is finished.
     */
    @Override
    public void onTcpReadable(PseudoTCPBase tcp)
    {
        if (tcp == getRemoteTcp())
        {
            try
            {
                readData();
                // TODO: OnTcpClosed() is currently only notified on error -
                // there is no on-the-wire equivalent of TCP FIN.
                // So we fake the notification when all the data has been read.
                int received, required;
                received = recvStream.size();
                required = sendStreamSize;
                if (logger.isLoggable(Level.FINER))
                {
                    logger.log(Level.FINER, "Receivied: " + received
                        + " required: " + required);
                }
                if (received == required)
                {
                    onTcpClosed(getRemoteTcp(), null);
                }
            }
            catch (IOException ex)
            {
                throw new RuntimeException(ex);
            }
        }
    }

    /**
     * Catches on TCP writeable event for local peer. Writes all data and closes
     * the stream
     */
    @Override
    public void onTcpWriteable(PseudoTCPBase tcp)
    {
        if (tcp == getLocalTcp())
        {
            // Write bytes from the send stream when we can.
            // Shut down when we've sent everything.
            logger.log(Level.FINER, "Flow Control Lifted");
            try
            {
                if (writeData())
                {
                    close();
                }
            }
            catch (IOException ex)
            {
                ex.printStackTrace();
                fail(ex.getMessage());
            }
        }
    }

    /**
     * Basic end-to-end data transfer tests Test the normal case of sending data
     * from one side to the other.
     */
    @Test
    public void testSend()
    {
        //logger.log(Level.INFO, "Test send");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.doTestTransfer(1000000);
    }

    /**
     * Test sending data with a 50 ms RTT. Transmission should take longer due
     * to a slower ramp-up in send rate.
     */
    @Test
    public void testSendWithDelay()
    {
        //logger.log(Level.INFO, "Test send with delay");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setDelay(50);
        test.doTestTransfer(1000000);
    }

    /**
     * Test sending data with packet loss. Transmission should take much longer
     * due to send back-off when loss occurs.
     */
    @Test
    public void testSendWithLoss()
    {
        //logger.log(Level.INFO, "Test send with loss");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setLoss(10);
        test.doTestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with a 50 ms RTT and 10% packet loss. Transmission
     * should take much longer due to send back-off and slower detection of
     * loss.
     */
    @Test
    public void testSendWithDelayAndLoss()
    {
        //logger.log(Level.INFO, "Test send with delay and loss");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setDelay(50);
        test.setLoss(10);
        test.doTestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with 10% packet loss and Nagling disabled. Transmission
     * should take about the same time as with Nagling enabled.
     */
    @Test
    public void testSendWithLossAndOptNaglingOff()
    {
        //logger.log(Level.INFO, "Test send with loss and OptNagling off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setLoss(10);
        test.setOptNagling(false);
        test.doTestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with 10% packet loss and Delayed ACK disabled.
     * Transmission should be slightly faster than with it enabled.
     */
    @Test
    public void testSendWithLossAndOptAckDelayOff()
    {
        //logger.log(Level.INFO, "Test send with loss and OptAckDelay off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setLoss(10);
        test.setOptAckDelay(0);
        test.doTestTransfer(100000);
    }

    /**
     * Test sending data with 50ms delay and Nagling disabled.
     */
    @Test
    public void testSendWithDelayAndOptNaglingOff()
    {
        //logger.log(Level.INFO, "Test send with delay and OptNagling off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setDelay(50);
        test.setOptNagling(false);
        test.doTestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with 50ms delay and Delayed ACK disabled.
     */
    @Test
    public void testSendWithDelayAndOptAckDelayOff()
    {
        //logger.log(Level.INFO, "Test send with delay and OptAckDelay off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setDelay(50);
        test.setOptAckDelay(0);
        test.doTestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test a large receive buffer with a sender that doesn't support scaling.
     */
    @Test
    public void testSendRemoteNoWindowScale()
    {
        //logger.log(Level.INFO, "Test send - remote no window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setLocalOptRcvBuf(100000);
        test.disableRemoteWindowScale();
        test.doTestTransfer(1000000);
    }

    /**
     * Test a large sender-side receive buffer with a receiver that doesn't
     * support scaling.
     */
    @Test
    public void testSendLocalNoWindowScale()
    {
        //logger.log(Level.INFO, "Test send - local no window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setRemoteOptRcvBuf(100000);
        test.disableLocalWindowScale();
        test.doTestTransfer(1000000);
    }

    /**
     * Test when both sides use window scaling.
     */
    @Test
    public void testSendBothUseWindowScale()
    {
        //logger.log(Level.INFO, "Test send - both use window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setRemoteOptRcvBuf(100000);
        test.setLocalOptRcvBuf(100000);
        test.doTestTransfer(1000000);
    }

    /**
     * Test using a large window scale value.
     */
    @Test
    public void testSendLargeInFlight()
    {
        //logger.log(Level.INFO, "Test send large in flight");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setRemoteOptRcvBuf(100000);
        test.setLocalOptRcvBuf(100000);
        test.setOptSndBuf(150000);
        test.doTestTransfer(1000000);
    }

    @Test
    public void testSendBothUseLargeWindowScale()
    {
        //logger.log(Level.INFO, "Test send both use large window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setRemoteOptRcvBuf(1000000);
        test.setLocalOptRcvBuf(1000000);
        test.doTestTransfer(10000000);
    }

    /**
     * Test using a small receive buffer.
     */
    @Test
    public void testSendSmallReceiveBuffer()
    {
        //logger.log(Level.INFO, "Test send small receive buffer");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setRemoteOptRcvBuf(10000);
        test.setLocalOptRcvBuf(10000);
        test.doTestTransfer(1000000);
    }

    /**
     * Test using a very small receive buffer.
     */
    @Test
    public void testSendVerySmallReceiveBuffer()
    {
        //logger.log(Level.INFO, "Test send very small receive buffer");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setRemoteOptRcvBuf(100);
        test.setLocalOptRcvBuf(100);
        test.doTestTransfer(100000);
    }
}
