/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.pseudotcp;

import java.io.*;
import java.util.logging.*;
import org.ice4j.pseudotcp.util.*;
import static org.junit.Assert.*;
import org.junit.*;

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

    public PseudoTcpTestTransfer()
    {
        super();
    }
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
     *
     * @param size
     */
    public void TestTransfer(int size)
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
        start = PseudoTCPBase.Now();
        StartClocks();
        try
        {
            Connect();
            //assertEquals(0, Connect());
        }
        catch (IOException ex)
        {
            fail(ex.getMessage());
        }

        assert_Connected_wait(kConnectTimeoutMs);
        // Sending will start from OnTcpWriteable and complete when all data has
        // been received.
        long transferTout = MaxTransferTime(sendData.length, kMinTransferRate);
        boolean transfferInTime = assert_Disconnected_wait(transferTout);
        elapsed = PseudoTCPBase.Now() - start;
        StopClocks();
        received = recvStream.size();
        assertEquals("Transfer timeout, transferred: " + received
            + " required: " + sendData.length
            + " elapsed: "
            + elapsed + " limit: " + transferTout,
                     true, transfferInTime);

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
     *
     * @throws IOException
     */
    void ReadData() throws IOException
    {
        byte[] block = new byte[kBlockSize];
        int rcvd;
        do
        {
            rcvd = RemoteRecv(block, block.length);
            UpdateRemoteClock();
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
     * @throws IOException
     */
    boolean WriteData() throws IOException
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
                sent = LocalSend(block, tosend);
                UpdateLocalClock();
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
     *
     * @param tcp
     */
    @Override
    public void OnTcpReadable(PseudoTCPBase tcp)
    {
        if (tcp == getRemoteTcp())
        {
            try
            {
                ReadData();
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
                    OnTcpClosed(getRemoteTcp(), null);
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
     *
     * @param tcp
     */
    @Override
    public void OnTcpWriteable(PseudoTCPBase tcp)
    {
        if (tcp == getLocalTcp())
        {
            // Write bytes from the send stream when we can.
            // Shut down when we've sent everything.
            logger.log(Level.FINER, "Flow Control Lifted");
            try
            {
                if (WriteData())
                {
                    Close();
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
    public void testSend()
    {
        //logger.log(Level.INFO, "Test send");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.TestTransfer(1000000);
    }

    /**
     * Test sending data with a 50 ms RTT. Transmission should take longer due
     * to a slower ramp-up in send rate.
     */
    public void testSendWithDelay()
    {
        //logger.log(Level.INFO, "Test send with delay");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetDelay(50);
        test.TestTransfer(1000000);
    }

    /**
     * Test sending data with packet loss. Transmission should take much longer
     * due to send back-off when loss occurs.
     */
    public void testSendWithLoss()
    {
        //logger.log(Level.INFO, "Test send with loss");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetLoss(10);
        test.TestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with a 50 ms RTT and 10% packet loss. Transmission
     * should take much longer due to send back-off and slower detection of
     * loss.
     */
    public void testSendWithDelayAndLoss()
    {
        //logger.log(Level.INFO, "Test send with delay and loss");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetDelay(50);
        test.SetLoss(10);
        test.TestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with 10% packet loss and Nagling disabled. Transmission
     * should take about the same time as with Nagling enabled.
     */
    public void testSendWithLossAndOptNaglingOff()
    {
        //logger.log(Level.INFO, "Test send with loss and OptNagling off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetLoss(10);
        test.SetOptNagling(false);
        test.TestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with 10% packet loss and Delayed ACK disabled.
     * Transmission should be slightly faster than with it enabled.
     */
    public void testSendWithLossAndOptAckDelayOff()
    {
        //logger.log(Level.INFO, "Test send with loss and OptAckDelay off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetLoss(10);
        test.SetOptAckDelay(0);
        test.TestTransfer(100000);
    }

    /**
     * Test sending data with 50ms delay and Nagling disabled.
     */
    public void testSendWithDelayAndOptNaglingOff()
    {
        //logger.log(Level.INFO, "Test send with delay and OptNagling off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetDelay(50);
        test.SetOptNagling(false);
        test.TestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test sending data with 50ms delay and Delayed ACK disabled.
     */
    public void testSendWithDelayAndOptAckDelayOff()
    {
        //logger.log(Level.INFO, "Test send with delay and OptAckDelay off");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetDelay(50);
        test.SetOptAckDelay(0);
        test.TestTransfer(100000);  // less data so test runs faster
    }

    /**
     * Test a large receive buffer with a sender that doesn't support scaling.
     */
    public void testSendRemoteNoWindowScale()
    {
        //logger.log(Level.INFO, "Test send - remote no window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetLocalOptRcvBuf(100000);
        test.DisableRemoteWindowScale();
        test.TestTransfer(1000000);
    }

    /**
     * Test a large sender-side receive buffer with a receiver that doesn't
     * support scaling.
     */
    public void testSendLocalNoWindowScale()
    {
        //logger.log(Level.INFO, "Test send - local no window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetRemoteOptRcvBuf(100000);
        test.DisableLocalWindowScale();
        test.TestTransfer(1000000);
    }

    /**
     * Test when both sides use window scaling.
     */
    public void testSendBothUseWindowScale()
    {
        //logger.log(Level.INFO, "Test send - both use window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetRemoteOptRcvBuf(100000);
        test.SetLocalOptRcvBuf(100000);
        test.TestTransfer(1000000);
    }

    /**
     * Test using a large window scale value.
     */
    public void testSendLargeInFlight()
    {
        //logger.log(Level.INFO, "Test send large in flight");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetRemoteOptRcvBuf(100000);
        test.SetLocalOptRcvBuf(100000);
        test.SetOptSndBuf(150000);
        test.TestTransfer(1000000);
    }

    public void testSendBothUseLargeWindowScale()
    {
        //logger.log(Level.INFO, "Test send both use large window scale");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetRemoteOptRcvBuf(1000000);
        test.SetLocalOptRcvBuf(1000000);
        test.TestTransfer(10000000);
    }

    /**
     * Test using a small receive buffer.
     */
    public void testSendSmallReceiveBuffer()
    {
        //logger.log(Level.INFO, "Test send small receive buffer");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetRemoteOptRcvBuf(10000);
        test.SetLocalOptRcvBuf(10000);
        test.TestTransfer(1000000);
    }

    /**
     * Test using a very small receive buffer.
     */
    public void testSendVerySmallReceiveBuffer()
    {
        //logger.log(Level.INFO, "Test send very small receive buffer");
        PseudoTcpTestTransfer test = new PseudoTcpTestTransfer();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetRemoteOptRcvBuf(100);
        test.SetLocalOptRcvBuf(100);
        test.TestTransfer(100000);
    }
}
