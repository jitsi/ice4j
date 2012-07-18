/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.pseudotcp;

import java.io.*;
import java.util.*;
import java.util.logging.*;
import org.ice4j.pseudotcp.util.*;
import static org.junit.Assert.*;
import org.junit.*;

/**
 * Fill the receiver window until it is full, drain it and then fill it with the
 * same amount. This is to test that receiver window contracts and enlarges
 * correctly.
 *
 * @author Pawel Domas
 */
public class PseudoTcpTestRecvWindow extends PseudoTcpTestBase
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(PseudoTCPBase.class.getName());
    /**
     * Send data buffer
     */
    private ByteFifoBuffer send_stream;
    /**
     * List which stores stream position after each write cycle
     */
    private List<Integer> send_position;
    /**
     * Receive data buffer
     */
    private ByteFifoBuffer recv_stream;
    /**
     * List which stores stream position after each read cycle
     */
    private List<Integer> recv_position;
    /**
     * Times used for write operations scheduling
     */
    private Timer writeTimer = new Timer("WriteTimer");
    /**
     * Stores data length used for the test.
     */
    private int testDataSize;

    public void TestTransfer(int size)
    {
        testDataSize = size;
        long start, end, elapsed;
        send_position = new ArrayList<Integer>();
        recv_position = new ArrayList<Integer>();
        // Create some dummy data
        byte[] dummy = createDummyData(size);
        send_stream = new ByteFifoBuffer(size);
        send_stream.Write(dummy, size);
        //Prepare the receive stream
        recv_stream = new ByteFifoBuffer(size);
        //Connect and wait until connected
        start = PseudoTCPBase.Now();
        StartClocks();
        try
        {
            Connect();
        }
        catch (IOException ex)
        {
            fail(ex.getMessage());
        }
        //assert Connect() == 0;
        //TODO: check assert result and fail
        // Connect and wait until connected.
        assert_Connected_wait(kConnectTimeoutMs);

        ScheduleWriteAction(0);

        long transferTout = MaxTransferTime(dummy.length, kMinTransferRate);
        System.out.println("Timeout: " + transferTout);
        boolean transfferInTime = assert_Disconnected_wait(transferTout);
        elapsed = PseudoTCPBase.Now() - start;
        StopClocks();
        int received = recv_stream.GetBuffered();
        assertEquals("Transfer timeout, transferred: " + received
            + " required: " + dummy.length
            + " elapsed: "
            + elapsed + " limit: " + transferTout,
                     true, transfferInTime);

        assert 2 == send_position.size();
        assert 2 == recv_position.size();

        int estimated_recv_window = EstimateReceiveWindowSize();

        // The difference in consecutive send positions should equal the
        // receive window size or match very closely. This verifies that receive
        // window is open after receiver drained all the data.
        int send_position_diff = send_position.get(1) - send_position.get(0);
        assertTrue(estimated_recv_window - send_position_diff <= 1024);

        // Receiver drained the receive window twice.(+-2 because of window scaling)        
        assert ((recv_position.get(1) - 2 * estimated_recv_window)
            <= getShadowedBytes(getRemoteScaleFactor()));
    }

    /**
     * This function calculates amount of bytes witch may introduce error to
     * estimation of receive window size caused by scale factor. This is because
     * data is being sent until all sent data is available in remote side's
     * buffer. But because of scale factor window size 0 is reached earlier than
     * expected and some data may still wait for window to open in the send
     * queue.
     *
     * For example: m_rcv_scale == 1 and m_rcv_wnd < 2 then rcv_wnd == 0 (1 byte
     * may block) m_rcv_scale == 2 and m_rcv_wnd < 4 then rcv_wnd == 0 (3 bytes
     * may block) m_rcv_scale == 3 and m_rcv_wnd < 8 then rcv_wnd == 0 (7 bytes
     * may block) and so on...
     *
     * In normal operation something would read data on remote side causing
     * window to expand.
     *
     *
     *
     *

     *
     * @param scaleFactor
     * @return count bytes shadowed by scale actor
     */
    static int getShadowedBytes(int scaleFactor)
    {
        return (int) (Math.pow(2, scaleFactor) - 1);
    }

    /**
     * Reads all data available at the buffer
     *
     * @throws IOException
     */
    void ReadUntilIOPending() throws IOException
    {
        byte[] block = new byte[getRemoteTcp().getRecvBufferSize() * 2];
        int position = recv_stream.GetBuffered();
        int rcvd, total = 0;
        do
        {
            rcvd = RemoteRecv(block, block.length);
            if (rcvd > 0)
            {
                recv_stream.Write(block, rcvd);
                total += rcvd;
                position += rcvd;
            }
        }
        while (rcvd > 0 && total != 0);
        recv_position.add(position);

        // Disconnect if we have done two transfers.
        if (recv_position.size() == 2)
        {
            Close();
            OnTcpClosed(getRemoteTcp(), null);
        }
        else
        {
            WriteData();
        }
    }

    /**
     * Schedules write operation with <tt>delay</tt> given in ms
     *
     * @param delay
     */
    void ScheduleWriteAction(long delay)
    {
        writeTimer.schedule(new TimerTask()
        {
            @Override
            public void run()
            {
                try
                {
                    WriteData();
                }
                catch (IOException ex)
                {
                    //it will get cought by 
                    //deafult exception handler in PseudoTcpTestBase
                    throw new RuntimeException(ex);
                }
            }
        }, delay);
    }

    /**
     * Writes the data
     *
     * @throws IOException
     */
    void WriteData() throws IOException
    {
        //writeOpCount++;
        int tosend;
        int sent;
        int totalSent = 0;
        byte[] block = new byte[getRemoteTcp().getRecvBufferSize() * 2];
        int position = testDataSize - send_stream.GetBuffered();
        synchronized (getLocalTcp())
        {
            do
            {
                tosend = send_stream.ReadOffset(block, 0, block.length, 0);
                if (tosend > 0)
                {
                    sent = LocalSend(block, tosend);
                    UpdateLocalClock();
                    if (sent > 0)
                    {
                        totalSent += sent;
                        send_stream.ConsumeReadData(sent);
                        position += sent;
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
            //position = send_stream.GetBuffered();

        }
        // Measured with precision according to window scale option used
        if (totalSent - getRemoteTcp().GetAvailable()
            > getShadowedBytes(getRemoteScaleFactor()))
        {
            //send buffer was fully filled
            //waits until it will be received by remote peer
            while (totalSent - getRemoteTcp().GetAvailable()
                > getShadowedBytes(getRemoteScaleFactor())
                && !getRemoteTcp().isReceiveBufferFull())
            {
                try
                {
                    Thread.sleep(50);
                    if (logger.isLoggable(Level.FINER))
                    {
                        logger.log(Level.FINER,
                                   "Waiting... sent: " + totalSent + " avail: "
                            + getRemoteTcp().GetAvailable() + " buffered not sent: "
                            + getLocalTcp().GetBytesBufferedNotSent()
                            + " isFull? " + getRemoteTcp().isReceiveBufferFull());
                    }
                }
                catch (InterruptedException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        }
        send_position.add(position);
        writeTimer.schedule(new TimerTask()
        {
            @Override
            public void run()
            {
                try
                {
                    ReadUntilIOPending();
                }
                catch (IOException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        }, 10);
    }

    /**
     *
     * @return estimated receive window size
     */
    int EstimateReceiveWindowSize()
    {
        return recv_position.get(0);
    }

    /**
     *
     * @return estimated send window size
     */
    int EstimateSendWindowSize()
    {
        return send_position.get(0);
    }

    @Override
    public void OnTcpReadable(PseudoTCPBase tcp)
    {
    }

    @Override
    public void OnTcpWriteable(PseudoTCPBase tcp)
    {
    }

    void SetLocalOptSndBuf(int len)
    {
        getLocalTcp().SetOption(Option.OPT_SNDBUF, len);
    }

    int getRemoteScaleFactor()
    {
        return getRemoteTcp().getM_rwnd_scale();
    }

    public void testGetShadowedBytes()
    {
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(0) == 0);
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(1) == 1);
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(2) == 3);
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(3) == 7);
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(4) == 15);
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(11) == 2047);
        assert (PseudoTcpTestRecvWindow.getShadowedBytes(14) == 16383);
    }

    /**
     * Test that receive window expands and contract correctly.
     */
    public void testReceiveWindow()
    {
        //logger.log(Level.INFO, "Test receive window");
        PseudoTcpTestRecvWindow test = new PseudoTcpTestRecvWindow();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetOptNagling(false);
        test.SetOptAckDelay(0);
        test.TestTransfer(1024 * 1000);
    }

    /**
     * Test setting send window size to a very small value.
     */
    public void testSetVerySmallSendWindowSize()
    {
        //TODO: finish test
        logger.log(Level.INFO, "Test very small receive window");
        PseudoTcpTestRecvWindow test = new PseudoTcpTestRecvWindow();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetOptNagling(false);
        test.SetOptAckDelay(0);
        test.SetOptSndBuf(900);
        test.TestTransfer(1024 * 1000);
        assertEquals(900, test.EstimateSendWindowSize());
    }

    /**
     * Test setting receive window size to a value other than default.
     */
    public void testSetReceiveWindowSize()
    {
        //logger.log(Level.INFO, "Test set receive window size");
        PseudoTcpTestRecvWindow test = new PseudoTcpTestRecvWindow();
        test.SetLocalMtu(1500);
        test.SetRemoteMtu(1500);
        test.SetOptNagling(false);
        test.SetOptAckDelay(0);
        int wndSize = 300000;
        test.SetRemoteOptRcvBuf(wndSize);
        test.SetLocalOptSndBuf(wndSize);
        int wndScale = test.getRemoteScaleFactor();
        //logger.log(Level.INFO, "Using scale factor: {0}", wndScale);
        test.TestTransfer(1024 * 3000);
        //beacuse there may be situations 
        //when 1 byte may be waiting in send queue
        //before 
        //scaling factor == 1 not allows to determine exact window size (+-1)
        assert (wndSize - test.EstimateReceiveWindowSize()
            <= PseudoTcpTestRecvWindow.getShadowedBytes(wndScale));
    }

    /*
     * Test sending data with mismatched MTUs. We should detect this and reduce
     * // our packet size accordingly. // TODO: This doesn't actually work right
     * now. The current code // doesn't detect if the MTU is set too high on
     * either side. TEST_F(PseudoTcpTest, TestSendWithMismatchedMtus) {
     * SetLocalMtu(1500); SetRemoteMtu(1280); TestTransfer(1000000); }
     */
}
