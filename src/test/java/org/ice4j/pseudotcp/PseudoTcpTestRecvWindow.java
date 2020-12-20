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
import java.util.*;
import java.util.logging.*;

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.pseudotcp.util.*;
import org.junit.jupiter.api.*;

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

    private void doTestTransfer(int size)
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        testDataSize = size;
        long start, elapsed;
        send_position = new ArrayList<>();
        recv_position = new ArrayList<>();
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
            fail(ex.getMessage());
        }
        //assert Connect() == 0;
        //TODO: check assert result and fail
        // Connect and wait until connected.
        assert_Connected_wait(kConnectTimeoutMs);

        scheduleWriteAction(0);

        long transferTout = maxTransferTime(dummy.length, kMinTransferRate);
        boolean transferInTime = assert_Disconnected_wait(transferTout);
        elapsed = PseudoTCPBase.now() - start;
        stopClocks();
        int received = recv_stream.getBuffered();
        assertTrue(transferInTime, "Transfer timeout, transferred: " + received
            + " required: " + dummy.length
            + " elapsed: "
            + elapsed + " limit: " + transferTout);

        assert 2 == send_position.size();
        assert 2 == recv_position.size();

        int estimated_recv_window = estimateReceiveWindowSize();

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
     * @return count bytes shadowed by scale actor
     */
    static int getShadowedBytes(int scaleFactor)
    {
        return (int) (Math.pow(2, scaleFactor) - 1);
    }

    /**
     * Reads all data available at the buffer
     */
    void readUntilIOPending() throws IOException
    {
        byte[] block = new byte[getRemoteTcp().getRecvBufferSize() * 2];
        int position = recv_stream.getBuffered();
        int rcvd, total = 0;
        do
        {
            rcvd = remoteRecv(block, block.length);
            if (rcvd > 0)
            {
                recv_stream.write(block, rcvd);
                total += rcvd;
                position += rcvd;
            }
        }
        while (rcvd > 0 && total != 0);
        recv_position.add(position);

        // Disconnect if we have done two transfers.
        if (recv_position.size() == 2)
        {
            close();
            onTcpClosed(getRemoteTcp(), null);
        }
        else
        {
            writeData();
        }
    }

    /**
     * Schedules write operation with <tt>delay</tt> given in ms
     */
    void scheduleWriteAction(long delay)
    {
        writeTimer.schedule(new TimerTask()
        {
            @Override
            public void run()
            {
                try
                {
                    writeData();
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
     */
    void writeData() throws IOException
    {
        //writeOpCount++;
        int tosend;
        int sent;
        int totalSent = 0;
        byte[] block = new byte[getRemoteTcp().getRecvBufferSize() * 2];
        int position = testDataSize - send_stream.getBuffered();
        synchronized (getLocalTcp())
        {
            do
            {
                tosend = send_stream.readOffset(block, 0, block.length, 0);
                if (tosend > 0)
                {
                    sent = localSend(block, tosend);
                    updateLocalClock();
                    if (sent > 0)
                    {
                        totalSent += sent;
                        send_stream.consumeReadData(sent);
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
        if (totalSent - getRemoteTcp().getAvailable()
            > getShadowedBytes(getRemoteScaleFactor()))
        {
            //send buffer was fully filled
            //waits until it will be received by remote peer
            while (totalSent - getRemoteTcp().getAvailable()
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
                            + getRemoteTcp().getAvailable() + " buffered not sent: "
                            + getLocalTcp().getBytesBufferedNotSent()
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
                    readUntilIOPending();
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
    int estimateReceiveWindowSize()
    {
        return recv_position.get(0);
    }

    /**
     *
     * @return estimated send window size
     */
    int estimateSendWindowSize()
    {
        return send_position.get(0);
    }

    @Override
    public void onTcpReadable(PseudoTCPBase tcp)
    {
    }

    @Override
    public void onTcpWriteable(PseudoTCPBase tcp)
    {
    }

    void setLocalOptSndBuf(int len)
    {
        getLocalTcp().setOption(Option.OPT_SNDBUF, len);
    }

    int getRemoteScaleFactor()
    {
        return getRemoteTcp().getM_rwnd_scale();
    }

    @Test
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
    @Test
    public void testReceiveWindow()
    {
        //logger.log(Level.INFO, "Test receive window");
        PseudoTcpTestRecvWindow test = new PseudoTcpTestRecvWindow();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptNagling(false);
        test.setOptAckDelay(0);
        test.doTestTransfer(1024 * 1000);
    }

    /**
     * Test setting send window size to a very small value.
     */
    @Test
    public void testSetVerySmallSendWindowSize()
    {
        //TODO: finish test
        logger.log(Level.INFO, "Test very small receive window");
        PseudoTcpTestRecvWindow test = new PseudoTcpTestRecvWindow();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptNagling(false);
        test.setOptAckDelay(0);
        test.setOptSndBuf(900);
        test.doTestTransfer(1024 * 1000);
        assertEquals(900, test.estimateSendWindowSize());
    }

    /**
     * Test setting receive window size to a value other than default.
     */
    @Test
    public void testSetReceiveWindowSize()
    {
        //logger.log(Level.INFO, "Test set receive window size");
        PseudoTcpTestRecvWindow test = new PseudoTcpTestRecvWindow();
        test.setLocalMtu(1500);
        test.setRemoteMtu(1500);
        test.setOptNagling(false);
        test.setOptAckDelay(0);
        int wndSize = 300000;
        // if window scaling is not supported by either local or remote, use 
        // default size
        if (!test.getLocalTcp().m_support_wnd_scale || 
            !test.getRemoteTcp().m_support_wnd_scale)
        {
        	wndSize = 65535;
        }
        test.setLocalOptSndBuf(wndSize);        	
        test.setRemoteOptRcvBuf(wndSize);
        int wndScale = test.getRemoteScaleFactor();
        //logger.log(Level.INFO, "Using scale factor: {0}", wndScale);
        test.doTestTransfer(1024 * 3000);
        //beacuse there may be situations 
        //when 1 byte may be waiting in send queue
        //before 
        //scaling factor == 1 not allows to determine exact window size (+-1)
        assert (wndSize - test.estimateReceiveWindowSize()
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
