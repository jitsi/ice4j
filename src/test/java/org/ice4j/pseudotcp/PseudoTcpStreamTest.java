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
import java.net.*;
import java.util.concurrent.atomic.*;
import java.util.logging.*;
import org.junit.jupiter.api.*;

public class PseudoTcpStreamTest
    extends MultiThreadSupportTest
{
    /**
     * The logger.
     */
    private static final Logger logger = Logger
        .getLogger(PseudoTcpStreamTest.class.getName());

    /**
     * Test one-way transfer with @link(PseudoTcpStream)
     */
    @Test
    @Timeout(10)
    public void testConnectTransferClose() 
        throws IOException
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        int transferTimeout = 5000;

        // bytes that will be read as a single byte
        final int singleStepCount = 34;
        final byte[] bufferSingle =
            PseudoTcpTestBase.createDummyData(singleStepCount);
        final int sizeA = 138746;
        final byte[] bufferA = PseudoTcpTestBase.createDummyData(sizeA);
        final int sizeB = 983746;
        final byte[] bufferB = PseudoTcpTestBase.createDummyData(sizeB);
        final PseudoTcpSocket server = 
            new PseudoTcpSocketFactory().createSocket();
        server.setDebugName("L");
        server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        final InetSocketAddress serverAddress =
            new InetSocketAddress(InetAddress.getLoopbackAddress(), server.getLocalPort());
        AtomicBoolean clientThreadEnded = new AtomicBoolean();
        AtomicBoolean serverThreadEnded = new AtomicBoolean();
        Thread serverThread = new Thread(() ->
        {
            try
            {
                server.accept(5000);
                byte[] rcvdSingle = new byte[singleStepCount];
                // read by one byte
                for (int i = 0; i < singleStepCount; i++)
                    rcvdSingle[i] = (byte) server.getInputStream().read();
                assertArrayEquals(bufferSingle, rcvdSingle);
                // receive buffer A
                byte[] recvdBufferA =
                    receiveBuffer(server.getInputStream(), sizeA);
                assertArrayEquals(bufferA, recvdBufferA);
                // receive buffer B
                byte[] recvdBufferB =
                    receiveBuffer(server.getInputStream(), sizeB);
                assertArrayEquals(bufferB, recvdBufferB);
                // server.close();
                serverThreadEnded.set(true);
            }
            catch (IOException ex)
            {
                throw new RuntimeException(ex);
            }
        });

        final PseudoTcpSocket client = 
            new PseudoTcpSocketFactory().createSocket();
        Thread clientThread = new Thread(() ->
        {
            try
            {
                client.setDebugName("R");
                client.connect(serverAddress, 5000);
                OutputStream os = client.getOutputStream();

                // write single array
                for (int i = 0; i < singleStepCount; i++)
                    os.write(bufferSingle[i]);

                // write whole array
                os.write(bufferA);

                // write by parts
                int partCount = 7;
                boolean notExact = sizeB % partCount != 0;
                int[] partsSize =
                    notExact ? new int[partCount + 1] : new int[partCount];
                for (int i = 0; i < partsSize.length; i++)
                {
                    if (notExact && i == partCount)
                        partsSize[i] = sizeB % partCount;
                    else
                        partsSize[i] = sizeB / partCount;
                }
                int written = 0;
                for (int j : partsSize)
                {
                    os.write(bufferB, written, j);
                    written += j;
                }
                assertEquals(sizeB, written);
                os.flush();
                client.close();
                clientThreadEnded.set(true);
            }
            catch (IOException ex)
            {
                throw new RuntimeException(ex);
            }
        });

        serverThread.start();
        clientThread.start();
        try
        {
            boolean success = assert_wait_until(
                () -> client.getState() == PseudoTcpState.TCP_CLOSED,
                transferTimeout);
            if (success)
            {
                clientThread.join(10_000);
                if (!clientThreadEnded.get())
                {
                    fail("client thread did not end");
                }
                serverThread.join(10_000);
                if (!serverThreadEnded.get())
                {
                    fail("server thread did not end");
                }
                server.close();
            }
            else
            {
                fail("Transfer timeout");
            }
        }
        catch (InterruptedException ex)
        {
            throw new RuntimeException(ex);
        }
    }

    private static byte[] receiveBuffer(InputStream input, int size)
        throws IOException
    {
        int rcvd = 0;
        byte[] buffer = new byte[size];
        rcvd += input.read(buffer);
        while (rcvd != size)
        {
            rcvd += input.read(buffer, rcvd, size - rcvd);
            if (logger.isLoggable(Level.FINER))
            {
                logger.log(Level.FINER, "Received: " + rcvd);
            }
        }
        
        return buffer;
    }

    /**
     * Test the timeout on accept method
     */
    @Test
    public void testAccept()
    {
        assertThrows(IOException.class, ()->
        {
            PseudoTcpSocketImpl server = new PseudoTcpSocketImpl(0);
            server.accept(10);
        });
    }

    /**
     * Interface used to pass timeout test function
     */
    private interface TimeoutOperationTest
    {
        void testTimeout(PseudoTcpSocketImpl socket) throws IOException;
    }

    private void doTestTimeout(final TimeoutOperationTest testOperation)
        throws Exception
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        final PseudoTcpSocketImpl server;
        final PseudoTcpSocketImpl client;
        DatagramSocket serverSocket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        server = new PseudoTcpSocketImpl(0, serverSocket);
        client = new PseudoTcpSocketImpl(0);
        //Servers thread waiting for connection
        new Thread(() ->
        {
            try
            {
                server.accept(2000);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
            try
            {
                testOperation.testTimeout(server);
                fail("No expected timeout occurred on operation");
            }
            catch (IOException e)
            {
                //success
                try
                {
                    server.close();
                }
                catch (IOException exc)
                {
                    throw new RuntimeException(exc);
                }
            }
        }).start();
        //Clients thread connects and closes socket
        new Thread(() ->
        {
            try
            {
                client.connect(new InetSocketAddress(
                    InetAddress.getLoopbackAddress(),
                        serverSocket.getLocalPort()),
                    2000);
                Thread.sleep(500);
                client.close();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }).start();
        //Waits for server to close socket
        boolean done = assert_wait_until(()
            -> server.getState() == PseudoTcpState.TCP_CLOSED, 3000);
        if(!done)
        {
            fail("Test timed out");
        }
    }

    /**
     * Tests timeout on read method
     */
    @Test
    public void testReadTimeout() throws Exception
    {
        doTestTimeout(socket ->
        {
            socket.setPTCPOption(Option.OPT_READ_TIMEOUT, 300);
            socket.getInputStream().read(new byte[500]);                
        });
    }

    /**
     * Tests timeout on write method
     */
    @Test
    public void testWriteTimeout() throws Exception
    {
        doTestTimeout(socket ->
        {
            //buffer that will exceed stack's buffer size
            byte[] bigBuffer = new byte[PseudoTCPBase.DEFAULT_SND_BUF_SIZE*2];
            socket.setPTCPOption(Option.OPT_WRITE_TIMEOUT, 300);
            socket.getOutputStream().write(bigBuffer);
        });
    }

    /**
     * Tests timeout on flush method
     */
    @Test
    public void testFlushTimeout() throws Exception
    {
        doTestTimeout(socket ->
        {
            //buffer that will exceed stack's buffer size
            byte[] buffer = new byte[PseudoTCPBase.DEFAULT_SND_BUF_SIZE];
            socket.setPTCPOption(Option.OPT_WRITE_TIMEOUT, 300);
            try
            {
                socket.getOutputStream().write(buffer);
            }
            catch(IOException e)
            {
                throw new RuntimeException("Unexpected exception: "+e);
            }
            socket.getOutputStream().flush();
        });
    }
}
