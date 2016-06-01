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

import static org.junit.Assert.*;

import java.io.*;
import java.net.*;
import java.util.logging.*;

/**
 * 
 * @author Pawel Domas
 */
public class PseudoTcpStreamTest
    extends MultiThreadSupportTest
{
    /**
     * The logger.
     */
    private static final Logger logger = Logger
        .getLogger(PseudoTcpStreamTest.class.getName());

    public PseudoTcpStreamTest()
    {
    }

    /**
     * Test one-way transfer with @link(PseudoTcpStream)
     * @throws IOException 
     */
    public void testConnectTransferClose() 
        throws IOException
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        final int server_port = 49999;
        int transferTimeout = 5000;

        // bytes that will be read as a single byte
        final int singleStepCount = 34;
        final byte[] bufferSingle =
            PseudoTcpTestBase.createDummyData(singleStepCount);
        final int sizeA = 138746;
        final byte[] bufferA = PseudoTcpTestBase.createDummyData(sizeA);
        final int sizeB = 983746;
        final byte[] bufferB = PseudoTcpTestBase.createDummyData(sizeB);
        final InetSocketAddress serverAddress = 
            new InetSocketAddress(InetAddress.getLocalHost(), server_port);
        final PseudoTcpSocket server = 
            new PseudoTcpSocketFactory().createSocket();
        Thread serverThread = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {                    
                    server.setDebugName("L");
                    server.bind(serverAddress);
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
                }
                catch (IOException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        });
        
        final PseudoTcpSocket client = 
            new PseudoTcpSocketFactory().createSocket();
        Thread clientThread = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {                   
                    client.setDebugName("R");
                    client.connect(serverAddress, 5000);
                    // write single array
                    for (int i = 0; i < singleStepCount; i++)
                        client.getOutputStream().write(bufferSingle[i]);
                    // write whole array
                    client.getOutputStream().write(bufferA);
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
                    for (int i = 0; i < partsSize.length; i++)
                    {
                        client.getOutputStream().write(bufferB, written,
                            partsSize[i]);
                        written += partsSize[i];
                    }
                    assertEquals(sizeB, written);
                    client.getOutputStream().flush();
                    client.close();
                }
                catch (IOException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        });

        serverThread.start();
        clientThread.start();
        try
        {
            boolean success = assert_wait_until(new WaitUntilDone()
            {
                @Override
                public boolean isDone()
                {
                    return client.getState() == PseudoTcpState.TCP_CLOSED;
                }
            }, transferTimeout);
            if (success)
            {
                clientThread.join();
                serverThread.join();
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
    public void testAccept()
    {
        try
        {
            PseudoTcpSocketImpl server = new PseudoTcpSocketImpl(0);
            server.accept(10);
            fail("Should throw timeout exception");
        }
        catch (IOException ex)
        {
            // success
        }
    }
    
    /**
     * Interface used to pass timeout test function
     * @author Pawel Domas
     *
     */
    private interface TimeoutOperationTest
    {
        void testTimeout(PseudoTcpSocketImpl socket) throws IOException;
    }
    
    /**
     * 
     * @param testOperation
     * @throws UnknownHostException 
     */
    private void doTestTimeout(final TimeoutOperationTest testOperation)
        throws Exception
    {
        Thread.setDefaultUncaughtExceptionHandler(this);
        final PseudoTcpSocketImpl server;
        final PseudoTcpSocketImpl client;
        final int server_port = 49998;
        final InetSocketAddress serverAddress = 
            new InetSocketAddress(InetAddress.getLocalHost(), server_port);        
        server = 
            new PseudoTcpSocketImpl(0,new DatagramSocket(serverAddress));            
        client = new PseudoTcpSocketImpl(0);        
        //Servers thread waiting for connection
        new Thread(new Runnable()
        {            
            @Override
            public void run()
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
                    fail("No expected timeout occured on operation");
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
            }
        }).start();
        //Clients thread connects and closes socket
        new Thread(new Runnable()
        {
            
            @Override
            public void run()
            {
                try
                {
                    client.connect(serverAddress, 2000);
                    Thread.sleep(500);
                    client.close();
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e);
                }                
            }
        }).start();
        //Waits for server to close socket
        boolean done = assert_wait_until(new WaitUntilDone()
        {
            
            @Override
            public boolean isDone()
            {
                return server.getState() == PseudoTcpState.TCP_CLOSED;
            }
        }, 3000);
        if(!done)
        {
            fail("Test timed out");
        }
    }
    
    /**
     * Tests timeout on read method
     * @throws UnknownHostException 
     */
    public void testReadTimeout() throws Exception
    {
        doTestTimeout(new TimeoutOperationTest()
        {
            
            @Override
            public void testTimeout(PseudoTcpSocketImpl socket) throws IOException
            {
                socket.setPTCPOption(Option.OPT_READ_TIMEOUT, 300);
                socket.getInputStream().read(new byte[500]);                
            }
        });
    }
    
    /**
     * Tests timeout on write method
     * @throws UnknownHostException 
     */
    public void testWriteTimeout() throws Exception
    {
        doTestTimeout(new TimeoutOperationTest()
        {            
            @Override
            public void testTimeout(PseudoTcpSocketImpl socket) throws IOException
            {
                //buffer that will exceed stack's buffer size
                byte[] bigBuffer = new byte[PseudoTCPBase.DEFAULT_SND_BUF_SIZE*2];
                socket.setPTCPOption(Option.OPT_WRITE_TIMEOUT, 300);
                socket.getOutputStream().write(bigBuffer);
            }
        });
    }
    
    /**
     * Tests timeout on flush method
     * @throws UnknownHostException 
     */
    public void testFlushTimeout() throws Exception
    {
        doTestTimeout(new TimeoutOperationTest()
        {            
            @Override
            public void testTimeout(PseudoTcpSocketImpl socket) throws IOException
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
            }
        });
    }
    
}
