/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 * 
 * Distributable under LGPL license. 
 * See terms of license at gnu.org.
 */
package org.ice4j.pseudotcp;

import java.io.*;
import java.net.*;
import java.util.logging.*;
import static org.junit.Assert.*;
import org.junit.*;

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
     * 
     * @throws SocketException
     * @throws UnknownHostException 
     */
    public void testConnectTransferClose() 
        throws SocketException, 
               UnknownHostException
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
        final int sizeB = 4803746;
        final byte[] bufferB = PseudoTcpTestBase.createDummyData(sizeB);
        final InetSocketAddress serverAddress = 
            new InetSocketAddress(InetAddress.getLocalHost(), server_port);
        Thread serverThread = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    final PseudoTcpSocket server = 
                        new PseudoTcpSocketFactory().
                        createSocket();
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
}
