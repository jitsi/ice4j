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
public class PseudoTcpStreamTest extends MultiThreadSupportTest
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(PseudoTcpStreamTest.class.getName());

    public PseudoTcpStreamTest()
    {
    }

    /**
     * Test one-way transfer with @link(PseudoTcpStream)
     *
     * @throws SocketException
     */
    public void testConnectTransferClose() throws SocketException
    {
        String ip = "";
        final int server_port = 49999;
        long conv_id = 0;
        final int size = 1000000;
        int transferTimeout = 5000;
        final PseudoTcpSocketImpl server = new PseudoTcpSocketImpl(conv_id);
        final PseudoTcpSocketImpl client = new PseudoTcpSocketImpl(conv_id);
        
        Thread serverThread = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {                    
                	server.bind(InetAddress.getLocalHost(), server_port);
                    server.accept(null);
                    int rcvd = 0;
                    while (rcvd != size)
                    {
                        rcvd += server.getInputStream().read(new byte[size]);
                        if (logger.isLoggable(Level.FINER))
                        {
                            logger.log(Level.FINER, "Received: " + rcvd);
                        }
                    }
                    if (logger.isLoggable(Level.FINER))
                    {
                        logger.log(Level.FINER, "Total received: " + rcvd);
                    }
                    //server.Close();

                }
                catch (IOException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        });
        Thread clientThread = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    client.connect(InetAddress.getLocalHost(), server_port);
                    assertEquals(PseudoTcpState.TCP_ESTABLISHED, client.getState());
                    client.getOutputStream().write(new byte[size]);
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
            boolean success = assert_wait_until(new IWaitUntilDone()
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

    /**
     * Test the timeout on accept method
     */
    public void testAccept()
    {
        try
        {
            PseudoTcpSocketImpl server = new PseudoTcpSocketImpl(0);
            server.Accept(10);
            fail("Should throw timeout exception");
        }
        catch (IOException ex)
        {
            //success            
        }
    }
}
