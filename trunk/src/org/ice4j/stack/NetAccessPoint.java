/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.util.*;
import java.io.IOException;
import java.net.*;
import java.util.logging.*;

import org.ice4j.*;

/**
 * The Network Access Point is the most outward part of the stack. It is
 * constructed around a datagram socket and takes care about forwarding incoming
 * messages to the MessageProcessor as well as sending datagrams to the STUN server
 * specified by the original NetAccessPointDescriptor.
 *
 * <p>Organisation: Louis Pasteur University, Strasbourg, France</p>
 *                   <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
 */

class NetAccessPoint
    implements Runnable
{
    private static final Logger logger =
        Logger.getLogger(NetAccessPoint.class.getName());
    NetAccessPoint()
    {
    }

    /**
     * Max datagram size.
     */
    private static final int MAX_DATAGRAM_SIZE = 8 * 1024;


    /**
     * The message queue is where incoming messages are added.
     */
    private MessageQueue messageQueue = null;

    /**
     * The socket object that used by this access point to access the network.
     */
    protected DatagramSocket sock;

    /**
     * Indicates whether the access point is using a socket that was created
     * by someone else. The variable is set to true when the AP's socket is
     * set using the <code>useExternalSocket()</code> method and is consulted
     * inside the stop method. When its value is true, the AP's socket is not
     * closed when <code>stop()</code>ing the AP.
     *
     * This variable is part of bug fix reported by Dave Stuart - SipQuest
     */
    private boolean isUsingExternalSocket = false;

    /**
     * A flag that is set to false to exit the message processor.
     */
    private boolean isRunning;

    /**
     * The descriptor used to create this access point.
     */
    private NetAccessPointDescriptor apDescriptor = null;

    /**
     * The instance to be notified if errors occur in the network listening
     * thread.
     */
    private ErrorHandler             errorHandler = null;

    /**
     * Used for locking socket operations
     */
    private Object socketLock = new Object();

    /**
     * Creates a network access point.
     * @param apDescriptor the address and port where to bind.
     * @param messageQueue the FIFO list where incoming messages should be queued
     * @param errorHandler the instance to notify when errors occur.
     */
    NetAccessPoint(NetAccessPointDescriptor apDescriptor,
                   MessageQueue             messageQueue,
                   ErrorHandler			    errorHandler)
    {
        this.apDescriptor = apDescriptor;
        this.messageQueue = messageQueue;
        this.errorHandler = errorHandler;
    }


    /**
     * Start the network listening thread.
     *
     * @throws IOException if we fail to setup the socket.
     */
    void start()
        throws IOException
    {
        synchronized(socketLock){

            //do not create the socket earlier as someone might want to set an
            // existing one was != null fixed (Ranga)
            if (sock == null)
            {
                this.sock = new DatagramSocket(getDescriptor().getAddress().
                                               getSocketAddress());
                this.isUsingExternalSocket = false;
                logger.info("Bound a socket on ap: " + toString());
            }

            sock.setReceiveBufferSize(MAX_DATAGRAM_SIZE);
            this.isRunning = true;
            Thread thread = new Thread(this);
            thread.start();
        }
    }

    /**
     * Returns the NetAccessPointDescriptor that contains the port and address
     * associated with this accesspoint.
     * @return the NetAccessPointDescriptor associated with this AP.
     */
    NetAccessPointDescriptor getDescriptor()
    {
        return apDescriptor;
    }

    /**
     * The listening thread's run method.
     */
    public void run()
    {
        while (this.isRunning)
        {
            try
            {
                int bufsize = sock.getReceiveBufferSize();
                byte message[] = new byte[bufsize];
                DatagramPacket packet = new DatagramPacket(message, bufsize);

                sock.receive(packet);
                logger.finest("received datagram");

                RawMessage rawMessage = new RawMessage( message,
                    packet.getLength(), packet.getAddress(), packet.getPort(),
                    getDescriptor());

                messageQueue.add(rawMessage);
            }
            catch (SocketException ex)
            {
                if (isRunning)
                {
                    logger.log(Level.WARNING,
                               "A net access point has gone useless:", ex);

                    stop();
                    //Something wrong has happened
                    errorHandler.handleFatalError(
                        this,
                        "A socket exception was thrown while trying to "
                        + "receive a message.",
                        ex);
                }
                else
                {
                    //The exception was most probably caused by calling this.stop()
                    // ....
                }
            }
            catch (IOException ex)
            {
                logger.log(Level.WARNING,
                           "A net access point has gone useless:", ex);

                errorHandler.handleError(ex.getMessage(), ex);
                //do not stop the thread;
            }
            catch (Throwable ex)
            {
                logger.log(Level.WARNING,
                           "A net access point has gone useless:", ex);

                stop();
                errorHandler.handleFatalError(
                    this,
                    "Unknown error occurred while listening for messages!",
                    ex);
            }
        }
    }


    /**
     * Shut down the access point. Close the socket for recieving
     * incoming messages. The method won't close the socket if it was created
     * outside the stack (Bug Report - Dave Stuart - SipQuest). It also seems
     * that sometimes sockets don't immdeiately free their port and trying
     * to bind to that port immediately after gets us an exception. We therefore
     * null the socket, wait for 200 miliseconds and call the garbage collector
     * this seems to be working fine but is not what one could call neat
     * behaviour, so if you'd like to disable it - set the
     * org.ice4j.stack.HARD_SOCK_CLOSE property to anything different from
     * true. If you'd want us to wait more or less - set
     * org.ice4j.stack.WAIT_FOR_SOCK_CLOSE to the appropriate number of
     * miliseconds.
     *
     */
    synchronized void stop()
    {
        this.isRunning = false;

        //avoid a needless null pointer exception
        if (sock != null
            && isUsingExternalSocket == false)
        {
            synchronized (socketLock)
            {
                sock.close();

                logger.info("Closed socket on ap " + toString());
                sock = null;
                String hardSocketClose =
                    System.getProperty("org.ice4j.stack.HARD_SOCK_CLOSE");

                //sometimes sockts stay open even after closing them. make sure
                //this doesn't happen here. (unless the user doesn't want us to)
                if (hardSocketClose == null
                    || hardSocketClose.equalsIgnoreCase("true"))
                {

                    int waitForSockClose = 200;
                    try
                    {
                        String waitForSockCloseStr =
                            System.getProperty(
                                "org.ice4j.stack.WAIT_FOR_SOCK_CLOSE");
                        if (waitForSockCloseStr != null &&
                            waitForSockCloseStr.length() > 0){

                            waitForSockClose =
                                Integer.parseInt(System.getProperty(
                                    waitForSockCloseStr));
                        }
                    }
                    catch (Throwable t)
                    {
                        logger.log(
                            Level.WARNING,
                            "Failed to parse wait_for_sock_close prop", t);

                        if (waitForSockClose < 0)
                        {
                            waitForSockClose = 200;
                        }
                    }

                    //wait
                    try
                    {
                        wait(waitForSockClose);
                    }
                    catch (InterruptedException t)
                    {
                        logger.warning("Interrupted waiting for sock close.");
                    }
                    System.gc();
                }
            }
        }
    }

    /**
     * Sends message through this access point's socket.
     * @param message the bytes to send.
     * @param address message destination.
     * @throws IOException if an exception occurs while sending the message.
     */
    void sendMessage(byte[] message, TransportAddress address)
        throws IOException
    {
        DatagramPacket datagramPacket = new DatagramPacket(
                                                message,
                                                0,
                                                message.length,
                                                address.getSocketAddress());
        synchronized(socketLock){
            sock.send(datagramPacket);
        }
    }

    /**
     * Returns a String representation of the object.
     * @return a String representation of the object.
     */
    public String toString()
    {
        return "org.ice4j.stack.AccessPoint@"
                +apDescriptor.getAddress()
                +" status: "
                + (isRunning? "not":"")
                +" running";
     }

     /**
      * Sets a socket for the access point to use. This socket will not be closed
      * when the AP is <code>stop()</code>ed (Bug Report - Dave Stuart - SipQuest).
      * @param socket the socket that the AP should use.
      */
     void useExternalSocket(DatagramSocket socket)
     {
         this.sock = socket;
         this.isUsingExternalSocket = true;
     }
}
