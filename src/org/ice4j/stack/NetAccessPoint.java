/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.io.*;
import java.net.*;
import java.util.logging.*;

import org.ice4j.*;

/**
 * The Network Access Point is the most outward part of the stack. It is
 * constructed around a datagram socket and takes care about forwarding incoming
 * messages to the MessageProcessor as well as sending datagrams to the STUN server
 * specified by the original NetAccessPointDescriptor.
 *
 * @author Emil Ivov
 */

class NetAccessPoint
    implements Runnable
{
    /**
     * Our class logger.
     */
    private static final Logger logger =
        Logger.getLogger(NetAccessPoint.class.getName());

    /**
     * Creates a new access point.
     */
    NetAccessPoint()
    {
    }

    /**
     * The message queue is where incoming messages are added.
     */
    private MessageQueue messageQueue = null;

    /**
     * The socket object that used by this access point to access the network.
     */
    protected DatagramSocket sock;

    /**
     * A flag that is set to false to exit the message processor.
     */
    private boolean isRunning;

    /**
     * The instance to be notified if errors occur in the network listening
     * thread.
     */
    private ErrorHandler errorHandler = null;

    /**
     * Used for locking socket operations
     */
    private Object socketLock = new Object();

    /**
     * Creates a network access point.
     * @param socket the socket that this access point is supposed to use for
     * communication.
     * @param messageQueue the FIFO list where incoming messages should be queued
     * @param errorHandler the instance to notify when errors occur.
     */
    protected NetAccessPoint(DatagramSocket socket,
                             MessageQueue   messageQueue,
                             ErrorHandler   errorHandler)
    {
        this.sock = socket;
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
        synchronized(socketLock)
        {
            this.isRunning = true;
            Thread thread = new Thread(this);
            thread.start();
        }
    }

    /**
     * Returns the <tt>DatagramSocket</tt> that contains the port and address
     * associated with this access point.
     *
     * @return the <tt>DatagramSocket</tt> associated with this AP.
     */
    protected DatagramSocket getSocket()
    {
        return sock;
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

                //get lost if we are no longer running.
                if(!isRunning)
                    return;

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
                {
                    //The exception was most probably caused by calling
                    //this.stop() ....
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
     * Makes the access point stop listening on its socket.
     *
     */
    synchronized void stop()
    {
        this.isRunning = false;
    }

    /**
     * Sends message through this access point's socket.
     *
     * @param message the bytes to send.
     * @param address message destination.
     *
     * @throws IOException if an exception occurs while sending the message.
     */
    void sendMessage(byte[] message, TransportAddress address)
        throws IOException
    {
        DatagramPacket datagramPacket = new DatagramPacket(
                        message, 0, message.length, address.getSocketAddress());

        synchronized(socketLock)
        {
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
      * Sets a socket for the access point to use. This socket will not be
      * closed when the AP is <tt>stop()</tt>ed (Bug Report - Dave Stuart).
      *
      * @param socket the socket that the AP should use.
      */
     void useExternalSocket(DatagramSocket socket)
     {
         this.sock = socket;
         this.isUsingExternalSocket = true;
     }
}
