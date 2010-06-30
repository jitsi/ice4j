/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.io.*;
import java.net.*;

/**
 * Represents an application-purposed (as opposed to a ICE-specific)
 * <tt>DatagramSocket</tt> for a <tt>RelayedCandidate</tt> harvested by a
 * <tt>TurnCandidateHarvest</tt> (and its associated
 * <tt>TurnCandidateHarvester</tt>, of course).
 * <tt>RelayedCandidateDatagramSocket</tt> is associated with a successful
 * Allocation on a TURN server and implements sends and receives through it
 * using TURN messages to and from that TURN server.
 *
 * @author Lubomir Marinov
 */
public class RelayedCandidateDatagramSocket
    extends SafeCloseDatagramSocket
{
    /**
     * Initializes a new <tt>RelayedCandidateDatagramSocket</tt> instance.
     *
     * @throws SocketException if anything goes wrong while initializing the new
     * <tt>RelayedCandidateDatagramSocket</tt> instance
     */
    public RelayedCandidateDatagramSocket()
        throws SocketException
    {
        super(null /* bindaddr */);
    }

    /**
     * Closes this datagram socket.
     *
     * @see DatagramSocket#close()
     */
    @Override
    public void close()
    {
        // TODO Auto-generated method stub
    }

    /**
     * Receives a datagram packet from this socket. When this method returns,
     * the <tt>DatagramPacket</tt>'s buffer is filled with the data received.
     * The datagram packet also contains the sender's IP address, and the port
     * number on the sender's machine.
     *
     * @param p the <tt>DatagramPacket</tt> into which to place the incoming
     * data
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#receive(DatagramPacket)
     */
    @Override
    public void receive(DatagramPacket p)
        throws IOException
    {
        // TODO Auto-generated method stub
    }

    /**
     * Sends a datagram packet from this socket. The <tt>DatagramPacket</tt>
     * includes information indicating the data to be sent, its length, the IP
     * address of the remote host, and the port number on the remote host.
     *
     * @param p the <tt>DatagramPacket</tt> to be sent
     * @throws IOException if an I/O error occurs
     * @see DatagramSocket#send(DatagramPacket)
     */
    @Override
    public void send(DatagramPacket p)
        throws IOException
    {
        // TODO Auto-generated method stub
    }
}
