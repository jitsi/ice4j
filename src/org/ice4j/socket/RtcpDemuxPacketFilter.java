/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.socket;

import java.net.*;

/**
 * Implements a <tt>DatagramPacketFilter</tt> which only accepts
 * <tt>DatagramPacket</tt>s which represent RTCP messages according to the rules
 * described in RFC5761.
 * <p>
 * This filter would only be able to demultiplex between RTP and RTCP packets.
 * Other protocols such as STUN/TURN, DTLS or ZRTP are not taken into account
 * and may produce false positives if left to this filter. They should hence
 * be handled by lower layers/demuxers.
 *
 * @author Emil Ivov
 */
public class RtcpDemuxPacketFilter
    implements DatagramPacketFilter
{
    /**
     * Determines whether a specific <tt>DatagramPacket</tt> is an RTCP.
     * <tt>DatagramPacket</tt> in a selection based on this filter.
     *
     * @param p the <tt>DatagramPacket</tt> whose protocol we'd like to
     * determine.
     * @return <tt>true</tt> if <tt>p</tt> is an RTCP and this filter accepts it
     * and <tt>false</tt> otherwise.
     */
    public boolean accept(DatagramPacket p)
    {
        return false;
    }
}
