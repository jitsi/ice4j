/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.lang.reflect.*;
import java.net.*;

import org.ice4j.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.socket.*;

/**
 * Represents a <tt>Candidate</tt> obtained by sending a TURN Allocate request
 * from a <tt>HostCandidate</tt> to a TURN server.  The relayed candidate is
 * resident on the TURN server, and the TURN server relays packets back towards
 * the agent.
 *
 * @author Lubomir Marinov
 */
public class RelayedCandidate
    extends LocalCandidate
{
    /**
     * The <tt>RelayedCandidateDatagramSocket</tt> which represents the
     * application-purposed <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>.
     */
    private RelayedCandidateDatagramSocket socket;

    /**
     * The <tt>TurnCandidateHarvest</tt> which has harvested this
     * <tt>RelayedCandidate</tt>.
     */
    private final TurnCandidateHarvest turnCandidateHarvest;

    /**
     * Initializes a new <tt>RelayedCandidate</tt> which is to represent a
     * specific <tt>TransportAddress</tt> harvested through a specific
     * <tt>HostCandidate</tt> and a TURN server with a specific
     * <tt>TransportAddress</tt>.
     * 
     * @param transportAddress the <tt>TransportAddress</tt> to be represented
     * by the new instance
     * @param turnCandidateHarvest the <tt>TurnCandidateHarvest</tt> which has
     * harvested the new instance
     * @param mappedAddress the mapped <tt>TransportAddress</tt> reported by the
     * TURN server with the delivery of the replayed <tt>transportAddress</tt>
     * to be represented by the new instance
     */
    public RelayedCandidate(
            TransportAddress transportAddress,
            TurnCandidateHarvest turnCandidateHarvest,
            TransportAddress mappedAddress)
    {
        super(
            transportAddress,
            turnCandidateHarvest.hostCandidate.getParentComponent(),
            CandidateType.RELAYED_CANDIDATE);

        this.turnCandidateHarvest = turnCandidateHarvest;

        // RFC 5245: The base of a relayed candidate is that candidate itself.
        setBase(this);
        setTurnServerAddress(turnCandidateHarvest.harvester.stunServer);
        setMappedAddress(mappedAddress);
    }

    /**
     * Gets the actual/host <tt>DatagramSocket</tt> which implements the
     * <tt>DatagramSocket</tt>s exposed by this <tt>LocalCandidate</tt>. The
     * default implementation is supposed to be good enough for the general case
     * and does not try to be universal - it returns the <tt>hostSocket</tt> of
     * the <tt>base</tt> of this <tt>LocalCandidate</tt> if the <tt>base</tt> is
     * different than <tt>this</tt> or the <tt>socket</tt> of this
     * <tt>LocalCandidate</tt> if it equals its <tt>base</tt>. The row reasoning
     * for the implementation is that if any <tt>Candidate</tt> knows about the
     * actual/host <tt>DatagramSocket</tt>, this <tt>LocalCandidate</tt> would
     * be based on it rather be related to it in any other way.
     *
     * @return the actual/host <tt>DatagramSocket</tt> which implements the
     * <tt>DatagramSocket</tt>s exposed by this <tt>LocalCandidate</tt>
     * @see LocalCandidate#getHostSocket()
     */
    @Override
    protected DatagramSocket getHostSocket()
    {
        return turnCandidateHarvest.hostCandidate.getSocket();
    }

    /**
     * Gets the <tt>DatagramSocket</tt> associated with this <tt>Candidate</tt>.
     *
     * @return the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>
     * @see LocalCandidate#getSocket()
     */
    public synchronized DatagramSocket getSocket()
    {
        if (socket == null)
        {
            try
            {
                socket = new RelayedCandidateDatagramSocket();
            }
            catch (SocketException sex)
            {
                throw new UndeclaredThrowableException(sex);
            }
        }
        return socket;
    }
}
