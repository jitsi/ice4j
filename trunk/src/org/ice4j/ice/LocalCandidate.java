/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * <tt>LocalCandidate</tt>s are obtained by an agent for every stream component
 * and are then included in outgoing offers or answers.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public abstract class LocalCandidate
    extends Candidate
{
    /**
     * The <tt>Logger</tt> used by the <tt>LocalCandidate</tt> class and its
     * instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(HostCandidate.class.getName());

    /**
     * Creates a <tt>LocalCandidate</tt> instance for the specified transport
     * address and properties.
     *
     * @param transportAddress  the transport address that this candidate is
     * encapsulating.
     * @param parentComponent the <tt>Component</tt> that this candidate
     * belongs to.
     * @param type the <tt>CandidateType</tt> for this <tt>Candidate</tt>.
     */
    public LocalCandidate(TransportAddress transportAddress,
                          Component        parentComponent,
                          CandidateType    type)
    {
        super(transportAddress, parentComponent, type);
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
     */
    protected DatagramSocket getHostSocket()
    {
        LocalCandidate base = getBase();

        return
            ((base == this) || (base == null))
                ? getSocket()
                : base.getHostSocket();
    }

    /**
     * Gets the <tt>DatagramSocket</tt> associated with this <tt>Candidate</tt>.
     *
     * @return the <tt>DatagramSocket</tt> associated with this
     * <tt>Candidate</tt>
     */
    public abstract DatagramSocket getSocket();

    /**
     * Creates if necessary and returns a <tt>DatagramSocket</tt> that would
     * capture all STUN packets arriving on this candidate's socket. If the
     * <tt>serverAddress</tt> parameter is not <tt>null</tt> this socket would
     * only intercept packets originating at this address.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or <tt>null</tt> if we'd like to intercept all STUN packets.
     *
     * @return the <tt>DatagramSocket</tt> that this candidate uses when sending
     * and receiving STUN packets, while harvesting STUN candidates or
     * performing connectivity checks.
     */
    public DatagramSocket getStunSocket(TransportAddress serverAddress)
    {
        DatagramSocket hostSocket = getHostSocket();
        DatagramSocket stunSocket = null;
        Throwable exception = null;

        if (hostSocket instanceof MultiplexingDatagramSocket)
        {
            DatagramPacketFilter stunDatagramPacketFilter
                = createStunDatagramPacketFilter(serverAddress);

            try
            {
                stunSocket
                    = ((MultiplexingDatagramSocket) hostSocket)
                        .getSocket(stunDatagramPacketFilter);
            }
            catch (SocketException sex) //don't u just luv da name? ;)
            {
                logger.log(Level.SEVERE,
                           "Failed to acquire DatagramSocket"
                               + " specific to STUN communication.",
                           sex);
                exception = sex;
            }
        }
        if (stunSocket == null)
            throw new IllegalArgumentException("hostCand", exception);
        else
            return stunSocket;
    }

    /**
     * Creates a new <tt>StunDatagramPacketFilter</tt> which is to capture STUN
     * messages and make them available to the <tt>DatagramSocket</tt> returned
     * by {@link #getStunSocket(TransportAddress)}.
     *
     * @param serverAddress the address of the source we'd like to receive
     * packets from or <tt>null</tt> if we'd like to intercept all STUN packets
     * @return the <tt>StunDatagramPacketFilter</tt> which is to capture STUN
     * messages and make them available to the <tt>DatagramSocket</tt> returned
     * by {@link #getStunSocket(TransportAddress)}
     */
    protected StunDatagramPacketFilter createStunDatagramPacketFilter(
            TransportAddress serverAddress)
    {
        return new StunDatagramPacketFilter(serverAddress);
    }

    /**
     * Frees resources allocated by this candidate such as its
     * <tt>DatagramSocket</tt> for example.
     */
    protected void free()
    {
        //remove our socket from the stack.
        StunStack.getInstance().removeSocket(getTransportAddress());

        // Close the socket associated with this Candidate.
        DatagramSocket socket = getSocket();

        /*
         * Allow this LocalCandiate implementation to not create a socket if it
         * still hasn't created one.
         */
        if (socket != null)
            socket.close();
    }

    /**
     * Determines whether this <tt>Candidate</tt> is the default one for its
     * parent component.
     *
     * @return <tt>true</tt> if this <tt>Candidate</tt> is the default for its
     * parent component and <tt>false</tt> if it isn't or if it has no parent
     * Component yet.
     */
    @Override
    public boolean isDefault()
    {
        Component parentCmp = getParentComponent();

        return (parentCmp != null) && equals(parentCmp.getDefaultCandidate());
    }
}
