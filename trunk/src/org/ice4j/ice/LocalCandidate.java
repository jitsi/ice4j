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
        DatagramSocket hostSocket = getSocket();
        DatagramSocket stunSocket = null;

        if (hostSocket instanceof MultiplexingDatagramSocket)
        {
            DatagramPacketFilter stunDatagramPacketFilter
                = createStunDatagramPacketFilter(serverAddress);
            Throwable exception = null;

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
            if (stunSocket == null)
            {
                throw
                    new IllegalStateException(
                            "Failed to acquire DatagramSocket"
                                + " specific to STUN communication",
                            exception);
            }
        }
        else
        {
            throw
                new IllegalStateException(
                        "The socket of "
                            + getClass().getSimpleName()
                            + " must be a MultiplexingDatagramSocket instance");
        }
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
     * <tt>DatagramSocket</tt>, for example. The <tt>socket</tt> of this
     * <tt>LocalCandidate</tt> is closed only if it is not the <tt>socket</tt>
     * of the <tt>base</tt> of this <tt>LocalCandidate</tt>.
     */
    protected void free()
    {
        // Close the socket associated with this LocalCandidate.
        DatagramSocket socket = getSocket();

        if (socket != null)
        {
            LocalCandidate base = getBase();

            if ((base == null)
                    || (base == this)
                    || (base.getSocket() != socket))
            {
                //remove our socket from the stack.
                StunStack.getInstance().removeSocket(getTransportAddress());

                /*
                 * Allow this LocalCandiate implementation to not create a
                 * socket if it still hasn't created one.
                 */
                socket.close();
            }
        }
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
