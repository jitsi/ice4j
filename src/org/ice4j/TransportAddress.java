/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import java.net.*;

import org.ice4j.ice.*;

/**
 * The Address class is used to define destinations to outgoing Stun Packets.
 *
 * @author Emil Ivov
 */

public class TransportAddress
{
    /**
     * The socket address instance that we use for saving address and port.
     */
    private InetSocketAddress socketAddress = null;

    /**
     * The variable that we are using to store the transport that this address
     * is pertaining to.
     */
    private final Transport transport;

    /**
     * Creates an address instance address from an IP address and a port number.
     * <p>
     * A valid port value is between 0 and 65535.
     * A port number of <tt>zero</tt> will let the system pick up an
     * ephemeral port in a <tt>bind</tt> operation.
     * <P>
     * A <tt>null</tt> address will assign the <i>wildcard</i> address.
     * <p>
     * @param   hostname    The IP address
     * @param   port        The port number
     * @param   transport   The transport that this address would be bound to.
     * @throws IllegalArgumentException if the port parameter is outside the
     * specified range of valid port values.
     */
    public TransportAddress(String hostname, int port, Transport transport)
    {
        socketAddress = new InetSocketAddress(hostname, port);
        this.transport = transport;
    }

    /**
     * Creates an address instance address from a byte array containing an IP
     * address and a port number.
     * <p>
     * A valid port value is between 0 and 65535.
     * A port number of <tt>zero</tt> will let the system pick up an
     * ephemeral port in a <tt>bind</tt> operation.
     * <P>
     * A <tt>null</tt> address will assign the <i>wildcard</i> address.
     * <p>
     * @param    ipAddress The IP address
     * @param    port      The port number
     * @param    transport The <tt>Transport</tt> to use with this address.
     *
     * @throws IllegalArgumentException if the port parameter is outside the
     * specified range of valid port values or if ipAddress is not a valid IP
     * address.
     */
    public TransportAddress(byte[] ipAddress, int port, Transport transport)
    {

        try
        {
            socketAddress = new InetSocketAddress(InetAddress.getByAddress(
                ipAddress), port);
        }
        catch (UnknownHostException ex)
        {
            //Unknown Host - Let's skip resolution
            socketAddress = new InetSocketAddress((ipAddress[0]&0xFF) + "."
                                                   +(ipAddress[1]&0xFF) + "."
                                                   +(ipAddress[2]&0xFF) + "."
                                                   +(ipAddress[3]&0xFF) + ".",
                                                   port);
        }

        this.transport = transport;
    }


    /**
     * Creates an address instance from a hostname and a port number.
     * <p>
     * An attempt will be made to resolve the hostname into an InetAddress.
     * If that attempt fails, the address will be flagged as <I>unresolved</I>.
     * <p>
     * A valid port value is between 0 and 65535. A port number of zero will
     * let the system pick up an ephemeral port in a <tt>bind</tt> operation.
     * <p>
     * @param    address   the address itself
     * @param    port      the port number
     * @param    transport the transport to use with this address.
     *
     * @throws IllegalArgumentException if the port parameter is outside the
     * range of valid port values, or if the hostname parmeter is <TT>null</TT>.
     */
    public TransportAddress(InetAddress address, int port, Transport transport)
    {
        socketAddress = new InetSocketAddress(address, port);
        this.transport = transport;
    }

    /**
     * Returns the raw IP address of this Address object. The result is in
     * network byte order: the highest order byte of the address is in
     * getAddress()[0].
     * @return the raw IP address of this object.
     */
    public byte[] getAddressBytes()
    {
        return (socketAddress == null
                   ?null
                   :socketAddress.getAddress().getAddress());
    }

    /**
     * Returns the port number or 0 if the address has not been initialized.
     * @return the port number.
     */
    public int getPort()
    {
        return (socketAddress == null
                   ? 0
                   : socketAddress.getPort());
    }

    /**
     * Returns the encapsulated InetSocketAddress instance.
     * @return the encapsulated InetSocketAddress instance.
     */
    public InetSocketAddress getSocketAddress()
    {
        return socketAddress;
    }

    /**
     * Constructs a string representation of this InetSocketAddress. This String
     * is constructed by calling toString() on the InetAddress and concatenating
     * the port number (with a colon). If the address is unresolved then the
     * part before the colon will only contain the hostname.
     *
     * @return a string representation of this object.
     */
    public String toString()
    {
        return socketAddress.toString() + " transport="+getTransport();
    }

    /**
     * Compares this object against the specified object. The result is true if
     * and only if the argument is not null and it represents the same address
     * as this object.
     * <p/>
     * Two instances of InetSocketAddress represent the same address if both the
     * InetAddresses (or hostnames if it is unresolved) and port numbers are
     * equal.
     * <p/>
     * If both addresses are unresolved, then the hostname & the port number are
     * compared.
     * @param obj the object to compare against.
     * @return true if the objects are the same; false otherwise.
     */
    public boolean equals(Object obj)
    {
        if(!(obj instanceof TransportAddress))
            return false;

        TransportAddress target = (TransportAddress)obj;
        if(   target.socketAddress == null
           && socketAddress ==null)
            return true;

        return socketAddress.equals(target.getSocketAddress());
    }

    /**
     * Returns the host address.
     *
     * @return a String part of the address
     */
    public String getHostAddress()
    {
        InetAddress addr = socketAddress.getAddress();

        String addressStr = socketAddress.getAddress().getHostAddress();

        if(addr instanceof Inet6Address)
            addressStr = NetworkUtils.stripScopeID(addressStr);

        return addressStr;
    }

    /**
     * Returns the <tt>InetAddress</tt> encapsulated by this
     * <tt>TransportAddress</tt>.
     *
     * @return the <tt>InetAddress</tt> encapsulated by this
     * <tt>TransportAddress</tt>.
     */
    public InetAddress getInetAddress()
    {
        return socketAddress.getAddress();
    }

    /**
     * The transport that this transport address is suggesting.
     *
     * @return one of the transport strings (UDP/TCP/...) defined as contants
     * in this class.
     */
    public Transport getTransport()
    {
        return transport;
    }
}
