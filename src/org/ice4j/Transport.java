/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j;

/**
 * The <tt>Transport</tt> enumeration contains all currently known transports
 * that ICE may be interacting with (but not necessarily support).
 *
 * @author Emil Ivov
 */
public enum Transport
{
    /**
     * Represents a TCP transport.
     */
    TCP("tcp"),

    /**
     * Represents a UDP transport.
     */
    UDP("udp"),

    /**
     * Represents a TLS transport.
     */
    TLS("tls"),

    /**
     * Represents a datagram TLS (DTLS) transport.
     */
    DTLS("dtls"),

    /**
     * Represents an SCTP transport.
     */
    SCTP("sctp");

    /**
     * The name of this <tt>Transport</tt>.
     */
    private final String transportName;

    /**
     * Creates a <tt>Transport</tt> instance with the specified name.
     *
     * @param transportName the name of the <tt>Transport</tt> instance we'd
     * like to create.
     */
    private Transport(String transportName)
    {
        this.transportName = transportName;
    }

    /**
     * Returns the name of this <tt>Transport</tt> (e.g. "udp" or
     * "tcp").
     *
     * @return the name of this <tt>Transport</tt> (e.g. "udp" or
     * "tcp").
     */
    @Override
    public String toString()
    {
        return transportName;
    }
}
