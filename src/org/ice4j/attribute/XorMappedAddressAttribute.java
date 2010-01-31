/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import java.net.*;

import org.ice4j.*;

/**
 * The XOR-MAPPED-ADDRESS attribute is only present in Binding
 * Responses.  It provides the same information that is present in the
 * MAPPED-ADDRESS attribute.  However, the information is encoded by
 * performing an exclusive or (XOR) operation between the mapped address
 * and the transaction ID.  Unfortunately, some NAT devices have been
 * found to rewrite binary encoded IP addresses and ports that are
 * present in protocol payloads.  This behavior interferes with the
 * operation of STUN.  By providing the mapped address in an obfuscated
 * form, STUN can continue to operate through these devices.
 *
 * The format of the XOR-MAPPED-ADDRESS is:
 *
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |x x x x x x x x|    Family     |         X-Port                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                X-Address (Variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The Family represents the IP address family, and is encoded
 * identically to the Family in MAPPED-ADDRESS.
 *
 * X-Port is equal to the port in MAPPED-ADDRESS, exclusive or'ed with
 * most significant 16 bits of the transaction ID.  If the IP address
 * family is IPv4, X-Address is equal to the IP address in MAPPED-
 * ADDRESS, exclusive or'ed with the most significant 32 bits of the
 * transaction ID.  If the IP address family is IPv6, the X-Address is
 * equal to the IP address in MAPPED-ADDRESS, exclusive or'ed with the
 * entire 128 bit transaction ID.
 *
 * <p>Copyright: Copyright (c) 2005.</p>
 * <p>Organization: Network Research Team, Louis Pasteur University</p>
 * @author Emil Ivov
 * @version 1.0
 */
public class XorMappedAddressAttribute
    extends AddressAttribute
{
    public static final String NAME = "XOR-MAPPED-ADDRESS";

    XorMappedAddressAttribute()
    {
        super(XOR_MAPPED_ADDRESS);
    }

    /**
     * Constructor.
     * @param type other type than XOR-MAPPED-ADDRESS
     */
    XorMappedAddressAttribute(char type)
    {
      super(type);
    }

    /**
     * Returns the result of applying XOR on the specified attribute's address.
     * The method may be used for both encoding and decoding XorMappedAddresses.
     *
     * @param address the address on which XOR should be applied
     * @param transactionID the transaction id to use for the XOR
     *
     * @return the XOR-ed address.
     */
    public static TransportAddress applyXor(TransportAddress address,
                                       byte[] transactionID)
    {
        byte[] addressBytes = address.getAddressBytes();
        char port = (char)address.getPort();

        char portModifier = (char)( (transactionID[0] << 8 & 0x0000FF00)
                                  | (transactionID[1] & 0x000000FF));

        port ^= portModifier;

        for(int i = 0; i < addressBytes.length; i++)
            addressBytes[i] ^= transactionID[i];

        TransportAddress xoredAdd;
        try
        {
            xoredAdd = new TransportAddress(addressBytes, port, Transport.UDP);
        }
        catch (UnknownHostException e)
        {
            //shouldn't happen so just throw an illegal arg
            throw new IllegalArgumentException(e);
        }

        return xoredAdd;
    }

    /**
     * Returns the result of applying XOR on this attribute's address, using the
     * specified transaction identifier. The method may be used for both
     * encoding and decoding XorMappedAddresses.
     * @param transactionID the transaction id to use for the XOR
     * @return the XOR-ed address.
     */
    public TransportAddress applyXor(byte[] transactionID)
    {
        return applyXor(getAddress(), transactionID);
    }
}
