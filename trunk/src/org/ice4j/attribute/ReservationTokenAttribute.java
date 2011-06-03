/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import java.util.*;

import org.ice4j.*;

/**
 * The RESERVATION-TOKEN attribute contains a token that identifie a reservation port
 * on a TURN server. The value is on 64 bits (8 bytes).
 *
 * @author Sebastien Vincent
 */
public class ReservationTokenAttribute
    extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "RESERVATION-TOKEN";

    /**
     * ReservationToken value.
     */
    private byte reservationToken[] = null;

    /**
     * Constructor.
     */
    protected ReservationTokenAttribute ()
    {
        super(RESERVATION_TOKEN);
    }

    /**
     * Copies the value of the reservationToken attribute from the specified
     * attributeValue.
     * @param attributeValue a binary array containing this attribute's
     *   field values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *   offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     * @throws StunException if attributeValue contains invalid reservationToken.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
        throws StunException
    {
        if(length != 8)
        {
          throw new StunException("Length mismatch!");
        }

        reservationToken = new byte[8];
        System.arraycopy(attributeValue, offset, reservationToken, 0, 8);
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + 8];

        //Type
        binValue[0] = (byte)(type >> 8);
        binValue[1] = (byte)(type & 0x00FF);

        //Length
        binValue[2] = (byte)(8 >> 8);
        binValue[3] = (byte)(8 & 0x00FF);

        //reservationToken
        System.arraycopy(reservationToken, 0, binValue, 4, 8);

        return binValue;
      }

    /**
     * Returns the human readable name of this attribute.
     *
     * @return this attribute's name.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Returns a (cloned) byte array containing the reservationToken value of
     * the reservationToken attribute.
     * @return the binary array containing the reservationToken.
     */
    public byte[] getReservationToken()
    {
        if (reservationToken == null)
            return null;

        byte[] copy = new byte[reservationToken.length];
        System.arraycopy(reservationToken, 0, copy, 0, reservationToken.length);
        return reservationToken;
      }

    /**
     * Copies the specified binary array into the the reservationToken value of
     * the reservationToken attribute.
     * @param reservationToken the binary array containing the reservationToken.
     */
    public void setReservationToken(byte[] reservationToken)
    {
        if (reservationToken == null)
        {
            this.reservationToken = null;
            return;
        }

        this.reservationToken = new byte[reservationToken.length];
        System.arraycopy(reservationToken, 0, this.reservationToken, 0,
                reservationToken.length);
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return (char)reservationToken.length;
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when
     * they have the same type length and value.
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof ReservationTokenAttribute)
              || obj == null)
            return false;

        if (obj == this)
            return true;

        ReservationTokenAttribute att = (ReservationTokenAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
            || att.getDataLength() != getDataLength()
            || !Arrays.equals( att.reservationToken, reservationToken))
            return false;

        return true;
    }
}
