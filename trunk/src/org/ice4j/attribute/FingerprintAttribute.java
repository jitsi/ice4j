/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * The FINGERPRINT attribute is used to distinguish STUN packets
 * from packets of other protocols.
 *
 * @author Sebastien Vincent
 * @version 0.1
 */
public class FingerprintAttribute extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "FINGERPRINT";

    /**
     * CRC value.
     */
    private int crc = 0;

    /**
     * Constructor.
     */
    FingerprintAttribute()
    {
        super(FINGERPRINT);
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return 4;
    }

    /**
     * Returns the human readable name of this attribute.
     * @return this attribute's name.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when they
     * have the same type length and value.
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof FingerprintAttribute) || obj == null)
            return false;

        if (obj == this)
            return true;

        FingerprintAttribute att = (FingerprintAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
                || att.getDataLength() != getDataLength()
                || att.crc ==  crc)
            return false;

        return true;
    }

    /**
     * Returns a (cloned) byte array containg the data value of the CRC
     * attribute.
     * @return the binary array containing the CRC.
     */
    public int getCrc()
    {
        return crc;
    }


    /**
     * Copies the specified binary array into the the CRC value of the CRC 
     * attribute.
     * @param crc the binary array containing the CRC.
     */
    public void setCrc(int crc)
    {
        this.crc = crc;
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength()];

        //Type
        binValue[0] = (byte)(type>>8);
        binValue[1] = (byte)(type&0x00FF);
        //Length
        binValue[2] = (byte)(getDataLength()>>8);
        binValue[3] = (byte)(getDataLength()&0x00FF);

        /* CRC */
        binValue[4] = (byte)((crc >> 24) & 0xff);
        binValue[5] = (byte)((crc >> 16) & 0xff);
        binValue[6] = (byte)((crc >> 8) & 0xff);
        binValue[7] = (byte)(crc & 0xff);

        return binValue;
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     * @param attributeValue a binary array containing this attribute's field
     *                       values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *         offset is equal to the index of the first byte after
     *         length)
     * @param length the length of the binary array.
     * @throws StunException if attrubteValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length) throws StunException
    {
        if(length != 4)
        {
            throw new StunException("length invalid");
        }

        crc = ((attributeValue[0] << 24) & 0xff000000) + ((attributeValue[1] << 16) & 0x00ff0000)
            + ((attributeValue[2] << 8) & 0x0000ff00) + (attributeValue[3] & 0x000000ff);
    }
}

