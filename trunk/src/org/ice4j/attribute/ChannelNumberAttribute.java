/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * The CHANNEL-NUMBER attribute is used to known on which
 * channel the TURN client want to send data.
 *
 * @author Sebastien Vincent
 */
public class ChannelNumberAttribute extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "CHANNEL-NUMBER";

    /**
     * The length of the data contained by this attribute.
     */
    public static final char DATA_LENGTH = 4;

    /**
     * Channel number.
     */
    private char channelNumber = 0;

    /**
     * Constructor.
     */
    ChannelNumberAttribute()
    {
        super(CHANNEL_NUMBER);
    }

    /**
     * Compares two STUN Attributes. Attributes are considered equal when their
     * type, length, and all data are the same.
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof ChannelNumberAttribute)
                || obj == null)
            return false;

        if (obj == this)
            return true;

        ChannelNumberAttribute att = (ChannelNumberAttribute) obj;
        if (att.getAttributeType()   != getAttributeType()
                || att.getDataLength()   != getDataLength()
                /* compare data */
                || att.channelNumber != channelNumber
           )
            return false;

        return true;
    }

    /**
     * Returns the human readable name of this attribute. Attribute names do
     * not really matter from the protocol point of view. They are only used
     * for debugging and readability.
     * @return this attribute's name.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value (8 bytes).
     */
    public char getDataLength()
    {
        return DATA_LENGTH;
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        byte binValue[] = new byte[HEADER_LENGTH + DATA_LENGTH];

        //Type
        binValue[0] = (byte)(getAttributeType() >> 8);
        binValue[1] = (byte)(getAttributeType() & 0x00FF);
        //Length
        binValue[2] = (byte)(getDataLength() >> 8);
        binValue[3] = (byte)(getDataLength() & 0x00FF);
        //Data
        binValue[4] = (byte)((channelNumber >> 8) & 0xff);
        binValue[5] = (byte)((channelNumber) & 0xff);
        binValue[6] = 0x00;
        binValue[7] = 0x00;

        return binValue;
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     * @param attributeValue a binary array containing this attribute's field
     *                       values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *          offset is equal to the index of the first byte after
     *          length)
     * @param length the length of the binary array.
     * @throws StunException if attrubteValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
        throws StunException
    {
        if(length != 4)
        {
            throw new StunException("length invalid");
        }

        channelNumber =
            ((char)((attributeValue[0] << 8 ) | (attributeValue[1] & 0xFF) ));
    }

    /**
     * Set the channel number.
     * @param channelNumber channel number
     */
    public void setChannelNumber(char channelNumber)
    {
        this.channelNumber = channelNumber;
    }

    /**
     * Get the channel number.
     * @return channel number
     */
    public char getChannelNumber()
    {
        return channelNumber;
    }
}