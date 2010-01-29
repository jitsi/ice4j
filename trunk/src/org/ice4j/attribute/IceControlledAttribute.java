package org.ice4j.attribute;

import java.util.Arrays;

import org.ice4j.*;


public class IceControlledAttribute
    extends Attribute
{

    /**
     * The length of the data contained in this attribute
     */
    private static final char DATA_LENGTH_ICE_CONTROLLED = 8;

    /**
     * The tie-breaker value represented in this attribute
     */
    byte[] tieBreaker = null;

    /**
     * Constructs an ICE-CONTROLLED attribute
     */
    protected IceControlledAttribute()
    {
        super(ICE_CONTROLLED);
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     *
     * @param attributeValue a binary array containing this attribute's field
     *                       values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *                  offset is equal to the index of the first byte after
     *                  length)
     * @param length the length of the attribute data.
     *
     * @throws StunException if attributeValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
            throws StunException
    {
        // initializing the byte arrays which holds the 64 bit value
        // after decoding
        tieBreaker = new byte[length];

        System.arraycopy(attributeValue, offset, tieBreaker, 0, length);
    }

     /**
      * Returns a binary representation of this attribute.
      *
      * @return a binary representation of this attribute.
      */
    public byte[] encode() {

        char type = getAttributeType();
        byte[] binValue = new byte[HEADER_LENGTH + DATA_LENGTH_ICE_CONTROLLED];

        // Type
        binValue[0] = (byte)(type>>8);
        binValue[1] = (byte)(type&0x00FF);

        // Length
        binValue[2] = (byte)(DATA_LENGTH_ICE_CONTROLLED>>8);
        binValue[3] = (byte)(DATA_LENGTH_ICE_CONTROLLED&0x00FF);

        // Tie-Breaker, 64 bits stored in network byte order
        System.arraycopy(tieBreaker, 0, binValue, 4, tieBreaker.length);

        return binValue;
    }

    /**
     * Compares two STUN Attributes. Attributes are considered equal when their
     * type, length, and all data are the same.
     *
     * @param obj the object to compare this attribute with.
     *
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if(!(obj instanceof IceControlledAttribute)
            || obj == null)
            return false;

        if(obj == this)
            return true;

        IceControlledAttribute iceControlledAtt = (IceControlledAttribute)obj;
        if(iceControlledAtt.getAttributeType() != getAttributeType()
            || iceControlledAtt.getDataLength() != DATA_LENGTH_ICE_CONTROLLED
            || (tieBreaker != null
                && !Arrays.equals(tieBreaker, iceControlledAtt.tieBreaker))
            )
            return false;

        return true;
    }

    /**
     * Returns the data length of this attribute
     *
     * @return    the data length of this attribute
     */
    public char getDataLength()
    {
        return DATA_LENGTH_ICE_CONTROLLED;
    }

    /**
     * Returns the human readable name of this attribute.
     *
     * @return this attribute's name.
     */
    public String getName()
    {
        return "ICE-CONTROLLED";
    }

    /**
     * Sets the Tie Breaker byte array to the specified byte array
     * An exact copy of the specified byte array is made
     *
     * @param tieBreaker the byte array containing the 64 bit tie-breaker
     * value
     *
     * @throws StunException if tieBreaker contains invalid data
     */
    public void setTieBreaker(byte[] tieBreaker)
        throws StunException
    {
        if(tieBreaker.length != DATA_LENGTH_ICE_CONTROLLED)
        {
            throw new StunException(StunException.ILLEGAL_ARGUMENT,
                "The supplied byte array does not contain the correct number"
                +" of bytes");
        }
        else
        {
            //FIXME - uncomment.
            //this.tieBreaker = Arrays.copyOf(tieBreaker, tieBreaker.length);
        }
    }

    /**
     * Returns a copy of the Tie Breaker byte array
     *
     * @return an exact copy of the Tie Breaker byte array
     */
    public byte[] getTieBreaker()
    {
        if(tieBreaker == null)
        {
            return null;
        }
        else
        {
            //FIXME uncomment
            //return Arrays.copyOf(tieBreaker, tieBreaker.length);
            return null;
        }
    }

}
