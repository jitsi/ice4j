/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import java.util.*;

import org.ice4j.*;

/**
 * The NONCE attribute is used for authentification.
 *
 * @author Sebastien Vincent
 * @version 0.1
 */
public class NonceAttribute extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "NONCE";

    /**
     * Nonce value.
     */
    private byte nonce[] = null;

    /**
     * Constructor.
     */
    NonceAttribute()
    {
        super(NONCE);
    }

    /**
     * Copies the value of the nonce attribute from the specified
     * attributeValue.
     * @param attributeValue a binary array containing this attribute's
     *   field values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *   offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     * @throws StunException if attributeValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length) throws StunException
    {
        nonce = new byte[length];
        System.arraycopy(attributeValue, offset, nonce, 0, length);
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength() + (getDataLength() % 4)];

        //Type
        binValue[0] = (byte)(type>>8);
        binValue[1] = (byte)(type&0x00FF);

        //Length
        binValue[2] = (byte)(getDataLength()>>8);
        binValue[3] = (byte)(getDataLength()&0x00FF);

        /* nonce */
        System.arraycopy(nonce, 0, binValue, 4, (int)getDataLength());

        return binValue;
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return (char)nonce.length;
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
     * Returns a (cloned) byte array containg the data value of the nonce
     * attribute.
     * @return the binary array containing the nonce.
     */
    public byte[] getNonce()
    {
        if (nonce == null)
            return null;

        byte[] copy = new byte[nonce.length];
        System.arraycopy(nonce, 0, copy, 0, nonce.length);
        return copy;
    }

    /**
     * Copies the specified binary array into the the data value of the nonce
     * attribute.
     * @param nonce the binary array containing the nonce.
     */
    public void setNonce(byte[] nonce)
    {
        if (nonce == null)
        {
            this.nonce = null;
            return;
        }

        this.nonce = new byte[nonce.length];
        System.arraycopy(nonce, 0, this.nonce, 0, nonce.length);
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when they
     * have the same type length and value.
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof NonceAttribute) || obj == null)
            return false;

        if (obj == this)
            return true;

        NonceAttribute att = (NonceAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
                || att.getDataLength() != getDataLength()
                || !Arrays.equals( att.nonce, nonce))
            return false;

        return true;
    }
}

