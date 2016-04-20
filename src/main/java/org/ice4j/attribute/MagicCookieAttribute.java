/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * The MAGIC-COOKIE attribute.
 *
 * It is used with old version of TURN (Google, Live messenger variant, ...).
 *
 * @author Sebastien Vincent
 */
public class MagicCookieAttribute
    extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "MAGIC-COOKIE";

    /**
     * The length of the data contained by this attribute.
     */
    public static final char DATA_LENGTH = 4;

    /**
     * Magic cookie value.
     */
    private int value = 0x72c64bc6;

    /**
     * Constructor.
     */
    MagicCookieAttribute()
    {
        super(MAGIC_COOKIE);
    }

    /**
     * Returns the human readable name of this attribute. Attribute names do
     * not really matter from the protocol point of view. They are only used
     * for debugging and readability.
     *
     * @return this attribute's name.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Returns the length of this attribute's body.
     *
     * @return the length of this attribute's value (8 bytes).
     */
    public char getDataLength()
    {
        return DATA_LENGTH;
    }

    /**
     * Compares two STUN Attributes. Attributes are considered equal when their
     * type, length, and all data are the same.
     *
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof MagicCookieAttribute))
            return false;

        if (obj == this)
            return true;

        MagicCookieAttribute att = (MagicCookieAttribute) obj;
        if (att.getAttributeType()   != getAttributeType()
                || att.getDataLength() != getDataLength()
                /* compare data */
                || att.value != value
           )
            return false;

        return true;
    }

    /**
     * Returns a binary representation of this attribute.
     *
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
        binValue[4] = (byte)((value >> 24) & 0xff);
        binValue[5] = (byte)((value >> 16) & 0xff);
        binValue[6] = (byte)((value >> 8) & 0xff);
        binValue[7] = (byte)((value) & 0xff);

        return binValue;
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     *
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

        value = ((attributeValue[0] << 24) & 0xff000000) +
            ((attributeValue[1] << 16) & 0x00ff0000) +
            ((attributeValue[2] << 8) & 0x0000ff00) +
            (attributeValue[3] & 0x000000ff);
    }
}
