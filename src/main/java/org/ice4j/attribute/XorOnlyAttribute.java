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
 *  This attribute is present in a Binding Request.  It is used by a
 *  client to request that a server compliant to this specification omit
 *  the MAPPED-ADDRESS from a Binding Response, and include only the XOR-
 *  MAPPED-ADDRESS.  This is necessary in cases where a Binding Response
 *  is failing integrity checks because a NAT is rewriting the contents
 *  of a MAPPED-ADDRESS in the Binding Response.
 *
 * This attribute has a length of zero, and therefore contains no other
 * information past the common attribute header.
 *
 * @author Emil Ivov
 */
public class XorOnlyAttribute
    extends Attribute
{
    /**
     * Constructor.
     */
    protected XorOnlyAttribute()
    {
        super(Attribute.XOR_ONLY);
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     *
     * @param attributeValue a binary array containing this attribute's
     *   field values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *   offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     * @throws StunException if attrubteValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
        throws StunException
    {
        //nothing to do cause we have 0 length
    }

    /**
     * Returns a binary representation of this attribute.
     *
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength()];

        //Type
        binValue[0] = (byte)(type >> 8);
        binValue[1] = (byte)(type & 0x00FF);

        //Length
        binValue[2] = (byte)(getDataLength() >> 8);
        binValue[3] = (byte)(getDataLength() & 0x00FF);

        return binValue;
    }

    /**
     * Returns the length of this attribute's body. (Which in the case of the
     * XOR-ONLY attribute is 0);
     *
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return 0;
    }

    /**
     * Returns the human readable name of this attribute.
     *
     * @return this attribute's name.
     */
    public String getName()
    {
        return "XOR-ONLY";
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when
     * they have the same type length and value.
     *
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */

    public boolean equals(Object obj)
    {
        if (! (obj instanceof XorOnlyAttribute))
            return false;

        if (obj == this)
            return true;

        XorOnlyAttribute att = (XorOnlyAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
            || att.getDataLength() != getDataLength())
            return false;

        return true;
    }
}
