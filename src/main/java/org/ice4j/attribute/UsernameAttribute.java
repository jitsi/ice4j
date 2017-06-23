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

import java.util.*;

/**
 * The USERNAME attribute is used for message integrity.
 * The value of USERNAME is a variable length value.
 *
 * @author Sebastien Vincent
 * @author Emil Ivov
 */
public class UsernameAttribute extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "USERNAME";

    /**
     * Username value.
     */
    private byte username[] = null;

    /**
     * Constructor.
     */
    UsernameAttribute()
    {
        super(USERNAME);
    }

    /**
     * Copies the value of the username attribute from the specified
     * attributeValue.
     *
     * @param attributeValue a binary array containing this attribute's
     *   field values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *   offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     */
    @Override
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
    {
        // This works around the following bug in Edge, which effectively adds
        // additional "0" bytes to the end of the USERNAME attribute:
        // https://developer.microsoft.com/en-us/microsoft-edge/platform/issues/12332457/
        while (length >= offset && attributeValue[length] == 0)
        {
            length--;
        }

        username = new byte[length];
        System.arraycopy(attributeValue, offset, username, 0, length);
    }

    /**
     * Returns a binary representation of this attribute.
     *
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength()
                                   //add padding
                                   + (4 - getDataLength() % 4) % 4];

        //Type
        binValue[0] = (byte)(type >> 8);
        binValue[1] = (byte)(type & 0x00FF);

        //Length
        binValue[2] = (byte)(getDataLength() >> 8);
        binValue[3] = (byte)(getDataLength() & 0x00FF);

        //username
        System.arraycopy(username, 0, binValue, 4, getDataLength());

        return binValue;
    }

    /**
     * Returns the length of this attribute's body.
     *
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return (char)username.length;
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
     * Returns a (cloned) byte array containing the data value of the username
     * attribute.
     *
     * @return the binary array containing the username.
     */
    public byte[] getUsername()
    {
        return (username == null) ? null : username.clone();
    }

    /**
     * Copies the specified binary array into the the data value of the username
     * attribute.
     *
     * @param username the binary array containing the username.
     */
    public void setUsername(byte[] username)
    {
        if (username == null)
        {
            this.username = null;
            return;
        }

        this.username = new byte[username.length];
        System.arraycopy(username, 0, this.username, 0, username.length);
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when
     * they have the same type length and value.
     *
     * @param obj the object to compare this attribute with.
     *
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof UsernameAttribute))
            return false;

        if (obj == this)
            return true;

        UsernameAttribute att = (UsernameAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
                || att.getDataLength() != getDataLength()
                || !Arrays.equals( att.username, username))
            return false;

        return true;
    }
}
