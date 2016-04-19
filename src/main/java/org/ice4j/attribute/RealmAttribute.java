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

import org.ice4j.*;

/**
 * The REALM attribute contains a text which meets the grammar for
 * "realm value" as described in RFC3261 but without the double quotes.
 *
 * @author Sebastien Vincent
 */
public class RealmAttribute extends Attribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "REALM";

    /**
     * Realm value.
     */
    private byte realm[] = null;

    /**
     * Constructor.
     */
    RealmAttribute()
    {
        super(REALM);
    }

    /**
     * Copies the value of the realm attribute from the specified
     * attributeValue.
     * @param attributeValue a binary array containing this attribute's
     *   field values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *   offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     * @throws StunException if attributeValue contains invalid data.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
        throws StunException
    {
        realm = new byte[length];
        System.arraycopy(attributeValue, offset, realm, 0, length);
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength() +
                                   (getDataLength() % 4)];

        //Type
        binValue[0] = (byte)(type >> 8);
        binValue[1] = (byte)(type & 0x00FF);

        //Length
        binValue[2] = (byte)(getDataLength() >> 8);
        binValue[3] = (byte)(getDataLength() & 0x00FF);

        /* realm */
        System.arraycopy(realm, 0, binValue, 4, getDataLength());

        return binValue;
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return (char)realm.length;
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
     * Returns a (cloned) byte array containing the data value of the realm
     * attribute.
     * @return the binary array containing the realm.
     */
    public byte[] getRealm()
    {
        return (realm == null) ? null : realm.clone();
    }

    /**
     * Copies the specified binary array into the the data value of the realm
     * attribute.
     * @param realm the binary array containing the realm.
     */
    public void setRealm(byte[] realm)
    {
        if (realm == null)
        {
            this.realm = null;
            return;
        }

        this.realm = new byte[realm.length];
        System.arraycopy(realm, 0, this.realm, 0, realm.length);
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when they
     * have the same type length and value.
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof RealmAttribute))
            return false;

        if (obj == this)
            return true;

        RealmAttribute att = (RealmAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
                || att.getDataLength() != getDataLength()
                || !Arrays.equals( att.realm, realm))
            return false;

        return true;
    }
}
