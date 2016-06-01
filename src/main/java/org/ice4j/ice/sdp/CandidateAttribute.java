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
package org.ice4j.ice.sdp;

import gov.nist.core.*;
import gov.nist.javax.sdp.fields.*;
import org.ice4j.*;
import org.ice4j.ice.*;

import javax.sdp.*;

public class CandidateAttribute extends AttributeField
{
    /**
     * The SDP name of candidate attributes.
     */
    public static final String NAME = "candidate";

    /**
     * This class's serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The Candidate that we will be encapsulating.
     */
    private Candidate<?> candidate;

    protected CandidateAttribute()
    {
        this(null);
    }

    /**
     * Creates an attribute instance
     *
     * @param candidate the Candidate
     */
    public CandidateAttribute(Candidate<?> candidate)
    {
        this.candidate = candidate;
    }

    /**
     * {@inheritDoc}
     */
    public NameValue getAttribute()
    {
        // We've overridden the method getValue() of AttributeField. The
        // NameValue pair of the method getAttribute() should return the value of
        // the method getValue() of AttributeField then. Unfortunately, NameValue
        // accesses its field value in multiple places so it is not a question of
        // simply overriding a method or two. As a compromise, initialize a new
        // NameValue with the current name and value upon each invocation.
        NameValue attribute = super.getAttribute();
        String name = getName();

        if ((attribute == null)
                || (name.equals(attribute.getName())
                        && (attribute.getValue() == null)))
        {
            attribute = new NameValue(name, getValue());
        }
        return attribute;
    }

    /**
     * Returns the name of this attribute
     *
     * @return a String identity.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Does nothing .
     *
     * @param name ignored.
     */
    public void setName(String name)
    {
    }

    /**
     * Always returns <tt>true</tt> as this attribute always has a value.
     *
     * @return true if the attribute has a value.
     */
    public boolean hasValue()
    {
        return true;
    }

    /**
     * Returns the value of this attribute.
     *
     * @return the value
     */
    public String getValue()
    {
        StringBuffer buff = new StringBuffer();

        buff.append(candidate.getFoundation());
        buff.append(" ").append(
            candidate.getParentComponent().getComponentID());
        buff.append(" ").append(candidate.getTransport());
        buff.append(" ").append(candidate.getPriority());
        buff.append(" ").append(
            candidate.getTransportAddress().getHostAddress());
        buff.append(" ").append(
            candidate.getTransportAddress().getPort());
        buff.append(" typ ").append(
            candidate.getType());

        TransportAddress relAddr = candidate.getRelatedAddress();

        if (relAddr != null)
        {
            buff.append(" raddr ").append(relAddr.getHostAddress());
            buff.append(" rport ").append(relAddr.getPort());
        }

        return buff.toString();
    }

    /**
     * Parses the value of this attribute.
     *
     * @param value the - attribute value
     *
     * @throws javax.sdp.SdpException if there's a problem with the <tt>value
     * String</tt>.
     */
    public void setValue(String value)
        throws SdpException
    {
    }

    /**
     * Returns the type character for the field.
     *
     * @return the type character for the field.
     */
    public char getTypeChar()
    {
        return 'a';
    }

    /**
     * Returns a reference to this attribute.
     *
     * @return a reference to this attribute.
     */
    public CandidateAttribute clone()
    {
        CandidateAttribute clone = (CandidateAttribute) super.clone();

        clone.candidate = candidate;
        return clone;
    }

    /**
     * Returns the string encoded version of this object
     *
     * @return the string encoded version of this object
     */
     public String encode()
     {
         StringBuffer sbuff = new StringBuffer(ATTRIBUTE_FIELD);
         sbuff.append(getName()).append(Separators.COLON);
         sbuff.append(getValue());
         return sbuff.append(Separators.NEWLINE).toString();
     }
}
