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

import junit.framework.*;

import org.ice4j.*;

/**
 * Class to test the RequestedAddressFamilyAttribute class.
 * 
 * @author Aakash Garg
 * 
 */
public class RequestedAddressFamilyAttributeTest
    extends TestCase
{
    private RequestedAddressFamilyAttribute requestedAddressFamilyAttribute =
        null;

    private MsgFixture msgFixture;

    @Override
    protected void setUp() throws Exception
    {
        super.setUp();
        this.requestedAddressFamilyAttribute =
            new RequestedAddressFamilyAttribute();
        this.msgFixture = new MsgFixture();

        msgFixture.setUp();
    }

    public RequestedAddressFamilyAttributeTest(String name)
    {
        super(name);
    }

    @Override
    protected void tearDown() throws Exception
    {
        this.requestedAddressFamilyAttribute = null;
        this.msgFixture.tearDown();

        this.msgFixture = null;
        super.tearDown();
    }

    /**
     * Tests whether data length is properly calculated.
     */
    public void testGetDataLength()
    {
        char expectedReturn = 1;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);
        char actualReturn =
            this.requestedAddressFamilyAttribute.getDataLength();
        assertEquals(
            "Datalength is not properly calculated", expectedReturn,
            actualReturn);

        expectedReturn = 1;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);
        actualReturn = this.requestedAddressFamilyAttribute.getDataLength();
        assertEquals(
            "Datalength is not properly calculated", expectedReturn,
            actualReturn);

    }

    /**
     * Tests getting the name.
     */
    public void testGetName()
    {
        String expectedReturn = "REQUESTED-ADDRESS-FAMILY";
        String actualReturn = requestedAddressFamilyAttribute.getName();
        assertEquals(
            "getting name failed", expectedReturn, actualReturn);
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     */
    public void testEqualsObject()
    {
        // null test
        RequestedAddressFamilyAttribute target = null;
        boolean expectedReturn = false;
        boolean actualReturn = requestedAddressFamilyAttribute.equals(target);

        assertEquals(
            "RequestedAddressFamilyAttribute.equals() failed against a null "
                + "target.", expectedReturn, actualReturn);

        // difference test
        target = new RequestedAddressFamilyAttribute();

        char family = MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6;
        target.setFamily(family);

        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);

        expectedReturn = false;
        actualReturn = requestedAddressFamilyAttribute.equals(target);
        assertEquals(
            "RequestedAddressFamilyAttribute.equals() failed against a "
                + "different target.", expectedReturn, actualReturn);

        // equality test
        target.setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);

        expectedReturn = true;
        actualReturn = requestedAddressFamilyAttribute.equals(target);
        assertEquals(
            "RequestedAddressFamilyAttribute.equals() failed against an equal "
                + "target.", expectedReturn, actualReturn);

        // ipv6 equality test
        target.setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);

        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);

        expectedReturn = true;
        actualReturn = requestedAddressFamilyAttribute.equals(target);
        assertEquals(
            "RequestedAddressFamilyAttribute.equals() failed for IPv6 address.",
            expectedReturn, actualReturn);
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * 
     * @throws StunException if something goes wrong while decoding 
     *             Attribute Body.
     */
    public void testDecodeAttributeBodyV4() throws StunException
    {
        byte[] attributeValue = msgFixture.requestedAddressFamilyV4;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        requestedAddressFamilyAttribute.decodeAttributeBody(
            attributeValue, offset, length);

        assertEquals(
            "RequestedAddressFamilyAttribute.decode() did not properly decode "
                + "the family field.",
            MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4,
            requestedAddressFamilyAttribute.getFamily());
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * 
     * @throws StunException if something goes wrong while decoding 
     *             Attribute Body.
     */
   public void testDecodeAttributeBodyV6() throws StunException
    {
        byte[] attributeValue = msgFixture.requestedAddressFamilyV6;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        requestedAddressFamilyAttribute.decodeAttributeBody(
            attributeValue, offset, length);

        assertEquals(
            "RequestedAddressFamilyAttribute.decode() did not properly decode.",
            MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6,
            requestedAddressFamilyAttribute.getFamily());
    }

    /**
     * Test whether attributes are properly encoded.
     */
    public void testEncodeV4()
    {
        byte[] expectedReturn = msgFixture.requestedAddressFamilyV4;
        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);
        byte[] actualReturn = requestedAddressFamilyAttribute.encode();
        assertTrue(
            "RequestedAddressFamilyAttribute.encode() did not "
                + "properly encode a sample attribute for IPv4 family",
            Arrays.equals(
                expectedReturn, actualReturn));
    }

    /**
     * Test whether attributes are properly encoded.
     */
    public void testEncodeV6()
    {
        byte[] expectedReturn = msgFixture.requestedAddressFamilyV6;
        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);
        byte[] actualReturn = requestedAddressFamilyAttribute.encode();
        assertTrue(
            "RequestedAddressFamilyAttribute.encode() did not "
                + "properly encode a sample attribute for IPv6 family",
            Arrays.equals(
                expectedReturn, actualReturn));
    }

    /**
     * Tests that the address family is always 0x01 or 0x02.
     */
    public void testGetFamily()
    {
        char expectedReturn = 0x01;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);
        char actualReturn = this.requestedAddressFamilyAttribute.getFamily();
        assertEquals(
            "Family is not properly calculated", expectedReturn,
            actualReturn);

        expectedReturn = 0x02;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);
        actualReturn = this.requestedAddressFamilyAttribute.getFamily();
        assertEquals(
            "Family is not properly calculated", expectedReturn,
            actualReturn);
    }

}
