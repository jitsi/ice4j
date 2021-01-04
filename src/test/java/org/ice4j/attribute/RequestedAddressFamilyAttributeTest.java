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

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;
import org.junit.jupiter.api.*;
/**
 * Class to test the RequestedAddressFamilyAttribute class.
 * 
 * @author Aakash Garg
 * 
 */
public class RequestedAddressFamilyAttributeTest
{
    private RequestedAddressFamilyAttribute requestedAddressFamilyAttribute =
        null;

    private MsgFixture msgFixture;

    @BeforeEach
    public void setUp() throws Exception
    {
        this.requestedAddressFamilyAttribute =
            new RequestedAddressFamilyAttribute();
        this.msgFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        this.requestedAddressFamilyAttribute = null;
        this.msgFixture = null;
    }

    /**
     * Tests whether data length is properly calculated.
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = 1;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);
        char actualReturn =
            this.requestedAddressFamilyAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn,
            "Datalength is not properly calculated");

        expectedReturn = 1;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);
        actualReturn = this.requestedAddressFamilyAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn,
            "Datalength is not properly calculated");

    }

    /**
     * Tests getting the name.
     */
    @Test
    public void testGetName()
    {
        assertEquals("REQUESTED-ADDRESS-FAMILY", requestedAddressFamilyAttribute.getName());
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     */
    @Test
    public void testEqualsObject()
    {
        // null test
        assertNotEquals(requestedAddressFamilyAttribute, null);

        // difference test
        RequestedAddressFamilyAttribute target;
        target = new RequestedAddressFamilyAttribute();

        char family = MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6;
        target.setFamily(family);

        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);

        assertNotEquals(requestedAddressFamilyAttribute, target);

        // equality test
        target.setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);

        assertEquals(requestedAddressFamilyAttribute, target);

        // ipv6 equality test
        target.setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);

        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);

        assertEquals(requestedAddressFamilyAttribute, target);
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * 
     * @throws StunException if something goes wrong while decoding 
     *             Attribute Body.
     */
    @Test
    public void testDecodeAttributeBodyV4() throws StunException
    {
        byte[] attributeValue = msgFixture.requestedAddressFamilyV4;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        requestedAddressFamilyAttribute.decodeAttributeBody(
            attributeValue, offset, length);

        assertEquals(
            MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4,
            requestedAddressFamilyAttribute.getFamily(),
            "RequestedAddressFamilyAttribute.decode() did not properly decode the family field."
        );
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * 
     * @throws StunException if something goes wrong while decoding 
     *             Attribute Body.
     */
    @Test
    public void testDecodeAttributeBodyV6() throws StunException
    {
        byte[] attributeValue = msgFixture.requestedAddressFamilyV6;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        requestedAddressFamilyAttribute.decodeAttributeBody(
            attributeValue, offset, length);

        assertEquals(
            MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6,
            requestedAddressFamilyAttribute.getFamily(),
            "RequestedAddressFamilyAttribute.decode() did not properly decode."
        );
    }

    /**
     * Test whether attributes are properly encoded.
     */
    @Test
    public void testEncodeV4()
    {
        byte[] expectedReturn = msgFixture.requestedAddressFamilyV4;
        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);
        byte[] actualReturn = requestedAddressFamilyAttribute.encode();
        assertArrayEquals(
            expectedReturn, actualReturn,
            "RequestedAddressFamilyAttribute.encode() did not properly encode a sample attribute for IPv4 family"
        );
    }

    /**
     * Test whether attributes are properly encoded.
     */
    @Test
    public void testEncodeV6()
    {
        byte[] expectedReturn = msgFixture.requestedAddressFamilyV6;
        requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);
        byte[] actualReturn = requestedAddressFamilyAttribute.encode();
        assertArrayEquals(
            expectedReturn, actualReturn,
            "RequestedAddressFamilyAttribute.encode() did not properly encode a sample attribute for IPv6 family"
        );
    }

    /**
     * Tests that the address family is always 0x01 or 0x02.
     */
    @Test
    public void testGetFamily()
    {
        char expectedReturn = 0x01;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V4);
        char actualReturn = this.requestedAddressFamilyAttribute.getFamily();
        assertEquals(expectedReturn, actualReturn,
            "Family is not properly calculated");

        expectedReturn = 0x02;
        this.requestedAddressFamilyAttribute
            .setFamily(MsgFixture.REQUESTED_ADDRESS_FAMILY_ATTRIBUTE_V6);
        actualReturn = this.requestedAddressFamilyAttribute.getFamily();
        assertEquals(expectedReturn, actualReturn,
            "Family is not properly calculated");
    }
}
