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

import java.util.*;

import org.ice4j.*;
import org.junit.jupiter.api.*;
/**
 * Tests the UNKNOWN attribute class.
 *
 * @author Emil Ivov
 */
public class UnknownAttributesAttributeTest
{
    private UnknownAttributesAttribute unknownAttributesAttribute = null;
    private MsgFixture binMessagesFixture;

    @BeforeEach
    public void setUp() throws Exception
    {
        unknownAttributesAttribute = new UnknownAttributesAttribute();
        binMessagesFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        unknownAttributesAttribute = null;
        binMessagesFixture = null;
    }
//-------------------------------- TESTS ---------------------------------------
    /**
     * Verify the the constructed object has the correct (UNKNOWN-ATTRIBUTES)
     * type.
     */
    @Test
    public void testUnknownAttributesAttribute()
    {
        unknownAttributesAttribute = new UnknownAttributesAttribute();
        assertEquals(
            Attribute.UNKNOWN_ATTRIBUTES,
            (int) unknownAttributesAttribute.getAttributeType(),
            "UnknownAttributesAttribute() did not properly set the Attribute's type field!"
        );
    }

    /**
     * Verify that the passed attribute id is added to the list of attributes
     * and that a second addition of the same id would not augment the attribute
     * count.
     */
    @Test
    public void testAddAttributeID()
    {
        char attributeID = 0x22; // unknown attribute id

        unknownAttributesAttribute.addAttributeID(attributeID);

        assertEquals(
            (int) attributeID,
            (int) unknownAttributesAttribute.getAttribute(0),
            "addAttributeID does not seem to properly add the attribute ID"
        );

        assertEquals(
            1,
            unknownAttributesAttribute.getAttributeCount(),
            "addAttributeID does not seem to properly add the attribute ID"
        );

        //add a second one
        unknownAttributesAttribute.addAttributeID(attributeID);

        assertEquals(
            1,
            unknownAttributesAttribute.getAttributeCount(),
            "Adding a 2nd time the same attributeID should not change the number of attributes"
        );
    }

    /**
     * Tests whether a sample binary array is properly decoded.
     * @throws StunException if anything goes wrong.
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        //a copy of the array in the fixture:
        byte[] attributeValue = binMessagesFixture.unknownAttsDecodeTestValue;

        unknownAttributesAttribute.decodeAttributeBody(attributeValue,
                                               Attribute.HEADER_LENGTH,
                                               (char)(attributeValue.length
                                               - Attribute.HEADER_LENGTH));
        //is every one there?
        assertTrue(
            unknownAttributesAttribute.contains(
                MsgFixture.UNKNOWN_ATTRIBUTES_1ST_ATT),
            "The " + (int) MsgFixture.UNKNOWN_ATTRIBUTES_1ST_ATT
                + " attribute id "
                + "was not found after decoding a binary array that contained it."
        );

        assertTrue(
            unknownAttributesAttribute.contains(
                MsgFixture.UNKNOWN_ATTRIBUTES_2ND_ATT),
            "The " + (int) MsgFixture.UNKNOWN_ATTRIBUTES_2ND_ATT
                + " attribute id "
                + "was not found after decoding a binary array that contained it."
        );
        assertTrue(
            unknownAttributesAttribute.contains(
                MsgFixture.UNKNOWN_ATTRIBUTES_3D_ATT),
            "The " + (int) MsgFixture.UNKNOWN_ATTRIBUTES_3D_ATT
                + " attribute id "
                + "was not found after decoding a binary array that contained it."
            );

        assertEquals(
            MsgFixture.UNKNOWN_ATTRIBUTES_CNT_DEC_TST,
            unknownAttributesAttribute.getAttributeCount(),
            "The decoded attribute contained "
                + unknownAttributesAttribute.getAttributeCount()
                + " attribute ids when there were only "
                + (int) MsgFixture.UNKNOWN_ATTRIBUTES_CNT_DEC_TST
                + " in the original binary array."
        );
    }

    /**
     * Creates a new UnknownAttributesAttribute encodes it and assert equality
     * with binMessagesFixture.unknownAttsEncodeExpectedResult.
     */
    @Test
    public void testEncode()
    {
        byte[] expectedReturn = binMessagesFixture.unknownAttsEncodeExpectedResult;

        unknownAttributesAttribute.addAttributeID(
            MsgFixture.UNKNOWN_ATTRIBUTES_1ST_ATT);
        unknownAttributesAttribute.addAttributeID(
            MsgFixture.UNKNOWN_ATTRIBUTES_2ND_ATT);

        byte[] actualReturn = unknownAttributesAttribute.encode();
        assertArrayEquals(actualReturn, expectedReturn);
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     */
    @Test
    public void testEquals()
    {
        UnknownAttributesAttribute target = new UnknownAttributesAttribute();

        assertNotEquals(unknownAttributesAttribute, null);

        unknownAttributesAttribute.addAttributeID((char)25);
        target.addAttributeID((char)25);

        unknownAttributesAttribute.addAttributeID((char)26);
        assertNotEquals(unknownAttributesAttribute, target);

        target.addAttributeID((char)26);
        assertEquals(unknownAttributesAttribute, target);
    }

    /**
     * Tests that getAttribute() return the correct attribute id, preserving
     * entry order.
     */
    @Test
    public void testGetAttribute()
    {
        char expectedId1 = 20;
        char expectedId2 = 21;

        char actualId1;
        char actualId2;

        unknownAttributesAttribute.addAttributeID(expectedId1);
        unknownAttributesAttribute.addAttributeID(expectedId2);

        actualId1 = unknownAttributesAttribute.getAttribute(0);
        actualId2 = unknownAttributesAttribute.getAttribute(1);

        assertEquals(expectedId1, actualId1, "getAttribute() return value mismatch");
        assertEquals(expectedId2, actualId2, "getAttribute() return value mismatch");
    }

    /**
     * Add some attributes and test whether their number is properly calculated.
     * Tests duplicate id handling as well.
     */
    @Test
    public void testGetAttributeCount()
    {
        int expectedReturn = 5;

        unknownAttributesAttribute.addAttributeID((char)21);
        unknownAttributesAttribute.addAttributeID((char)22);
        unknownAttributesAttribute.addAttributeID((char)23);
        unknownAttributesAttribute.addAttributeID((char)24);
        unknownAttributesAttribute.addAttributeID((char)25);
        unknownAttributesAttribute.addAttributeID((char)25);//duplicate values should be ignored

        int actualReturn = unknownAttributesAttribute.getAttributeCount();
        assertEquals(expectedReturn, actualReturn,
            "getAttributeCount did not return the expected value");
    }

    /**
     * Same as testGetAttributeID, only attribute attributes are extracted
     * through the getAttributes()'s iterator.
     */
    @Test
    public void testGetAttributes()
    {
        char expectedId1 = 20;
        char expectedId2 = 21;

        char actualId1;
        char actualId2;

        unknownAttributesAttribute.addAttributeID(expectedId1);
        unknownAttributesAttribute.addAttributeID(expectedId2);

        Iterator<Character> iterator = unknownAttributesAttribute.getAttributes();

        actualId1 = iterator.next();
        actualId2 = iterator.next();

        assertEquals(expectedId1, actualId1, "getAttributes() return value mismatch");
        assertEquals(expectedId2, actualId2, "getAttributes() return value mismatch");
    }

    /**
     * Adds a fixed number of attributes and checks data length accordingly.
     * Test is first performed for an odd number of attributes and then again
     * (after adding another attribute id). Both results should be the same.
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = 8;

        unknownAttributesAttribute.addAttributeID((char)20);
        unknownAttributesAttribute.addAttributeID((char)21);
        unknownAttributesAttribute.addAttributeID((char)22);

        char actualReturn = unknownAttributesAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn,
            "Incorrect testGetDataLength() return value");

        unknownAttributesAttribute.addAttributeID((char)23);

        actualReturn = unknownAttributesAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn,
            "Incorrect testGetDataLength() return value");

    }

    /**
     * Tests whether getName returns a relevant name.
     */
    @Test
    public void testGetName()
    {
        assertEquals("UNKNOWN-ATTRIBUTES", unknownAttributesAttribute.getName());
    }
}
