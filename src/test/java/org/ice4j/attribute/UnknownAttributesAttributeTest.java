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

import junit.framework.*;

import java.util.*;

import org.ice4j.*;

/**
 * Tests the UNKNOWN attribute class.
 *
 * @author Emil Ivov
 */
public class UnknownAttributesAttributeTest extends TestCase
{
    private UnknownAttributesAttribute unknownAttributesAttribute = null;
    private MsgFixture binMessagesFixture;

    public UnknownAttributesAttributeTest(String name)
    {
        super(name);
    }

    protected void setUp() throws Exception
    {
        super.setUp();
        unknownAttributesAttribute = new UnknownAttributesAttribute();
        binMessagesFixture = new MsgFixture();

        binMessagesFixture.setUp();
    }

    protected void tearDown() throws Exception
    {
        unknownAttributesAttribute = null;
        binMessagesFixture.tearDown();

        binMessagesFixture = null;
        super.tearDown();
    }
//-------------------------------- TESTS ---------------------------------------
    /**
     * Verify the the constructed object has the correct (UNKNOWN-ATTRIBUTES)
     * type.
     */
    public void testUnknownAttributesAttribute()
    {
        unknownAttributesAttribute = new UnknownAttributesAttribute();

        assertEquals("UnknownAttributesAttribute() did not properly set the "
                   +"Attribute's type field!",
                   (int)Attribute.UNKNOWN_ATTRIBUTES,
                   (int)unknownAttributesAttribute.getAttributeType()
                   );
    }

    /**
     * Verify that the passed attribute id is added to the list of attributes
     * and that a second addition of the same id would not augment the attribute
     * count.
     */
    public void testAddAttributeID()
    {
        char attributeID = 0x22; // unknown attribute id

        unknownAttributesAttribute.addAttributeID(attributeID);

        assertEquals("addAttributeID does not seem to properly add the attribute ID",
                    (int)attributeID,
                    (int)unknownAttributesAttribute.getAttribute(0)
                    );

        assertEquals("addAttributeID does not seem to properly add the attribute ID",
                     1,
                     unknownAttributesAttribute.getAttributeCount()
                     );

        //add a second one
        unknownAttributesAttribute.addAttributeID(attributeID);

        assertEquals("Adding a 2nd time the same attributeID should not change "
                     +"the number of attributes",
                     1,
                     unknownAttributesAttribute.getAttributeCount()
                     );

    }

    /**
     * Tests whether a sample binary array is properly decoded.
     * @throws StunException if anything goes wrong.
     */
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
            "The " + (int)MsgFixture.UNKNOWN_ATTRIBUTES_1ST_ATT +" attribute id "
            + "was not found after decoding a binary array that contained it.",
            unknownAttributesAttribute.contains(
                                MsgFixture.UNKNOWN_ATTRIBUTES_1ST_ATT));

        assertTrue(
            "The " + (int)MsgFixture.UNKNOWN_ATTRIBUTES_2ND_ATT +" attribute id "
            + "was not found after decoding a binary array that contained it.",
            unknownAttributesAttribute.contains(
                                MsgFixture.UNKNOWN_ATTRIBUTES_2ND_ATT));
        assertTrue(
            "The " + (int)MsgFixture.UNKNOWN_ATTRIBUTES_3D_ATT +" attribute id "
            + "was not found after decoding a binary array that contained it.",
            unknownAttributesAttribute.contains(
                                MsgFixture.UNKNOWN_ATTRIBUTES_3D_ATT));


        assertEquals("The decoded attribute contained "
                   + unknownAttributesAttribute.getAttributeCount()
                   + " attribute ids when there were only "
                   + (int)MsgFixture.UNKNOWN_ATTRIBUTES_CNT_DEC_TST
                   + " in the original binary array.",
                   MsgFixture.UNKNOWN_ATTRIBUTES_CNT_DEC_TST,
                   unknownAttributesAttribute.getAttributeCount()
                   );
    }

    /**
     * Creates a new UnknownAttributesAttribute encodes it and assert equality
     * with binMessagesFixture.unknownAttsEncodeExpectedResult.
     */
    public void testEncode()
    {
        byte[] expectedReturn = binMessagesFixture.unknownAttsEncodeExpectedResult;

        unknownAttributesAttribute.addAttributeID(
            MsgFixture.UNKNOWN_ATTRIBUTES_1ST_ATT);
        unknownAttributesAttribute.addAttributeID(
            MsgFixture.UNKNOWN_ATTRIBUTES_2ND_ATT);



        byte[] actualReturn = unknownAttributesAttribute.encode();
        assertTrue("UnknownAttributesAttribute did not encode properly.",
                   Arrays.equals(actualReturn, expectedReturn));
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     */
    public void testEquals()
    {
        UnknownAttributesAttribute target = new UnknownAttributesAttribute();

        boolean expectedReturn = false;
        boolean actualReturn = unknownAttributesAttribute.equals(null);
        assertEquals("Equals failed for a null object",
                     expectedReturn, actualReturn);

        unknownAttributesAttribute.addAttributeID((char)25);
        target.addAttributeID((char)25);

        unknownAttributesAttribute.addAttributeID((char)26);
        actualReturn = unknownAttributesAttribute.equals(target);
        assertEquals("Equals failed when comparing different objects.",
                     expectedReturn, actualReturn);

        target.addAttributeID((char)26);
        expectedReturn = true;
        actualReturn = unknownAttributesAttribute.equals(target);
        assertEquals("Equals failed to recognize identical objects.",
                     expectedReturn, actualReturn);

    }

    /**
     * Tests that getAttribute() return the correct attribute id, preserving
     * entry order.
     */
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

        assertEquals("getAttribute() return value mismatch", expectedId1, actualId1);
        assertEquals("getAttribute() return value mismatch", expectedId2, actualId2);
    }

    /**
     * Add some attributes and test whether their number is properly calculated.
     * Tests duplicate id handling as well.
     */
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
        assertEquals("getAttributeCount did not return the expected value",
                     expectedReturn, actualReturn);
    }

    /**
     * Same as testGetAttributeID, only attribute attributes are extracted
     * through the getAttributes()'s iterator.
     */
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

        assertEquals("getAttributes() return value mismatch", expectedId1, actualId1);
        assertEquals("getAttributes() return value mismatch", expectedId2, actualId2);


    }

    /**
     * Adds a fixed number of attributes and checks data length accordingly.
     * Test is first performed for an odd number of attributes and then again
     * (after adding another attribute id). Both results should be the same.
     */
    public void testGetDataLength()
    {
        char expectedReturn = 8;

        unknownAttributesAttribute.addAttributeID((char)20);
        unknownAttributesAttribute.addAttributeID((char)21);
        unknownAttributesAttribute.addAttributeID((char)22);

        char actualReturn = unknownAttributesAttribute.getDataLength();
        assertEquals("Incorrect testGetDataLength() return value",
                     expectedReturn, actualReturn);

        unknownAttributesAttribute.addAttributeID((char)23);

        actualReturn = unknownAttributesAttribute.getDataLength();
        assertEquals("Incorrect testGetDataLength() return value",
                     expectedReturn, actualReturn);

    }

    /**
     * Tests whether getName returns a relevant name.
     */
    public void testGetName()
    {
        String expectedReturn = "UNKNOWN-ATTRIBUTES";
        String actualReturn = unknownAttributesAttribute.getName();
        assertEquals("getName() return", expectedReturn, actualReturn);
    }

}
