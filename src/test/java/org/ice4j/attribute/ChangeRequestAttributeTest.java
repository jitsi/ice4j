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
 * Tests the CHANGE-REQUEST attribute class.
 *
 * @author Emil Ivov
 */
public class ChangeRequestAttributeTest
{
    private ChangeRequestAttribute changeRequestAttribute = null;
    private MsgFixture binMessagesFixture;

    @BeforeEach
    public void setUp() throws Exception
    {
        changeRequestAttribute = new ChangeRequestAttribute();
        binMessagesFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        changeRequestAttribute = null;
        binMessagesFixture = null;
    }

    /**
     * Test whether the constructed object has the proper type.
     */
    @Test
    public void testChangeRequestAttribute()
    {
        changeRequestAttribute = new ChangeRequestAttribute();

        assertEquals(
            changeRequestAttribute.getAttributeType(),
            Attribute.CHANGE_REQUEST,
            "ChangeRequestAttribute did not construct an attribute with the correct type."
        );

    }

    /**
     * Test whether sample binary arrays are properly decoded.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testDecodeAttributeBody()
        throws StunException
    {
        byte[] attributeValue = binMessagesFixture.chngReqTestValue1;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(attributeValue.length - offset);
        changeRequestAttribute.decodeAttributeBody(attributeValue, offset, length);

        assertEquals(
            MsgFixture.CHANGE_IP_FLAG_1,
            changeRequestAttribute.getChangeIpFlag(),
            "decodeAttributeBody() did not properly decode the changeIpFlag"
        );
        assertEquals(
            MsgFixture.CHANGE_PORT_FLAG_1,
            changeRequestAttribute.getChangePortFlag(),
            "decodeAttributeBody() did not properly decode the changePortFlag"
        );

        //2nd sample
        attributeValue = binMessagesFixture.chngReqTestValue2;
        changeRequestAttribute
            .decodeAttributeBody(attributeValue, offset, length);
        assertEquals(
            MsgFixture.CHANGE_IP_FLAG_2,
            changeRequestAttribute.getChangeIpFlag(),
            "decodeAttributeBody() did not properly decode the changeIpFlag"
        );
        assertEquals(
            MsgFixture.CHANGE_PORT_FLAG_2,
            changeRequestAttribute.getChangePortFlag(),
            "decodeAttributeBody() did not properly decode the changePortFlag"
        );

        changeRequestAttribute.getChangePortFlag();
    }

    /**
     * Create sample objects and test whether they encode properly.
     */
    @Test
    public void testEncode()
    {
        byte[] expectedReturn = binMessagesFixture.chngReqTestValue1;

        changeRequestAttribute = new ChangeRequestAttribute();

        changeRequestAttribute.setChangeIpFlag(MsgFixture.CHANGE_IP_FLAG_1);
        changeRequestAttribute.setChangePortFlag(MsgFixture.CHANGE_PORT_FLAG_1);

        byte[] actualReturn = changeRequestAttribute.encode();
        assertArrayEquals(expectedReturn, actualReturn,
            "Object did not encode properly.");

        //2nd test
        expectedReturn = binMessagesFixture.chngReqTestValue2;
        changeRequestAttribute = new ChangeRequestAttribute();

        changeRequestAttribute.setChangeIpFlag(MsgFixture.CHANGE_IP_FLAG_2);
        changeRequestAttribute.setChangePortFlag(MsgFixture.CHANGE_PORT_FLAG_2);

        actualReturn = changeRequestAttribute.encode();
        assertArrayEquals(expectedReturn, actualReturn,
            "Object did not encode properly.");
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     */
    @Test
    public void testEquals()
    {
        //null test
        assertNotEquals(changeRequestAttribute, null);

        //test against a different object.
        ChangeRequestAttribute target = new ChangeRequestAttribute();

        changeRequestAttribute.setChangeIpFlag(true);
        changeRequestAttribute.setChangePortFlag(false);

        target.setChangeIpFlag(false);
        target.setChangePortFlag(true);

        assertNotEquals(changeRequestAttribute, target);

        //test against an equal value
        target = new ChangeRequestAttribute();

        changeRequestAttribute.setChangeIpFlag(true);
        changeRequestAttribute.setChangePortFlag(false);

        target.setChangeIpFlag(true);
        target.setChangePortFlag(false);
        assertEquals(changeRequestAttribute, target);
    }

    /**
     * Test whether the returned value is always 4.
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = 4; // constant 4 bytes of data
        char actualReturn = changeRequestAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn,
            "data length returned an invalid value");
    }

    /**
     * Test whether we get a relevant name.
     */
    @Test
    public void testGetName()
    {
        assertEquals("CHANGE-REQUEST", changeRequestAttribute.getName());
    }
}
