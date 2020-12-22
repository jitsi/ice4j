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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.*;
/**
 * Class to test the ConnectionIdAttribute class.
 * 
 * @author Aakash Garg
 * 
 */
public class ConnectionIdAttributeTest
{
    private ConnectionIdAttribute connectionIdAttribute = null;

    private MsgFixture msgFixture;

    @BeforeEach
    public void setUp() throws Exception
    {
        this.connectionIdAttribute = new ConnectionIdAttribute();
        this.msgFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        this.connectionIdAttribute = null;
        this.msgFixture = null;
    }

    /**
     * Tests whether data length is properly calculated.
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = 4;
        this.connectionIdAttribute
            .setConnectionIdValue(MsgFixture.CONNECTION_ID);
        char actualReturn = this.connectionIdAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn,
            "Datalength is not properly calculated");
    }

    /**
     * Tests getting the name.
     */
    @Test
    public void testGetName()
    {
        assertEquals("CONNECTION-ID", connectionIdAttribute.getName());
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     */
    @Test
    public void testEqualsObject()
    {
        // null test
        assertNotEquals(connectionIdAttribute, null);

        // difference test
        ConnectionIdAttribute target = new ConnectionIdAttribute();

        int connectionId = MsgFixture.CONNECTION_ID_2;
        target.setConnectionIdValue(connectionId);

        connectionIdAttribute.setConnectionIdValue(MsgFixture.CONNECTION_ID);
        assertNotEquals(connectionIdAttribute, target,
            "ConnectionIdAttribute.equals() failed against a different target.");

        // equality test
        target.setConnectionIdValue(MsgFixture.CONNECTION_ID);
        assertEquals(connectionIdAttribute, target,
            "ConnectionIdAttribute.equals() failed against an equal target.");
    }

    /**
     * Test whether attributes are properly encoded.
     */
    @Test
    public void testEncode()
    {
        byte[] expectedReturn = msgFixture.connectionId;
        connectionIdAttribute.setConnectionIdValue(MsgFixture.CONNECTION_ID);
        byte[] actualReturn = connectionIdAttribute.encode();

        assertArrayEquals(expectedReturn, actualReturn,
            "ConnectionIdAttribute.encode() did not properly encode a sample attribute");
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * 
     * @throws StunException if something goes wrong while decoding 
     *             Attribute Body.
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        byte[] attributeValue = msgFixture.connectionId;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char) (attributeValue.length - offset);

        connectionIdAttribute.decodeAttributeBody(
            attributeValue, offset, length);

        assertEquals(
            MsgFixture.CONNECTION_ID,
            connectionIdAttribute.getConnectionIdValue(),
            "ConnectionIdAttribute.decode() did not properly decode the connection id field."
        );
    }

    /**
     * Tests that the connection Id is always integer.
     */
    @Test
    public void testGetConnectionIdValue()
    {
        int expectedReturn = 0x5555;
        this.connectionIdAttribute
            .setConnectionIdValue(MsgFixture.CONNECTION_ID);
        int actualReturn = this.connectionIdAttribute.getConnectionIdValue();
        assertEquals(expectedReturn, actualReturn,
            "ConnectionId is not properly calculated");

        expectedReturn = 0x2222;
        this.connectionIdAttribute
            .setConnectionIdValue(MsgFixture.CONNECTION_ID_2);
        actualReturn = this.connectionIdAttribute.getConnectionIdValue();
        assertEquals(expectedReturn, actualReturn,
            "ConnectionId is not properly calculated");
    }

}
