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
 * Tests the username attribute class.
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 */
public class UsernameAttributeTest
{
    private UsernameAttribute usernameAttribute = null;
    MsgFixture msgFixture = null;
    String usernameValue = "username";
    byte[] attributeBinValue = new byte[]{
            (byte)(UsernameAttribute.USERNAME>>8),
            (byte)(UsernameAttribute.USERNAME & 0x00FF),
            0, (byte)usernameValue.length(),
            'u', 's', 'e', 'r', 'n', 'a', 'm','e'};

    @BeforeEach
    public void setUp() throws Exception
    {
        msgFixture = new MsgFixture();

        usernameAttribute = new UsernameAttribute();
        usernameAttribute.setUsername(usernameValue.getBytes());
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        usernameAttribute = null;
        msgFixture = null;
    }

    /**
     * Tests decoding of the username attribute.
     * @throws StunException upon a failure
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        char offset = 0;
        UsernameAttribute decoded = new UsernameAttribute();
        char length = (char)usernameValue.length();
        decoded.decodeAttributeBody(usernameValue.getBytes(), offset, length);

        //username value
        assertEquals(usernameAttribute, decoded);
    }

    /**
     * Tests the encode method
     */
    @Test
    public void testEncode()
    {
        assertArrayEquals(usernameAttribute.encode(), attributeBinValue);
    }

    /**
     * Test Equals
     */
    @Test
    public void testEquals()
    {
        UsernameAttribute usernameAttribute2 = new UsernameAttribute();
        usernameAttribute2.setUsername(usernameValue.getBytes());

        //test positive equals
        assertEquals(usernameAttribute, usernameAttribute2);

        //test negative equals
        usernameAttribute2 = new UsernameAttribute();
        usernameAttribute2.setUsername("some other username".getBytes());

        //test positive equals
        assertNotEquals(usernameAttribute2, usernameAttribute);

        //test null equals
        assertNotEquals(usernameAttribute, null);
    }

    /**
     * Tests extracting data length
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = (char)usernameValue.length();
        char actualReturn = usernameAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn);
    }

    /**
     * Tests getting the name
     */
    @Test
    public void testGetName()
    {
        assertEquals("USERNAME", usernameAttribute.getName());
    }

    @Test
    public void testSetGetUsername()
    {
        byte[] expectedReturn = usernameValue.getBytes();

        UsernameAttribute att = new UsernameAttribute();
        att.setUsername(expectedReturn);

        byte[] actualReturn = att.getUsername();
        assertArrayEquals(expectedReturn, actualReturn,
            "username setter or getter failed");
    }
}
