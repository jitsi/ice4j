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
 * Tests the username attribute class.
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 */
public class UsernameAttributeTest extends TestCase
{
    private UsernameAttribute usernameAttribute = null;
    MsgFixture msgFixture = null;
    String usernameValue = "username";
    byte[] attributeBinValue = new byte[]{
            (byte)(UsernameAttribute.USERNAME>>8),
            (byte)(UsernameAttribute.USERNAME & 0x00FF),
            0, (byte)usernameValue.length(),
            'u', 's', 'e', 'r', 'n', 'a', 'm','e'};

    protected void setUp() throws Exception
    {
        super.setUp();
        msgFixture = new MsgFixture();

        usernameAttribute = new UsernameAttribute();
        usernameAttribute.setUsername(usernameValue.getBytes());

        msgFixture.setUp();
    }

    protected void tearDown() throws Exception
    {
        usernameAttribute = null;
        msgFixture.tearDown();

        msgFixture = null;
        super.tearDown();
    }

    /**
     * Tests decoding of the username attribute.
     * @throws StunException upon a failure
     */
    public void testDecodeAttributeBody() throws StunException
    {
        char offset = 0;
        UsernameAttribute decoded = new UsernameAttribute();
        char length = (char)usernameValue.length();
        decoded.decodeAttributeBody(usernameValue.getBytes(), offset, length);

        //username value
        assertEquals( "decode failed", usernameAttribute, decoded);
    }

    /**
     * Tests the encode method
     */
    public void testEncode()
    {
        assertTrue("encode failed",
                   Arrays.equals(usernameAttribute.encode(),
                                 attributeBinValue));
    }

    /**
     * Test Equals
     */
    public void testEquals()
    {
        UsernameAttribute usernameAttribute2 = new UsernameAttribute();
        usernameAttribute2.setUsername(usernameValue.getBytes());

        //test positive equals
        assertEquals("testequals failed", usernameAttribute, usernameAttribute2);

        //test negative equals
        usernameAttribute2 = new UsernameAttribute();
        usernameAttribute2.setUsername("some other username".getBytes());

        //test positive equals
        assertFalse("testequals failed",
                    usernameAttribute.equals(usernameAttribute2));

        //test null equals
        assertFalse("testequals failed",
                    usernameAttribute.equals(null));
    }

    /**
     * Tests extracting data length
     */
    public void testGetDataLength()
    {
        char expectedReturn = (char)usernameValue.length();
        char actualReturn = usernameAttribute.getDataLength();
        assertEquals("getDataLength - failed", expectedReturn, actualReturn);
    }

    /**
     * Tests getting the name
     */
    public void testGetName()
    {
        String expectedReturn = "USERNAME";
        String actualReturn = usernameAttribute.getName();
        assertEquals("getting name failed", expectedReturn, actualReturn);
    }

    public void testSetGetUsername()
    {
        byte[] expectedReturn = usernameValue.getBytes();

        UsernameAttribute att = new UsernameAttribute();
        att.setUsername(expectedReturn);

        byte[] actualReturn = att.getUsername();
        assertTrue("username setter or getter failed",
                     Arrays.equals( expectedReturn,
                                    actualReturn));
    }
}
