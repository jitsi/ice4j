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
 * Tests the software attribute class.
 *
 * @author Emil Ivov
 */
public class SoftwareAttributeTest extends TestCase
{
    private SoftwareAttribute softwareAttribute = null;
    MsgFixture msgFixture = null;
    String softwareValue = "turnserver.org";
    byte[] attributeBinValue = new byte[]{
            (byte)(SoftwareAttribute.SOFTWARE>>8),
            (byte)(SoftwareAttribute.SOFTWARE & 0x00FF),
            0, (byte)softwareValue.length(),
            't', 'u', 'r', 'n', 's', 'e', 'r','v', 'e', 'r', '.', 'o', 'r', 'g',
            0x00, 0x00};

    protected void setUp() throws Exception
    {
        super.setUp();
        msgFixture = new MsgFixture();

        softwareAttribute = new SoftwareAttribute();
        softwareAttribute.setSoftware(softwareValue.getBytes());

        msgFixture.setUp();
    }

    protected void tearDown() throws Exception
    {
        softwareAttribute = null;
        msgFixture.tearDown();

        msgFixture = null;
        super.tearDown();
    }

    /**
     * Tests decoding of the software attribute.
     * @throws StunException upon a failure
     */
    public void testDecodeAttributeBody() throws StunException
    {
        char offset = 0;
        SoftwareAttribute decoded = new SoftwareAttribute();
        char length = (char)softwareValue.length();
        decoded.decodeAttributeBody(softwareValue.getBytes(), offset, length);

        //software value
        assertEquals( "decode failed", softwareAttribute, decoded);
    }

    /**
     * Tests the encode method
     */
    public void testEncode()
    {
        assertTrue("encode failed",
                   Arrays.equals(softwareAttribute.encode(),
                                 attributeBinValue));
    }

    /**
     * Test Equals
     */
    public void testEquals()
    {
        SoftwareAttribute softwareAttribute2 = new SoftwareAttribute();
        softwareAttribute2.setSoftware(softwareValue.getBytes());

        //test positive equals
        assertEquals("testequals failed", softwareAttribute, softwareAttribute2);

        //test negative equals
        softwareAttribute2 = new SoftwareAttribute();
        softwareAttribute2.setSoftware("some other software".getBytes());

        //test positive equals
        assertFalse("testequals failed",
                    softwareAttribute.equals(softwareAttribute2));

        //test null equals
        assertFalse("testequals failed",
                    softwareAttribute.equals(null));
    }

    /**
     * Tests extracting data length
     */
    public void testGetDataLength()
    {
        char expectedReturn = (char)softwareValue.length();
        char actualReturn = softwareAttribute.getDataLength();
        assertEquals("getDataLength - failed", expectedReturn, actualReturn);
    }

    /**
     * Tests getting the name
     */
    public void testGetName()
    {
        String expectedReturn = "SOFTWARE";
        String actualReturn = softwareAttribute.getName();
        assertEquals("getting name failed", expectedReturn, actualReturn);
    }

    public void testSetGetSoftware()
    {
        byte[] expectedReturn = softwareValue.getBytes();

        SoftwareAttribute att = new SoftwareAttribute();
        att.setSoftware(expectedReturn);

        byte[] actualReturn = att.getSoftware();
        assertTrue("software setter or getter failed",
                     Arrays.equals( expectedReturn,
                                    actualReturn));
    }
}
