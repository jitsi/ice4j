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
 * Tests the software attribute class.
 *
 * @author Emil Ivov
 */
public class SoftwareAttributeTest {
    private SoftwareAttribute softwareAttribute = null;
    MsgFixture msgFixture = null;
    String softwareValue = "turnserver.org";
    byte[] attributeBinValue = new byte[]{
            (byte)(SoftwareAttribute.SOFTWARE>>8),
            (byte)(SoftwareAttribute.SOFTWARE & 0x00FF),
            0, (byte)softwareValue.length(),
            't', 'u', 'r', 'n', 's', 'e', 'r','v', 'e', 'r', '.', 'o', 'r', 'g',
            0x00, 0x00};

    @BeforeEach
    public void setUp() throws Exception
    {
        msgFixture = new MsgFixture();

        softwareAttribute = new SoftwareAttribute();
        softwareAttribute.setSoftware(softwareValue.getBytes());
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        softwareAttribute = null;
        msgFixture = null;
    }

    /**
     * Tests decoding of the software attribute.
     * @throws StunException upon a failure
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        char offset = 0;
        SoftwareAttribute decoded = new SoftwareAttribute();
        char length = (char)softwareValue.length();
        decoded.decodeAttributeBody(softwareValue.getBytes(), offset, length);

        //software value
        assertEquals(softwareAttribute, decoded);
    }

    /**
     * Tests the encode method
     */
    @Test
    public void testEncode()
    {
        assertArrayEquals(softwareAttribute.encode(), attributeBinValue);
    }

    /**
     * Test Equals
     */
    @Test
    public void testEquals()
    {
        SoftwareAttribute softwareAttribute2 = new SoftwareAttribute();
        softwareAttribute2.setSoftware(softwareValue.getBytes());

        //test positive equals
        assertEquals(softwareAttribute, softwareAttribute2);

        //test negative equals
        softwareAttribute2 = new SoftwareAttribute();
        softwareAttribute2.setSoftware("some other software".getBytes());

        //test positive equals
        assertNotEquals(softwareAttribute2, softwareAttribute);

        //test null equals
        assertNotEquals(softwareAttribute, null);
    }

    /**
     * Tests extracting data length
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = (char)softwareValue.length();
        char actualReturn = softwareAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn);
    }

    /**
     * Tests getting the name
     */
    @Test
    public void testGetName()
    {
        assertEquals("SOFTWARE", softwareAttribute.getName());
    }

    @Test
    public void testSetGetSoftware()
    {
        byte[] expectedReturn = softwareValue.getBytes();

        SoftwareAttribute att = new SoftwareAttribute();
        att.setSoftware(expectedReturn);

        byte[] actualReturn = att.getSoftware();
        assertArrayEquals(expectedReturn, actualReturn,
            "software setter or getter failed");
    }
}
