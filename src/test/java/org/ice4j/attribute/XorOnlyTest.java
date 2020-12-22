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
 * @author Emil Ivov
 */
public class XorOnlyTest
{
    private XorOnlyAttribute xorOnly = null;
    private MsgFixture msgFixture = null;

    @BeforeEach
    public void setUp() throws Exception
    {
        xorOnly = new XorOnlyAttribute();
        msgFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        xorOnly = null;
        msgFixture = null;
    }

    /**
     * Just makes sure that no exceptions are thrown when calling it as the
     * decode method doesn't do anything in the XorOnly att.
     * @throws StunException if sth happens
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        byte[] attributeValue = new byte[]{};
        char offset = 0;
        char length = 0;
        xorOnly.decodeAttributeBody(attributeValue, offset, length);
    }

    /**
     * Test encoding XorOnly attributes.
     */
    @Test
    public void testEncode()
    {
        byte[] expectedReturn = new byte[]{Attribute.XOR_ONLY>>8,
                                           Attribute.XOR_ONLY&0x00FF,
                                            0, 0};
        byte[] actualReturn = xorOnly.encode();
        assertArrayEquals(expectedReturn, actualReturn);
    }

    /**
     * Test positive and negative XorOnly.equals() returns
     * @throws Exception if decoding fails
     */
    @Test
    public void testEquals() throws Exception
    {
        XorOnlyAttribute xor2 = new XorOnlyAttribute();
        assertEquals(xorOnly, xor2);

        MappedAddressAttribute maatt =  new MappedAddressAttribute();
        maatt.decodeAttributeBody( msgFixture.mappedAddress,
                                   (char) 0,
                                   (char) msgFixture.mappedAddress.length );

        assertNotEquals(maatt, xorOnly);
        assertNotEquals(xorOnly, null);
    }

    /**
     * Makes sure the data langth is 0
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = 0;
        char actualReturn = xorOnly.getDataLength();
        assertEquals(expectedReturn, actualReturn, "data length was not 0");
    }

    /**
     * Verifies the name (do we really need this?).
     */
    @Test
    public void testGetName()
    {
        assertEquals("XOR-ONLY", xorOnly.getName());
    }
}
