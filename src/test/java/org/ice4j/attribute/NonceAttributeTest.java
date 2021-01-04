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
 * Tests the nonce attribute class.
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 */
public class NonceAttributeTest
{
    private NonceAttribute nonceAttribute = null;
    MsgFixture msgFixture = null;
    String nonceValue = "0123456789abcdef";
    byte[] attributeBinValue = new byte[]{
            (byte)(NonceAttribute.NONCE>>8),
            (byte)(NonceAttribute.NONCE & 0x00FF),
            0, (byte)nonceValue.length(),
            '0', '1', '2', '3', '4', '5', '6','7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    @BeforeEach
    public void setUp() throws Exception
    {
        msgFixture = new MsgFixture();
        nonceAttribute = new NonceAttribute();
        nonceAttribute.setNonce(nonceValue.getBytes());
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        nonceAttribute = null;
        msgFixture = null;
    }

    /**
     * Tests decoding of the nonce attribute.
     * @throws StunException upon a failure
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        char offset = 0;
        NonceAttribute decoded = new NonceAttribute();
        char length = (char)nonceValue.length();
        decoded.decodeAttributeBody(nonceValue.getBytes(), offset, length);

        //nonce value
        assertEquals(nonceAttribute, decoded, "decode failed");
    }

    /**
     * Tests the encode method
     */
    @Test
    public void testEncode()
    {
        assertArrayEquals(nonceAttribute.encode(), attributeBinValue,
            "encode failed");
    }

    /**
     * Test Equals
     */
    @Test
    public void testEquals()
    {
        NonceAttribute nonceAttribute2 = new NonceAttribute();
        nonceAttribute2.setNonce(nonceValue.getBytes());

        //test positive equals
        assertEquals(nonceAttribute, nonceAttribute2);

        //test negative equals
        nonceAttribute2 = new NonceAttribute();
        nonceAttribute2.setNonce("some other nonce".getBytes());

        //test positive equals
        assertNotEquals(nonceAttribute2, nonceAttribute);

        //test null equals
        assertNotEquals(nonceAttribute, null);
    }

    /**
     * Tests extracting data length
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = (char)nonceValue.length();
        char actualReturn = nonceAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn);
    }

    /**
     * Tests getting the name
     */
    @Test
    public void testGetName()
    {
        assertEquals("NONCE", nonceAttribute.getName());
    }

    @Test
    public void testSetGetNonce()
    {
        byte[] expectedReturn = nonceValue.getBytes();

        NonceAttribute att = new NonceAttribute();
        att.setNonce(expectedReturn);

        byte[] actualReturn = att.getNonce();
        assertArrayEquals(expectedReturn, actualReturn,
            "nonce setter or getter failed");
    }
}
