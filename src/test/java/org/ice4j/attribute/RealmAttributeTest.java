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
 * Tests the realm attribute class.
 *
 * @author Emil Ivov
 * @author Sebastien Vincent
 */
public class RealmAttributeTest
{
    private RealmAttribute realmAttribute = null;
    MsgFixture msgFixture = null;
    String realmValue = "domain.org";
    byte[] attributeBinValue = new byte[]{
            (byte)(RealmAttribute.REALM>>8),
            (byte)(RealmAttribute.REALM & 0x00FF),
            0, (byte)realmValue.length(),
            'd', 'o', 'm', 'a', 'i', 'n', '.', 'o', 'r', 'g', 0x00, 0x00};

    @BeforeEach
    public void setUp() throws Exception
    {
        msgFixture = new MsgFixture();

        realmAttribute = new RealmAttribute();
        realmAttribute.setRealm(realmValue.getBytes());
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        realmAttribute = null;
        msgFixture = null;
    }

    /**
     * Tests decoding of the realm attribute.
     * @throws StunException upon a failure
     */
    @Test
    public void testDecodeAttributeBody() throws StunException
    {
        char offset = 0;
        RealmAttribute decoded = new RealmAttribute();
        char length = (char)realmValue.length();
        decoded.decodeAttributeBody(realmValue.getBytes(), offset, length);

        //realm value
        assertEquals(realmAttribute, decoded);
    }

    /**
     * Tests the encode method
     */
    @Test
    public void testEncode()
    {
        assertArrayEquals(realmAttribute.encode(), attributeBinValue);
    }

    /**
     * Test Equals
     */
    @Test
    public void testEquals()
    {
        RealmAttribute realmAttribute2 = new RealmAttribute();
        realmAttribute2.setRealm(realmValue.getBytes());

        //test positive equals
        assertEquals(realmAttribute, realmAttribute2);

        //test negative equals
        realmAttribute2 = new RealmAttribute();
        realmAttribute2.setRealm("some other realm".getBytes());

        //test positive equals
        assertNotEquals(realmAttribute2, realmAttribute);

        //test null equals
        assertNotEquals(realmAttribute, null);
    }

    /**
     * Tests extracting data length
     */
    @Test
    public void testGetDataLength()
    {
        char expectedReturn = (char)realmValue.length();
        char actualReturn = realmAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn);
    }

    /**
     * Tests getting the name
     */
    @Test
    public void testGetName()
    {
        assertEquals("REALM", realmAttribute.getName());
    }

    @Test
    public void testSetGetRealm()
    {
        byte[] expectedReturn = realmValue.getBytes();

        RealmAttribute att = new RealmAttribute();
        att.setRealm(expectedReturn);

        byte[] actualReturn = att.getRealm();
        assertArrayEquals(expectedReturn, actualReturn,
            "realm setter or getter failed");
    }
}
