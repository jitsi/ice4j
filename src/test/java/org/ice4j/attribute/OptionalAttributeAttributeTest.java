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
public class OptionalAttributeAttributeTest
{
    private OptionalAttribute optionalAttribute = null;
    private MsgFixture msgFixture = null;
    byte[] expectedAttributeValue = null;

    @BeforeEach
    public void setUp() throws Exception
    {
        msgFixture = new MsgFixture();
        int offset = Attribute.HEADER_LENGTH;

        //init a sample body
        expectedAttributeValue =
            new byte[msgFixture.unknownOptionalAttribute.length - offset];

        System.arraycopy(msgFixture.unknownOptionalAttribute, offset,
                         expectedAttributeValue, 0,
                         expectedAttributeValue.length);

        optionalAttribute = new OptionalAttribute(
                                        msgFixture.optionalAttributeType);
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        optionalAttribute = null;
        expectedAttributeValue = null;
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * @throws StunException if anything goes wrong.
     */
    @Test
    public void testDecodeAttributeBody() throws StunException {

        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(msgFixture.unknownOptionalAttribute.length - offset);

        optionalAttribute.decodeAttributeBody(msgFixture.unknownOptionalAttribute,
                                              offset, length);

        assertArrayEquals(
            expectedAttributeValue, optionalAttribute.getBody(),
            "OptionalAttribute did not decode properly.");

        assertEquals(length, optionalAttribute.getDataLength(),
            "Length was not properly decoded");
    }

    /**
     * Test whether attributes are properly encoded
     */
    @Test
    public void testEncode()
    {
        optionalAttribute.setBody(expectedAttributeValue, 0,
                                  expectedAttributeValue.length);

        byte[] actualReturn = optionalAttribute.encode();
        assertArrayEquals(msgFixture.unknownOptionalAttribute, actualReturn);
    }

    /**
     * Test whether the equals method works ok
     */
    @Test
    public void testEquals()
    {
        //null comparison
        optionalAttribute.setBody( expectedAttributeValue, 0,
                                   expectedAttributeValue.length);

        assertNotEquals(optionalAttribute, null);

        //wrong type comparison
        assertNotEquals(optionalAttribute, "hehe :)");

        //succesful comparison
        OptionalAttribute obj =
            new OptionalAttribute(msgFixture.optionalAttributeType);

        obj.setBody( expectedAttributeValue, 0,
                                          expectedAttributeValue.length);
        assertEquals(obj, optionalAttribute);
    }

    @Test
    public void testGetDataLength()
    {
        char expectedReturn = (char)expectedAttributeValue.length;

        optionalAttribute.setBody( expectedAttributeValue, 0,
                                   expectedAttributeValue.length);

        char actualReturn = optionalAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn);
    }

}
