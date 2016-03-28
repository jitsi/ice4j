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

import java.util.Arrays;

import org.ice4j.*;

/**
 * @author Emil Ivov
 */
public class OptionalAttributeAttributeTest extends TestCase
{
    private OptionalAttribute optionalAttribute = null;
    private MsgFixture msgFixture = null;
    byte[] expectedAttributeValue = null;

    protected void setUp() throws Exception
    {
        super.setUp();

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

    protected void tearDown() throws Exception
    {
        optionalAttribute = null;
        expectedAttributeValue = null;
        super.tearDown();
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     * @throws StunException if anything goes wrong.
     */
    public void testDecodeAttributeBody() throws StunException {

        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(msgFixture.unknownOptionalAttribute.length - offset);

        optionalAttribute.decodeAttributeBody(msgFixture.unknownOptionalAttribute,
                                              offset, length);


        assertTrue("OptionalAttribute did not decode properly.",
                     Arrays.equals( expectedAttributeValue,
                                    optionalAttribute.getBody()));

        assertEquals("Lenght was not properly decoded", length,
                     optionalAttribute.getDataLength());

    }

    /**
     * Test whether attributes are properly encoded
     */
    public void testEncode()
    {
        optionalAttribute.setBody(expectedAttributeValue, 0,
                                  expectedAttributeValue.length);

        byte[] actualReturn = optionalAttribute.encode();

        assertTrue("encode failed",
                  Arrays.equals( msgFixture.unknownOptionalAttribute, actualReturn) );
    }

    /**
     * Test whether the equals method works ok
     */
    public void testEquals()
    {
        //null comparison
        Object obj = null;
        boolean expectedReturn = false;
        optionalAttribute.setBody( expectedAttributeValue, 0,
                                   expectedAttributeValue.length);

        boolean actualReturn = optionalAttribute.equals(obj);
        assertEquals("failed null comparison", expectedReturn, actualReturn);

        //wrong type comparison
        obj = "hehe :)";
        actualReturn = optionalAttribute.equals(obj);
        assertEquals("failed wrong type comparison", expectedReturn,
                     actualReturn);

        //succesful comparison
        obj = new OptionalAttribute(msgFixture.optionalAttributeType);

        ((OptionalAttribute)obj).setBody( expectedAttributeValue, 0,
                                          expectedAttributeValue.length);
        expectedReturn = true;
        actualReturn = optionalAttribute.equals(obj);
        assertEquals("failed null comparison", expectedReturn, actualReturn);
    }

    public void testGetDataLength()
    {
        char expectedReturn = (char)expectedAttributeValue.length;

        optionalAttribute.setBody( expectedAttributeValue, 0,
                                   expectedAttributeValue.length);

        char actualReturn = optionalAttribute.getDataLength();
        assertEquals("return value", expectedReturn, actualReturn);
    }

}
