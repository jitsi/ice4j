/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import junit.framework.*;

import java.util.Arrays;

import org.ice4j.*;
import org.ice4j.attribute.*;

/**
 * @author Emil Ivov
 * @version 1.0
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
        obj = new String("hehe :)");
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
