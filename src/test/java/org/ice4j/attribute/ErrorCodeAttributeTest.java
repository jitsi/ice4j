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
 *
 * @author Emil Ivov
 */
public class ErrorCodeAttributeTest extends TestCase {
    private ErrorCodeAttribute errorCodeAttribute = null;
    private MsgFixture msgFixture;

    public ErrorCodeAttributeTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        super.setUp();
        errorCodeAttribute = new ErrorCodeAttribute();
        msgFixture = new MsgFixture();

        msgFixture.setUp();
    }

    protected void tearDown() throws Exception {
        errorCodeAttribute = null;
        msgFixture.tearDown();

        msgFixture = null;
        super.tearDown();
    }

    /**
     * Test Attribute type
     */
    public void testErrorCodeAttribute()
    {

        errorCodeAttribute = new ErrorCodeAttribute();

        assertEquals("ErrorCodeAttribute() constructed an attribute with an invalid type",
                     Attribute.ERROR_CODE,
                     errorCodeAttribute.getAttributeType());
    }

    /**
     * Test whether sample binary arrays are properly decoded.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testDecodeAttributeBody()
        throws StunException {
        byte[] attributeValue = msgFixture.errCodeTestValue;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(attributeValue.length - Attribute.HEADER_LENGTH);
        errorCodeAttribute.decodeAttributeBody(attributeValue, offset, length);

        assertEquals("Error Class was not correctly decoded",
                     MsgFixture.ERROR_CLASS,
                     errorCodeAttribute.getErrorClass());

        assertEquals("Error Number was not correctly decoded",
                     MsgFixture.ERROR_NUMBER,
                     errorCodeAttribute.getErrorNumber());

        assertEquals("Reason phrase was not correctly decoded",
                     MsgFixture.REASON_PHRASE.trim(),
                     errorCodeAttribute.getReasonPhrase().trim());

    }

    /**
     * Construct and encode a sample object and assert equality with a sample
     * binary array.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testEncode()
        throws StunException
    {
        byte[] expectedReturn = msgFixture.errCodeTestValue;

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setReasonPhrase(MsgFixture.REASON_PHRASE);

        byte[] actualReturn = errorCodeAttribute.encode();

        assertTrue("encode() did not return the expected binary array.",
                   Arrays.equals( expectedReturn, actualReturn));
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testEquals()
        throws StunException
    {

        //null value test
        ErrorCodeAttribute target = null;
        boolean expectedReturn = false;
        boolean actualReturn = errorCodeAttribute.equals(target);
        assertEquals("equals() failed against a null value target.",
                     expectedReturn, actualReturn);

        //different objects
        target = new ErrorCodeAttribute();
        expectedReturn = false;

        target.setErrorClass(MsgFixture.ERROR_CLASS);
        target.setErrorNumber(MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass((byte)(MsgFixture.ERROR_CLASS+1));
        errorCodeAttribute.setErrorNumber((byte)(MsgFixture.ERROR_NUMBER+1));

        actualReturn = errorCodeAttribute.equals(target);
        assertEquals("equals() failed against a not equal target.",
                     expectedReturn, actualReturn);

        //different objects
        target = new ErrorCodeAttribute();
        errorCodeAttribute = new ErrorCodeAttribute();
        expectedReturn = true;

        target.setErrorClass(MsgFixture.ERROR_CLASS);
        target.setErrorNumber(MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);

        actualReturn = errorCodeAttribute.equals(target);
        assertEquals("equals() failed against a not equal target.",
                     expectedReturn, actualReturn);


    }

    /**
     * Test whether data length is propertly calculated.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testGetDataLength()
        throws StunException
    {
        int expectedReturn = MsgFixture.REASON_PHRASE.getBytes().length
                            + 4; //error code specific header

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);
        errorCodeAttribute.setReasonPhrase(MsgFixture.REASON_PHRASE);

        char actualReturn = errorCodeAttribute.getDataLength();
        assertEquals("data length1", expectedReturn, actualReturn);
    }

    /**
     * Test whether error code is properly calculated from error class and number
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testGetErrorCode()
        throws StunException
    {
        char expectedReturn = (char)(100*MsgFixture.ERROR_CLASS
                                     + MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);

        char actualReturn = errorCodeAttribute.getErrorCode();
        assertEquals("return value", expectedReturn, actualReturn);
    }

    /**
     * Test whether we get a proper name for that attribute.
     */
    public void testGetName() {
        String expectedReturn = "ERROR-CODE";
        String actualReturn = errorCodeAttribute.getName();
        assertEquals("return value", expectedReturn, actualReturn);

    }

    /**
     * Test whether error code is properly calculated from error class and number
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testSetErrorCode() throws StunException {
        char errorCode = (char)(MsgFixture.ERROR_CLASS*100 + MsgFixture.ERROR_NUMBER);
        errorCodeAttribute.setErrorCode(errorCode);

        assertEquals("An error class was not properly set after decoding an error code.",
                     (int)MsgFixture.ERROR_CLASS,
                     (int)errorCodeAttribute.getErrorClass());
        assertEquals("An error number was not properly set after decoding an error code.",
                     (int)MsgFixture.ERROR_NUMBER,
                     (int)errorCodeAttribute.getErrorNumber());
    }


}
