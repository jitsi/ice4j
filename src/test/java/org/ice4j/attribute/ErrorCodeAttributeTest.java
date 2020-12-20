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
 *
 * @author Emil Ivov
 */
public class ErrorCodeAttributeTest
{
    private ErrorCodeAttribute errorCodeAttribute = null;
    private MsgFixture msgFixture;

    @BeforeEach
    public void setUp() throws Exception
    {
        errorCodeAttribute = new ErrorCodeAttribute();
        msgFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception {
        errorCodeAttribute = null;
        msgFixture = null;
    }

    /**
     * Test Attribute type
     */
    @Test
    public void testErrorCodeAttribute()
    {
        errorCodeAttribute = new ErrorCodeAttribute();
        assertEquals(
            Attribute.ERROR_CODE,
            errorCodeAttribute.getAttributeType(),
            "ErrorCodeAttribute() constructed an attribute with an invalid type"
        );
    }

    /**
     * Test whether sample binary arrays are properly decoded.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testDecodeAttributeBody()
        throws StunException {
        byte[] attributeValue = msgFixture.errCodeTestValue;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(attributeValue.length - Attribute.HEADER_LENGTH);
        errorCodeAttribute.decodeAttributeBody(attributeValue, offset, length);

        assertEquals(
            MsgFixture.ERROR_CLASS,
            errorCodeAttribute.getErrorClass(),
            "Error Class was not correctly decoded"
        );

        assertEquals(
            MsgFixture.ERROR_NUMBER,
            errorCodeAttribute.getErrorNumber(),
            "Error Number was not correctly decoded"
        );

        assertEquals(
            MsgFixture.REASON_PHRASE.trim(),
            errorCodeAttribute.getReasonPhrase().trim(),
            "Reason phrase was not correctly decoded");
    }

    /**
     * Construct and encode a sample object and assert equality with a sample
     * binary array.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testEncode()
        throws StunException
    {
        byte[] expectedReturn = msgFixture.errCodeTestValue;

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setReasonPhrase(MsgFixture.REASON_PHRASE);

        byte[] actualReturn = errorCodeAttribute.encode();

        assertArrayEquals(expectedReturn, actualReturn,
            "encode() did not return the expected binary array.");
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testEquals()
        throws StunException
    {
        //null value test
        assertNotEquals(errorCodeAttribute, null,
            "equals() failed against a null value target.");

        //different objects
        ErrorCodeAttribute target;
        target = new ErrorCodeAttribute();

        target.setErrorClass(MsgFixture.ERROR_CLASS);
        target.setErrorNumber(MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass((byte)(MsgFixture.ERROR_CLASS+1));
        errorCodeAttribute.setErrorNumber((byte)(MsgFixture.ERROR_NUMBER+1));

        assertNotEquals(errorCodeAttribute, target,
            "equals() failed against a not equal target.");

        //equal objects
        target = new ErrorCodeAttribute();
        errorCodeAttribute = new ErrorCodeAttribute();

        target.setErrorClass(MsgFixture.ERROR_CLASS);
        target.setErrorNumber(MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);

        assertEquals(errorCodeAttribute, target,
            "equals() failed against an equal target.");
    }

    /**
     * Test whether data length is propertly calculated.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testGetDataLength()
        throws StunException
    {
        int expectedReturn = MsgFixture.REASON_PHRASE.getBytes().length
                            + 4; //error code specific header

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);
        errorCodeAttribute.setReasonPhrase(MsgFixture.REASON_PHRASE);

        char actualReturn = errorCodeAttribute.getDataLength();
        assertEquals(expectedReturn, actualReturn, "data length1");
    }

    /**
     * Test whether error code is properly calculated from error class and number
     */
    @Test
    public void testGetErrorCode()
    {
        char expectedReturn = (char)(100*MsgFixture.ERROR_CLASS
                                     + MsgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass(MsgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(MsgFixture.ERROR_NUMBER);

        char actualReturn = errorCodeAttribute.getErrorCode();
        assertEquals(expectedReturn, actualReturn);
    }

    /**
     * Test whether we get a proper name for that attribute.
     */
    @Test
    public void testGetName() {
        assertEquals("ERROR-CODE", errorCodeAttribute.getName());
    }

    /**
     * Test whether error code is properly calculated from error class and number
     *
     */
    @Test
    public void testSetErrorCode()
    {
        char errorCode = (char)(MsgFixture.ERROR_CLASS*100 + MsgFixture.ERROR_NUMBER);
        errorCodeAttribute.setErrorCode(errorCode);

        assertEquals(
            MsgFixture.ERROR_CLASS,
            (int) errorCodeAttribute.getErrorClass(),
            "An error class was not properly set after decoding an error code."
        );
        assertEquals(
            MsgFixture.ERROR_NUMBER,
            (int) errorCodeAttribute.getErrorNumber(),
            "An error number was not properly set after decoding an error code."
        );
    }
}
