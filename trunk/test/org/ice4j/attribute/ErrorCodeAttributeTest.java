/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import junit.framework.*;

import java.util.Arrays;

import org.ice4j.*;
import org.ice4j.attribute.*;

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
                     msgFixture.ERROR_CLASS,
                     errorCodeAttribute.getErrorClass());

        assertEquals("Error Number was not correctly decoded",
                     msgFixture.ERROR_NUMBER,
                     errorCodeAttribute.getErrorNumber());

        assertEquals("Reason phrase was not correctly decoded",
                     msgFixture.REASON_PHRASE.trim(),
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

        errorCodeAttribute.setErrorClass(msgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(msgFixture.ERROR_NUMBER);

        errorCodeAttribute.setReasonPhrase(msgFixture.REASON_PHRASE);

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

        target.setErrorClass(msgFixture.ERROR_CLASS);
        target.setErrorNumber(msgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass((byte)(msgFixture.ERROR_CLASS+1));
        errorCodeAttribute.setErrorNumber((byte)(msgFixture.ERROR_NUMBER+1));

        actualReturn = errorCodeAttribute.equals(target);
        assertEquals("equals() failed against a not equal target.",
                     expectedReturn, actualReturn);

        //different objects
        target = new ErrorCodeAttribute();
        errorCodeAttribute = new ErrorCodeAttribute();
        expectedReturn = true;

        target.setErrorClass(msgFixture.ERROR_CLASS);
        target.setErrorNumber(msgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass(msgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(msgFixture.ERROR_NUMBER);

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
        char expectedReturn =
                     (char)(msgFixture.errCodeTestValue.length
                            - Attribute.HEADER_LENGTH);

        errorCodeAttribute.setErrorClass(msgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(msgFixture.ERROR_NUMBER);
        errorCodeAttribute.setReasonPhrase(msgFixture.REASON_PHRASE);

        char actualReturn = errorCodeAttribute.getDataLength();
        assertEquals("return value", expectedReturn, actualReturn);
    }

    /**
     * Test whether error code is properly calculated from error class and number
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testGetErrorCode()
        throws StunException
    {
        char expectedReturn = (char)(100*msgFixture.ERROR_CLASS
                                     + msgFixture.ERROR_NUMBER);

        errorCodeAttribute.setErrorClass(msgFixture.ERROR_CLASS);
        errorCodeAttribute.setErrorNumber(msgFixture.ERROR_NUMBER);

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
        char errorCode = (char)(msgFixture.ERROR_CLASS*100 + msgFixture.ERROR_NUMBER);
        errorCodeAttribute.setErrorCode(errorCode);

        assertEquals("An error class was not properly set after decoding an error code.",
                     (int)msgFixture.ERROR_CLASS,
                     (int)errorCodeAttribute.getErrorClass());
        assertEquals("An error number was not properly set after decoding an error code.",
                     (int)msgFixture.ERROR_NUMBER,
                     (int)errorCodeAttribute.getErrorNumber());
    }


}
