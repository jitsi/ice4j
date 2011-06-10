/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

/**
 * The ERROR-CODE attribute is present in the Binding Error Response and
 * Shared Secret Error Response.  It is a numeric value in the range of
 * 100 to 699 plus a textual reason phrase encoded in UTF-8, and is
 * consistent in its code assignments and semantics with SIP [10] and
 * HTTP [15].  The reason phrase is meant for user consumption, and can
 * be anything appropriate for the response code.  The lengths of the
 * reason phrases MUST be a multiple of 4 (measured in bytes).  This can
 * be accomplished by added spaces to the end of the text, if necessary.
 * Recommended reason phrases for the defined response codes are
 * presented below.
 *
 * To facilitate processing, the class of the error code (the hundreds
 * digit) is encoded separately from the rest of the code.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   0                     |Class|     Number    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Reason Phrase (variable)                                ..
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The class represents the hundreds digit of the response code.  The
 * value MUST be between 1 and 6.  The number represents the response
 * code modulo 100, and its value MUST be between 0 and 99.
 *
 * The following response codes, along with their recommended reason
 * phrases (in brackets) are defined at this time:
 *
 * 400 (Bad Request): The request was malformed.  The client should not
 *      retry the request without modification from the previous
 *      attempt.
 *
 * 401 (Unauthorized): The Binding Request did not contain a MESSAGE-
 *      INTEGRITY attribute.
 *
 * 420 (Unknown Attribute): The server did not understand a mandatory
 *      attribute in the request.
 *
 * 430 (Stale Credentials): The Binding Request did contain a MESSAGE-
 *      INTEGRITY attribute, but it used a shared secret that has
 *      expired.  The client should obtain a new shared secret and try
 *      again.
 *
 * 431 (Integrity Check Failure): The Binding Request contained a
 *      MESSAGE-INTEGRITY attribute, but the HMAC failed verification.
 *      This could be a sign of a potential attack, or client
 *      implementation error.
 *
 * 432 (Missing Username): The Binding Request contained a MESSAGE-
 *      INTEGRITY attribute, but not a USERNAME attribute.  Both must be
 *      present for integrity checks.
 *
 * 433 (Use TLS): The Shared Secret request has to be sent over TLS, but
 *      was not received over TLS.
 *
 * 500 (Server Error): The server has suffered a temporary error. The
 *      client should try again.
 *
 * 600 (Global Failure:) The server is refusing to fulfill the request.
 *      The client should not retry.
 *
 * @author Emil Ivov
 */
public class ErrorCodeAttribute extends Attribute
{
    /**
     * Attribute's name.
     */
    public static final String NAME = "ERROR-CODE";

    // Common error codes
    /**
     * Bad request error code.
     */
    public static final char BAD_REQUEST   = 400;

    /**
     * Unauthorized error code.
     */
    public static final char UNAUTHORIZED  = 401;

    /**
     * Unknown attribute error code.
     */
    public static final char UNKNOWN_ATTRIBUTE = 420;

    /**
     * Stale credentials error code.
     */
    public static final char STALE_CREDENTIALS = 430;

    /**
     * Integrity check failure error code.
     */
    public static final char INTEGRITY_CHECK_FAILURE = 431;

    /**
     * Missing username error code.
     */
    public static final char MISSING_USERNAME = 432;

    /**
     * Use TLS error code.
     */
    public static final char USE_TLS = 433;

    /**
     * Role conflict error code.
     */
    public static final char ROLE_CONFLICT   = 487;

    /**
     * Server error code.
     */
    public static final char SERVER_ERROR = 500;

    /**
     * Global failure error code.
     */
    public static final char GLOBAL_FAILURE = 600;

    /**
     * The class represents the hundreds digit of the response code.  The
     * value MUST be between 1 and 6.
     */
    private byte errorClass = 0;

    /**
     * The number represents the response
     * code modulo 100, and its value MUST be between 0 and 99.
     */
    private byte errorNumber = 0;

    /**
     * The reason phrase is meant for user consumption, and can
     * be anything appropriate for the response code.
     */
    private byte[] reasonPhrase = null;

    /**
     * Constructs a new ERROR-CODE attribute
     */
    ErrorCodeAttribute()
    {
        super(ERROR_CODE);
    }

    /**
     * A convenience method that sets error class and number according to the
     * specified errorCode.The class represents the hundreds digit of the error
     * code. The value MUST be between 1 and 6.  The number represents the
     * response code modulo 100, and its value MUST be between 0 and 99.
     *
     * @param errorCode the errorCode that this class encapsulates.
     * @throws IllegalArgumentException if errorCode is not a valid error code.
     */
    public void setErrorCode(char errorCode)
        throws IllegalArgumentException
    {
        setErrorClass((byte)(errorCode / 100));
        setErrorNumber((byte)(errorCode % 100));
    }

    /**
     * A convenience method that constructs an error code from this Attribute's
     * class and number.
     * @return the code of the error this attribute represents.
     */
    public char getErrorCode()
    {
        return (char)(getErrorClass() * 100 + getErrorNumber());
    }

    /**
     * Sets this attribute's error number.
     * @param errorNumber the error number to assign this attribute.
     * @throws IllegalArgumentException if errorNumber is not a valid error
     * number.
     */
    public void setErrorNumber(byte errorNumber)
        throws IllegalArgumentException
    {
        /*
        if(errorNumber < 0 || errorNumber > 9999)
            throw new IllegalArgumentException(
                            errorNumber + " is not a valid error number!");
         */
        this.errorNumber = errorNumber;
    }

    /**
     * Returns this attribute's error number.
     * @return  this attribute's error number.
     */
    public byte getErrorNumber()
    {
        return this.errorNumber;
    }

    /**
     * Sets this error's error class.
     * @param errorClass this error's error class.
     * @throws IllegalArgumentException if errorClass is not a valid error
     * class.
     */
    public void setErrorClass(byte errorClass)
        throws IllegalArgumentException
    {
        if(errorClass < 0 || errorClass > 99)
            throw new IllegalArgumentException(
                errorClass + " is not a valid error number!");
        this.errorClass = errorClass;
    }

    /**
     * Returns this error's error class.
     * @return this error's error class.
     */
    public byte getErrorClass()
    {
        return errorClass;
    }

    /**
     * Returns a default reason phrase corresponding to the specified error
     * code, as described by rfc 3489.
     * @param errorCode the code of the error that the reason phrase must
     *                  describe.
     * @return a default reason phrase corresponding to the specified error
     * code, as described by rfc 3489.
     */
    public static String getDefaultReasonPhrase(char errorCode)
    {
        switch(errorCode)
        {
            case 400: return  "(Bad Request): The request was malformed.  The client should not "
                             +"retry the request without modification from the previous attempt.";
            case 401: return  "(Unauthorized): The Binding Request did not contain a MESSAGE-"
                             +"INTEGRITY attribute.";
            case 420: return  "(Unknown Attribute): The server did not understand a mandatory "
                             +"attribute in the request.";
            case 430: return  "(Stale Credentials): The Binding Request did contain a MESSAGE-"
                             +"INTEGRITY attribute, but it used a shared secret that has "
                             +"expired.  The client should obtain a new shared secret and try"
                             +"again";
            case 431: return  "(Integrity Check Failure): The Binding Request contained a "
                             +"MESSAGE-INTEGRITY attribute, but the HMAC failed verification. "
                             +"This could be a sign of a potential attack, or client "
                             +"implementation error.";
            case 432: return  "(Missing Username): The Binding Request contained a MESSAGE-"
                             +"INTEGRITY attribute, but not a USERNAME attribute.  Both must be"
                             +"present for integrity checks.";
            case 433: return  "(Use TLS): The Shared Secret request has to be sent over TLS, but"
                             +"was not received over TLS.";
            case 500: return  "(Server Error): The server has suffered a temporary error. The"
                             +"client should try again.";
            case 600: return "(Global Failure:) The server is refusing to fulfill the request."
                             +"The client should not retry.";

            default:  return "Unknown Error";
        }
    }

    /**
     * Set's a reason phrase. The reason phrase is meant for user consumption,
     * and can be anything appropriate for the response code.  The lengths of
     * the reason phrases MUST be a multiple of 4 (measured in bytes).
     *
     * @param reasonPhrase a reason phrase that describes this error.
     */
    public void setReasonPhrase(String reasonPhrase)
    {
        this.reasonPhrase = reasonPhrase.getBytes();
    }

    /**
     * Returns the reason phrase. The reason phrase is meant for user consumption,
     * and can be anything appropriate for the response code.  The lengths of
     * the reason phrases MUST be a multiple of 4 (measured in bytes).
     *
     * @return reasonPhrase a reason phrase that describes this error.
     */
    public String getReasonPhrase()
    {
        if(reasonPhrase == null)
            return null;

        return new String(reasonPhrase);
    }

    /**
     * Returns the human readable name of this attribute. Attribute names do
     * not really matter from the protocol point of view. They are only used
     * for debugging and readability.
     * @return this attribute's name.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Returns the length of this attribute's body.
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        char len = (char)(4 //error code numbers
           + (char)(reasonPhrase == null ? 0 : reasonPhrase.length));

        return len;
    }

    /**
     * Returns a binary representation of this attribute.
     * @return a binary representation of this attribute.
     */
    public byte[] encode()
    {
        byte binValue[] =  new byte[HEADER_LENGTH + getDataLength()
                                    //add padding
                                    + (4 - getDataLength() % 4) % 4];

        //Type
        binValue[0] = (byte) (getAttributeType() >> 8);
        binValue[1] = (byte) (getAttributeType() & 0x00FF);
        //Length
        binValue[2] = (byte) (getDataLength() >> 8);
        binValue[3] = (byte) (getDataLength() & 0x00FF);

        //Not used
        binValue[4] = 0x00;
        binValue[5] = 0x00;

        //Error code
        binValue[6] = getErrorClass();
        binValue[7] = getErrorNumber();

        if(reasonPhrase != null)
            System.arraycopy(reasonPhrase, 0, binValue, 8, reasonPhrase.length);

        return binValue;
    }

    /**
     * Compares two STUN Attributes. Attributes are considered equal when their
     * type, length, and all data are the same.
     *
     * @param obj the object to compare this attribute with.
     * @return true if the attributes are equal and false otherwise.
     */
     public boolean equals(Object obj)
     {
         if (! (obj instanceof ErrorCodeAttribute)
             || obj == null)
             return false;

         if (obj == this)
             return true;

         ErrorCodeAttribute att = (ErrorCodeAttribute) obj;
         if (att.getAttributeType() != getAttributeType()
             || att.getDataLength() != getDataLength()
             //compare data
             || att.getErrorClass() != getErrorClass()
             || att.getErrorNumber()!= getErrorNumber()
             || ( att.getReasonPhrase() != null
                  && !att.getReasonPhrase().equals(getReasonPhrase()))
             )
             return false;

         return true;
    }

    /**
     * Sets this attribute's fields according to attributeValue array.
     *
     * @param attributeValue a binary array containing this attribute's field
     *                       values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     *                  offset is equal to the index of the first byte after
     *                  length)
     * @param length the length of the binary array.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
    {

        offset += 2; //skip the 0s

        //Error code
        setErrorClass(attributeValue[offset++]);
        setErrorNumber(attributeValue[offset++]);

        //Reason Phrase
        byte[] reasonBytes = new byte[length - 4];

        System.arraycopy(attributeValue, offset, reasonBytes,
                            0, reasonBytes.length);
        setReasonPhrase(new String(reasonBytes));
    }
}
