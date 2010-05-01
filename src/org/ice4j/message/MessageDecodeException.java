/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.message;

import org.ice4j.attribute.*;

/**
 * The {@link MessageDecodeException} is thrown during decoding in order
 * to indicate what problems there might have been with a particular incoming
 * message. The exception is particularly useful when decoding incoming requests
 * so that the stack could generate an appropriate error response.
 *
 * @author Emil Ivov
 */
public class MessageDecodeException
    extends Exception
{
    /**
     * Dummy version UID
     */
    static final long serialVersionUID = -1L;

    /**
     * The error code to use in case we do not want this exception to cause a
     * response and would prefer to discard instead.
     */
    public static int NO_RESPONSE = -1;

    /**
     * A STUN Error Response code to use if the message that caused the
     * exception was a {@link Request} and we could send an error response.
     */
    private int stunResponseCode = NO_RESPONSE;

    /**
     * An attribute to include in the error response.
     */
    private Attribute responseAttribute = null;

    /**
     * The ID of the transaction to use in case the exception allows for
     * sending an error response.
     */
    private byte[] transactionID = null;

    /**
     * Creates a new <tt>MessageDecodeException</tt> instance.
     *
     * @param message a text message explaining the exception
     */
    public MessageDecodeException(String message)
    {
        super(message);
    }

    /**
     * Creates a new <tt>MessageDecodeException</tt> instance.
     *
     * @param message a text message explaining the exception
     * @param cause A reference to a {@link Throwable} instance in case this
     * exception was caused by another, unexpected exception.
     */
    public MessageDecodeException(String    message,
                                  Throwable cause)
    {
        super(message, cause);
    }

    /**
     * Creates a new <tt>MessageDecodeException</tt> instance.
     *
     * @param message a text message explaining the exception
     * @param stunResponseCode a STUN Error Response code to use if the message
     * that caused the exception was a {@link Request} and we could send an
     * error response, or <tt>-1</tt> in case we should not reply.
     * @param transactionID the id of the transaction to use in an error
     * response.
     */
    public MessageDecodeException(String message,
                                  int    stunResponseCode,
                                  byte[] transactionID)
    {
        super(message);
        this.stunResponseCode = stunResponseCode;
        this.transactionID = transactionID;
    }

    /**
     * Creates a new <tt>MessageDecodeException</tt> instance.
     *
     * @param message a text message explaining the exception
     * @param stunResponseCode a STUN Error Response code to use if the message
     * that caused the exception was a {@link Request} and we could send an
     * error response, or <tt>-1</tt> in case we should not reply.
     * @param transactionID the id of the transaction to use in an error
     * response.
     * @param attribute the Attribute an attribute to include in the error
     * response.
     */
    public MessageDecodeException(String    message,
                                  int       stunResponseCode,
                                  byte[]    transactionID,
                                  Attribute attribute)
    {
        super(message);
        this.stunResponseCode = stunResponseCode;
        this.transactionID = transactionID;
    }


    /**
     * Returns a STUN Error Response code to use if the message that caused the
     * exception was a {@link Request} and we could send an error response.
     *
     * @return a STUN Error Response code to use if the message that caused the
     * exception was a {@link Request} and we could send an error response.
     */
    public int getErrorResponseCode()
    {
        return stunResponseCode;
    }

    /**
     * Returns whatever attribute would have to be included in a potential
     * error response like for example the attribute that cause a 420 error.
     *
     * @return  whatever attribute would have to be included in a potential
     * error response like for example the attribute that cause a 420 error.
     */
    public Attribute getResponseAttribute()
    {
        return responseAttribute;
    }

    /**
     * Returns the id of the transaction to use in an error response.
     *
     * @return the id of the transaction to use in an error response.
     */
    public byte[] getTransactionID()
    {
        return transactionID;
    }
}
