/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import java.util.*;
import java.util.zip.*;

import org.ice4j.*;

/**
 * The FINGERPRINT attribute is used to distinguish STUN packets from packets
 * of other protocols. It MAY be present in all STUN messages.  The
 * value of the attribute is computed as the CRC-32 of the STUN message
 * up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
 * the 32-bit value 0x5354554e (the XOR helps in cases where an
 * application packet is also using CRC-32 in it).  The 32-bit CRC is
 * the one defined in ITU V.42 [ITU.V42.2002], which has a generator
 * polynomial of x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1.
 * When present, the FINGERPRINT attribute MUST be the last attribute in
 * the message, and thus will appear after MESSAGE-INTEGRITY.
 * <p>
 * The FINGERPRINT attribute can aid in distinguishing STUN packets from
 * packets of other protocols.  See Section 8.
 * <p>
 * As with MESSAGE-INTEGRITY, the CRC used in the FINGERPRINT attribute
 * covers the length field from the STUN message header.  Therefore,
 * this value must be correct and include the CRC attribute as part of
 * the message length, prior to computation of the CRC.  When using the
 * FINGERPRINT attribute in a message, the attribute is first placed
 * into the message with a dummy value, then the CRC is computed, and
 * then the value of the attribute is updated.  If the MESSAGE-INTEGRITY
 * attribute is also present, then it must be present with the correct
 * message-integrity value before the CRC is computed, since the CRC is
 * done over the value of the MESSAGE-INTEGRITY attribute as well.
 *
 * @author Sebastien Vincent
 * @author Emil Ivov
 */
public class FingerprintAttribute
    extends Attribute
    implements ContentDependentAttribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "FINGERPRINT";

    /**
     * The value that we need to XOR the CRC with. The XOR helps in cases where
     * an application packet is also using CRC-32 in it).
     */
    public static final byte[] XOR_MASK = { 0x53, 0x54, 0x55, 0x4e};


    /**
     * Creates a <tt>FingerPrintAttribute</tt> instance.
     */
    FingerprintAttribute()
    {
        super(FINGERPRINT);
    }

    /**
     * Returns the length of this attribute's body.
     *
     * @return the length of this attribute's value.
     */
    public char getDataLength()
    {
        return 4;
    }

    /**
     * Returns the human readable name of this attribute.
     *
     * @return this attribute's name.
     */
    public String getName()
    {
        return NAME;
    }

    /**
     * Compares two STUN Attributes. Two attributes are considered equal when
     * they have the same type length and value.
     *
     * @param obj the object to compare this attribute with.
     *
     * @return true if the attributes are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (! (obj instanceof FingerprintAttribute) || obj == null)
            return false;

        if (obj == this)
            return true;

        FingerprintAttribute att = (FingerprintAttribute) obj;
        if (att.getAttributeType() != getAttributeType()
                || att.getDataLength() != getDataLength())
        {
            return false;
        }

        return true;
    }

    /**
     * Returns a binary representation of this attribute.
     *
     * @return nothing
     * @throws UnsupportedOperationException since {@link
     * ContentDependentAttribute}s should be encoded through the content
     * dependent encode method.
     */
    public byte[] encode()
        throws UnsupportedOperationException
    {
        throw new UnsupportedOperationException(
                        "ContentDependentAttributes should be encoded "
                        +"through the contend-dependent encode method");
    }

    /**
     * Returns a binary representation of this attribute.
     *
     * @param content the content of the message that this attribute will be
     * transported in
     * @param offset the <tt>content</tt>-related offset where the actual
     * content starts.
     * @param length the length of the content in the <tt>content</tt> array.
     *
     * @return a binary representation of this attribute valid for the message
     * with the specified <tt>content</tt>.
     */
    public byte[] encode(byte[] content, int offset, int length)
    {
        char type = getAttributeType();
        byte binValue[] = new byte[HEADER_LENGTH + getDataLength()];

        //Type
        binValue[0] = (byte)(type>>8);
        binValue[1] = (byte)(type&0x00FF);
        //Length
        binValue[2] = (byte)(getDataLength()>>8);
        binValue[3] = (byte)(getDataLength()&0x00FF);

        //calculate the check sum
        byte[] xorCrc32 = calculateXorCRC32(content, offset, length);

        //copy into the attribute;
        binValue[4] = xorCrc32[0];
        binValue[5] = xorCrc32[1];
        binValue[6] = xorCrc32[2];
        binValue[7] = xorCrc32[3];

        return binValue;
    }

    /**
     * Sets this attribute's fields according to the message and attributeValue
     * arrays. This method allows the stack to validate the content of content
     * dependent attributes such as the {@link MessageIntegrityAttribute} or
     * the {@link FingerprintAttribute} and hide invalid ones from the
     * application.
     *
     * @param attributeValue a binary array containing this attribute's field
     * values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     * offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     * @param messageHead the bytes of the message that brought this attribute.
     * @param mhOffset the start of the message that brought this attribute
     * @param mhLen the length of the message in the messageHead param up until
     * the start of this attribute.
     *
     * @throws StunException if attrubteValue contains invalid data.
     */
    public void decodeAttributeBody( byte[] attributeValue,
                                     char offset,
                                     char length,
                                     byte[] messageHead,
                                     char mhOffset,
                                     char mhLen)
        throws StunException
    {
        if(length != 4)
        {
            throw new StunException("length invalid");
        }

        byte[] incomingCrcBytes = new byte[4];

        incomingCrcBytes[0] = attributeValue[offset];
        incomingCrcBytes[1] = attributeValue[offset + 1];
        incomingCrcBytes[2] = attributeValue[offset + 2];
        incomingCrcBytes[3] = attributeValue[offset + 3];

        //now check whether the CRC really is what it's supposed to be.
        //re calculate the check sum
        byte[] realCrcBytes = calculateXorCRC32(messageHead, mhOffset, mhLen);

        //CRC validation.
        if ( ! Arrays.equals(incomingCrcBytes, realCrcBytes))
            throw new StunException(StunException.ILLEGAL_ARGUMENT,
                "An incoming message arrived with a wrong FINGERPRINT "
                +"attribute value. "
                +"CRC Was:"  + Arrays.toString(incomingCrcBytes)
                + ". Should have been:" + Arrays.toString(realCrcBytes)
                +". Will ignore.");
    }

    /**
     * Calculates and returns the CRC32 checksum for <tt>message</tt> after
     * applying the <tt>XOR_MASK</tt> specified by RFC 5389.
     *
     * @param message the message whose checksum we'd like to have
     * @param offset the location in <tt>message</tt> where the actual message
     * starts.
     * @param len the number of message bytes in <tt>message</tt>
     *
     * @return the CRC value that should be sent in a <tt>FINGERPRINT</tt>
     * attribute traveling in the <tt>message</tt> message.
     */
    private static byte[] calculateXorCRC32(byte[] message, int offset, int len)
    {
        //now check whether the CRC really is what it's supposed to be.
        //re calculate the check sum
        CRC32 checksum = new CRC32();
        checksum.update(message, offset, len);

        long crc = checksum.getValue();
        byte[] xorCRC32 = new byte[4];

        xorCRC32[0] = (byte)((byte)((crc >> 24) & 0xff) ^ XOR_MASK[0]);
        xorCRC32[1] = (byte)((byte)((crc >> 16) & 0xff) ^ XOR_MASK[1]);
        xorCRC32[2] = (byte)((byte)((crc >> 8)  & 0xff) ^ XOR_MASK[2]);
        xorCRC32[3] = (byte)((byte) (crc        & 0xff) ^ XOR_MASK[3]);

        return xorCRC32;
    }

    /**
     * Creates a <tt>long</tt> CRC value out of the specified <tt>bytes</tt>.
     *
     * @param bytes the byte array to convert into a <tt>long</tt>.
     *
     * @return the CRC value contained by the <tt>bytes</tt> array.
     */
    private long byteArrayToCRC(byte[] bytes)
    {
        long crc = ((bytes[0] << 24) & 0xff000000)
                 + ((bytes[1] << 16) & 0x00ff0000)
                 + ((bytes[2] << 8)  & 0x0000ff00)
                 +  (bytes[3]        & 0x000000ff);

        return crc;
    }

    /**
     * Always throws an {@link UnsupportedOperationException} since this
     * attribute should be decoded through the content specific decode method.
     *
     * @param attributeValue a binary array containing this attribute's
     * field values and NOT containing the attribute header.
     * @param offset the position where attribute values begin (most often
     * offset is equal to the index of the first byte after length)
     * @param length the length of the binary array.
     *
     * @throws UnsupportedOperationException since we are supposed to decode
     * through the content specific decode method.
     */
    void decodeAttributeBody(byte[] attributeValue, char offset, char length)
        throws UnsupportedOperationException
    {
        throw new UnsupportedOperationException(
                        "ContentDependentAttributes should be decoded "
                        +"through the contend-dependent decode method");
    }
}

