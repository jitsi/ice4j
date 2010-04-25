/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * <tt>ContentDependentAttribute</tt>s have a value that depend on the content
 * of the message. The {@link MessageIntegrityAttribute} and {@link
 * FingerprintAttribute} are two such attributes.
 * <p>
 * Rather than encoding them via the standard {@link Attribute#encode()} method,
 * the stack would use the one from this interface.
 *
 * @author Emil Ivov
 */
public interface ContentDependentAttribute
{
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
    public byte[] encode(byte[] content, int offset, int length);

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
        throws StunException;
}
