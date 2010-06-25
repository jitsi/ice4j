/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

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
}
