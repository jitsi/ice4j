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

import org.ice4j.stack.*;

/**
 * <tt>ContentDependentAttribute</tt>s have a value that depend on the content
 * of the message. The {@link MessageIntegrityAttribute} and {@link
 * FingerprintAttribute} are two such attributes.
 * <p>
 * Rather than encoding them via the standard {@link Attribute#encode()} method,
 * the stack would use the one from this interface.
 * </p>
 *
 * @author Emil Ivov
 */
public interface ContentDependentAttribute
{
    /**
     * Returns a binary representation of this attribute.
     *
     * @param stunStack the <tt>StunStack</tt> in the context of which the
     * request to encode this <tt>ContentDependentAttribute</tt> is being made
     * @param content the content of the message that this attribute will be
     * transported in
     * @param offset the <tt>content</tt>-related offset where the actual
     * content starts.
     * @param length the length of the content in the <tt>content</tt> array.
     *
     * @return a binary representation of this attribute valid for the message
     * with the specified <tt>content</tt>.
     */
    public byte[] encode(
            StunStack stunStack,
            byte[] content, int offset, int length);
}
