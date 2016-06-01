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
package org.ice4j.stack;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * Handles incoming requests.
 *
 * @author Emil Ivov
 */
public interface RequestListener
{
    /**
     * Called when delivering incoming STUN requests. Throwing an
     * {@link IllegalArgumentException} from within this method would cause the
     * stack to reply with a <tt>400 Bad Request</tt> {@link Response} using
     * the exception's message as a reason phrase for the error response. Any
     * other exception would result in a <tt>500 Server Error</tt> {@link
     * Response}.
     *
     * @param evt the event containing the incoming STUN request.
     *
     * @throws IllegalArgumentException if <tt>evt</tt> contains a malformed
     * {@link Request} and the stack would need to response with a
     * <tt>400 Bad Request</tt> {@link Response}.
     */
    public void processRequest(StunMessageEvent evt)
        throws IllegalArgumentException;
}
