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
package org.ice4j.socket;

import java.net.*;

/**
 * Classes implementing this interface follow the factory pattern, generating
 * DatagramSocket objects for use by other classes in the stack.
 * 
 * By extending this interface and using the method
 * DelegatingDatagramSocket#setDefaultDelegateFactory()
 * it is possible for the application developer to ensure their own variety
 * of DatagramSocket is used by the ice4j stack and passed back to their
 * application when the ICE protocol is completed.
 * 
 * @author Daniel Pocock
 * @author Vincent Lucas
 */
public interface DatagramSocketFactory
{
    /**
     * Creates an unbound DatagramSocket:
     * - i.e <tt>return new DatagramSocket((SocketAddress) null)</tt>.
     *
     * @return An unbound DatagramSocket.
     *
     * @throws SocketException if the socket could not be opened.
     */
    public DatagramSocket createUnboundDatagramSocket()
        throws SocketException;
}
