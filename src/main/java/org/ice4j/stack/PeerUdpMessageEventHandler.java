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

/**
 * The interface is used for collecting incoming Peer UDP Message messages from
 * the NetAccessManager (and more precisely - MessageProcessors) if it is of no
 * other type. This is our way of keeping scalable network and stun layers.
 * 
 * @author Aakash Garg
 */
public interface PeerUdpMessageEventHandler
{
    /**
     * Called when an incoming Peer UDP message has been received, parsed
     * and is ready for delivery.
     * 
     * @param messageEvent the event object that encapsulates the newly received
     *                     message.
     */
    public void handleMessageEvent(PeerUdpMessageEvent messageEvent);
}
