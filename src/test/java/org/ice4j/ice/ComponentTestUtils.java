/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2026 - present 8x8, Inc.
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
package org.ice4j.ice;

import org.ice4j.socket.*;

import java.net.*;

/**
 * Helpers for tests outside the {@code org.ice4j.ice} package which need access to package-private functionality.
 */
public final class ComponentTestUtils
{
    private ComponentTestUtils()
    {
    }

    /**
     * Creates a component directly on a stream, without harvesting candidates on the real network interfaces as
     * {@link Agent#createComponent} would, and with the component socket disabled.
     */
    public static Component createComponent(IceMediaStream stream, KeepAliveStrategy keepAliveStrategy)
    {
        return stream.createComponent(keepAliveStrategy, false);
    }

    /**
     * @return the socket which a component uses to send to a remote address through one of its local candidates,
     * or {@code null} if no candidate has one.
     */
    public static IceSocketWrapper getCandidateSocket(Component component, SocketAddress remoteAddress)
    {
        for (LocalCandidate candidate : component.getLocalCandidates())
        {
            IceSocketWrapper socket = candidate.getCandidateIceSocketWrapper(remoteAddress);
            if (socket != null)
            {
                return socket;
            }
        }
        return null;
    }
}
