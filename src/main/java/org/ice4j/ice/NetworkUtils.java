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
package org.ice4j.ice;

/**
 * Utility methods and fields to use when working with network addresses.
 *
 * @author Emil Ivov
 * @author Damian Minkov
 * @author Vincent Lucas
 * @author Alan Kelly
 */
public class NetworkUtils
{
    /**
     * The maximum int value that could correspond to a port number.
     */
    public static final int    MAX_PORT_NUMBER = 65535;

    /**
     * The minimum int value that could correspond to a port number bindable
     * by ice4j.
     */
    public static final int    MIN_PORT_NUMBER = 1024;

    /**
     * Determines whether <tt>port</tt> is a valid port number bindable by an
     * application (i.e. an integer between 1024 and 65535).
     *
     * @param port the port number that we'd like verified.
     *
     * @return <tt>true</tt> if port is a valid and bindable port number and
     * <tt>false</tt> otherwise.
     */
    public static boolean isValidPortNumber(int port)
    {
        return MIN_PORT_NUMBER <= port && port <= MAX_PORT_NUMBER;
    }

    /**
     * Returns a <tt>String</tt> that is guaranteed not to contain an address
     * scope specified (i.e. removes the %scopeID at the end of IPv6 addresses
     * returned by Java. Takes into account the presence or absence of square
     * brackets encompassing the address.
     *
     * @param ipv6Address the address whose scope ID we'd like to get rid of.
     *
     * @return the newly form address containing no scope ID.
     */
    public static String stripScopeID(String ipv6Address)
    {
        int scopeStart = ipv6Address.indexOf('%');

        if (scopeStart == -1)
            return ipv6Address;

        ipv6Address = ipv6Address.substring(0, scopeStart);

        //in case this was an IPv6 literal and we remove the closing bracket,
        //put it back in now.
        if (ipv6Address.charAt(0) == '['
            && ipv6Address.charAt(ipv6Address.length()-1) != ']')
        {
            ipv6Address += ']';
        }

        return ipv6Address;
    }
}
