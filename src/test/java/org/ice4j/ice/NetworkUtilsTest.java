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

import static org.junit.Assert.*;

import org.junit.*;

public class NetworkUtilsTest
{
    @Test
    public void testIpv4StringToBytes()
    {
        byte[] addr = NetworkUtils.strToIPv4("1");
        assertArrayEquals(new byte[]{0, 0, 0, 1}, addr);

        addr = NetworkUtils.strToIPv4("1.2");
        assertArrayEquals(new byte[]{1, 0, 0, 2}, addr);

        addr = NetworkUtils.strToIPv4("1.2.3");
        assertArrayEquals(new byte[]{1, 2, 0, 3}, addr);

        addr = NetworkUtils.strToIPv4("1.2.3.4");
        assertArrayEquals(new byte[]{1, 2, 3, 4}, addr);

        assertNull(NetworkUtils.strToIPv4(""));
        assertNull(NetworkUtils.strToIPv4("-1"));
        assertNull(NetworkUtils.strToIPv4("1.-2"));
        assertNull(NetworkUtils.strToIPv4("-1.2"));
        assertNull(NetworkUtils.strToIPv4("1.-2.3"));
        assertNull(NetworkUtils.strToIPv4("1.2.-3"));
        assertNull(NetworkUtils.strToIPv4("-1.2.3"));
        assertNull(NetworkUtils.strToIPv4("1.-2.3.4"));
        assertNull(NetworkUtils.strToIPv4("1.2.-3.4"));
        assertNull(NetworkUtils.strToIPv4("1.2.3.-4"));
        assertNull(NetworkUtils.strToIPv4("-1.2.3.4"));
        assertNull(NetworkUtils.strToIPv4("1.2.3.4.5"));
        assertNull(NetworkUtils.strToIPv4("1.2.3.256"));
    }

    @Test
    public void testIpv6StringToBytes()
    {
        byte[] addr = NetworkUtils.strToIPv6("::12");
        assertNotNull(addr);
        assertEquals(18, addr[15]);

        addr = NetworkUtils.strToIPv6("[::12]");
        assertNotNull(addr);
        assertEquals(18, addr[15]);

        addr = NetworkUtils.strToIPv6("::12%1");
        assertNotNull(addr);
        assertEquals(18, addr[15]);

        addr = NetworkUtils.strToIPv6("[::12%1]");
        assertNotNull(addr);
        assertEquals(18, addr[15]);

        assertNull(NetworkUtils.strToIPv6(""));
        assertNull(NetworkUtils.strToIPv6(":::"));
        assertNull(NetworkUtils.strToIPv6("[^"));
        assertNull(NetworkUtils.strToIPv6("[%"));
        assertNull(NetworkUtils.strToIPv6(":?0"));
        assertNull(NetworkUtils.strToIPv6("[::12]%1"));
        assertNull(NetworkUtils.strToIPv6("[::65536]%1"));
        assertNull(NetworkUtils.strToIPv6("1111:222:3333:4444:5555:6666:7"));
    }
}
