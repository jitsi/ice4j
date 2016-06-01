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

/**
 * The MAPPED-ADDRESS attribute indicates the mapped IP address and
 * port.  It consists of an eight bit address family, and a sixteen bit
 * port, followed by a fixed length value representing the IP address.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |x x x x x x x x|    Family     |           Port                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Address                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The port is a network byte ordered representation of the mapped port.
 * The address family is always 0x01, corresponding to IPv4.  The first
 * 8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
 * aligning parameters on natural boundaries.  The IPv4 address is 32
 * bits.
 *
 * @author Emil Ivov
 */
public class MappedAddressAttribute extends AddressAttribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "MAPPED-ADDRESS";

    /**
     * Constructor.
     */
    MappedAddressAttribute()
    {
        super(MAPPED_ADDRESS);
    }
}
