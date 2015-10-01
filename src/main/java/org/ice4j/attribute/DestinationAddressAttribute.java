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
 * The DESTINATION-ADDRESS is present in Send Requests of old TURN versions.
 * It specifies the address and port where the data is to be sent. It is encoded
 * in the same way as MAPPED-ADDRESS.
 *
 * @author Sebastien Vincent
 */
public class DestinationAddressAttribute extends AddressAttribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "DESTINATION-ADDRESS";

    /**
     * Constructor.
     */
    DestinationAddressAttribute()
    {
        super(DESTINATION_ADDRESS);
    }
}
