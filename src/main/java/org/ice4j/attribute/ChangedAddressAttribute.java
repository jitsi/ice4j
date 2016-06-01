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
 * The CHANGED-ADDRESS attribute indicates the IP address and port where
 * responses would have been sent from if the "change IP" and "change
 * port" flags had been set in the CHANGE-REQUEST attribute of the
 * Binding Request.  The attribute is always present in a Binding
 * Response, independent of the value of the flags.  Its syntax is
 * identical to MAPPED-ADDRESS.
 *
 * @author Emil Ivov
 */

public class ChangedAddressAttribute extends AddressAttribute
{
    /**
     * Attribute name.
     */
    public static final String NAME = "CHANGED-ADDRESS";

    /**
     * Creates a CHANGED_ADDRESS attribute
     */
    public ChangedAddressAttribute()
    {
        super(CHANGED_ADDRESS);
    }
}
