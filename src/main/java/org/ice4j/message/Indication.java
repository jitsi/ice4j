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
package org.ice4j.message;

/**
 * An indication descendant of the message class.
 *
 * For example, indication messages is used by TURN protocol
 * to send and receive encapsulated data.
 *
 * @author Sebastien Vincent
 */
public class Indication
    extends Message
{
    /**
     * Constructor.
     */
    Indication()
    {
    }

    /**
     * Checks whether indicationType is a valid indication type and if yes sets
     * it as the type of this instance.
     *
     * @param indicationType the type to set
     * @throws IllegalArgumentException if indicationType is not a valid
     * indication type
     */
    @Override
    public void setMessageType(char indicationType)
        throws IllegalArgumentException
    {
        /* old TURN DATA indication type is an indication despite
         * 0x0115 & 0x0110 indicates STUN error response type
         */
        if(!isIndicationType(indicationType) &&
                indicationType != OLD_DATA_INDICATION)
            throw new IllegalArgumentException(
                    (int)(indicationType)
                    + " - is not a valid indication type.");

        super.setMessageType(indicationType);
    }
}
