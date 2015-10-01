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
 * A request descendant of the message class. The primary purpose of the
 * Request class is to allow better functional definition of the classes in the
 * stack package.
 *
 * @author Emil Ivov
 */
public class Request extends Message
{

    /**
     * Constructor.
     */
    Request()
    {
    }

    /**
     * Checks whether requestType is a valid request type and if yes sets it
     * as the type of the current instance.
     * @param requestType the type to set
     * @throws IllegalArgumentException if requestType is not a valid
     * request type
     */
    public void setMessageType(char requestType)
        throws IllegalArgumentException
    {
        if(!isRequestType(requestType))
            throw new IllegalArgumentException(
                                    (int)(requestType)
                                    + " - is not a valid request type.");


        super.setMessageType(requestType);
    }
}
