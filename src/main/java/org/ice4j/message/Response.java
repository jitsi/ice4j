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
 * A response descendant of the message class. The primary purpose of the
 * Response class is to allow better functional definition of the classes in the
 * stack package.
 *
 * @author Emil Ivov
 * @author Lubomir Marinov
 */
public class Response
    extends Message
{

    /**
     * Constructor.
     */
    Response()
    {
    }

    /**
     * Determines whether this instance represents a STUN error response.
     *
     * @return <tt>true</tt> if this instance represents a STUN error response;
     * otherwise, <tt>false</tt>
     */
    public boolean isErrorResponse()
    {
        return isErrorResponseType(getMessageType());
    }

    /**
     * Determines whether this instance represents a STUN success response.
     *
     * @return <tt>true</tt> if this instance represents a STUN success
     * response; otherwise, <tt>false</tt>
     */
    public boolean isSuccessResponse()
    {
        return isSuccessResponseType(getMessageType());
    }

    /**
     * Checks whether responseType is a valid response type and if yes sets it
     * as the type of the current instance.
     * @param responseType the type to set
     * @throws IllegalArgumentException if responseType is not a valid
     * response type
     */
    public void setMessageType(char responseType)
        throws IllegalArgumentException
    {
        if(!isResponseType(responseType))
            throw new IllegalArgumentException(
                                    Integer.toString(responseType)
                                        + " is not a valid response type.");


        super.setMessageType(responseType);
    }
}
