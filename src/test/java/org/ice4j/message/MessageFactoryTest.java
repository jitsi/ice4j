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

import junit.framework.*;

import org.ice4j.*;
import org.ice4j.attribute.*;

public class MessageFactoryTest extends TestCase
{
    private MsgFixture msgFixture;

    public MessageFactoryTest(String name)
    {
        super(name);
    }

    protected void setUp() throws Exception
    {
        super.setUp();
        msgFixture = new MsgFixture();

        msgFixture.setUp();
    }

    protected void tearDown() throws Exception
    {
        msgFixture.tearDown();

        msgFixture = null;
        super.tearDown();
    }

    public void testCreateBindingErrorResponse() throws StunException
    {
        char errorCode = 400;

        Response expectedReturn = new Response();
        expectedReturn.setMessageType(Message.BINDING_ERROR_RESPONSE);

        Attribute errorCodeAtt
            = AttributeFactory.createErrorCodeAttribute(errorCode);
        expectedReturn.putAttribute(errorCodeAtt);

        Message actualReturn
            = MessageFactory.createBindingErrorResponse(errorCode);
        assertEquals("return value", expectedReturn, actualReturn);
    }

    public void testCreateBindingErrorResponse1() throws StunException
    {
        char errorCode = 400;
        String reasonPhrase = "Bad Request";

        Response expectedReturn = new Response();
        expectedReturn.setMessageType(Message.BINDING_ERROR_RESPONSE);

        Attribute errorCodeAtt = AttributeFactory
            .createErrorCodeAttribute(errorCode, reasonPhrase);
        expectedReturn.putAttribute(errorCodeAtt);

        Message actualReturn = MessageFactory
            .createBindingErrorResponse(errorCode, reasonPhrase);
        assertEquals("Failed to create an error code attribute.",
                        expectedReturn, actualReturn);
    }

    public void testCreateBindingErrorResponseUnknownAttributes()
            throws StunException
    {
        char errorCode = 420;
        char[] unknownAttributes = new char[]{21, 22, 23};

        //create a message manually
        Response expectedReturn = new Response();
        expectedReturn.setMessageType(Message.BINDING_ERROR_RESPONSE);

        Attribute errorCodeAtt = AttributeFactory
            .createErrorCodeAttribute(errorCode);
        ((ErrorCodeAttribute)errorCodeAtt).setReasonPhrase(
                        ErrorCodeAttribute.getDefaultReasonPhrase(errorCode));
        expectedReturn.putAttribute(errorCodeAtt);

        UnknownAttributesAttribute unknownAtts =
                        AttributeFactory.createUnknownAttributesAttribute();

        for (int i = 0; i < unknownAttributes.length; i++) {
            unknownAtts.addAttributeID(unknownAttributes[i]);
        }
        expectedReturn.putAttribute(unknownAtts);

        //create the same message using the factory
        Message actualReturn = MessageFactory
            .createBindingErrorResponseUnknownAttributes(unknownAttributes);
        //compare
        assertEquals("return value", expectedReturn, actualReturn);
    }

    public void testCreateBindingErrorResponseUnknownAttributes1()
            throws StunException
    {
        char errorCode = 420;
        String reasonPhrase = "UnknwonAttributes";
        char[] unknownAttributes = new char[]{21, 22, 23};

        Response expectedReturn = new Response();
        expectedReturn.setMessageType(Message.BINDING_ERROR_RESPONSE);

        Attribute errorCodeAtt = AttributeFactory.createErrorCodeAttribute(
            errorCode, reasonPhrase);
        expectedReturn.putAttribute(errorCodeAtt);

        UnknownAttributesAttribute unknownAtts =
            AttributeFactory.createUnknownAttributesAttribute();

        for (int i = 0; i < unknownAttributes.length; i++)
        {
            unknownAtts.addAttributeID(unknownAttributes[i]);
        }
        expectedReturn.putAttribute(unknownAtts);

        Message actualReturn = MessageFactory
            .createBindingErrorResponseUnknownAttributes(
                                           reasonPhrase, unknownAttributes);
        assertEquals("return value", expectedReturn, actualReturn);
    }

    public void testCreateBindingRequest() throws StunException
    {
        Request bindingRequest = new Request();
        Request expectedReturn = bindingRequest;
        bindingRequest.setMessageType(Message.BINDING_REQUEST);
/*
        Attribute changeRequest = AttributeFactory.createChangeRequestAttribute(
                    msgFixture.CHANGE_IP_FLAG_1, msgFixture.CHANGE_PORT_FLAG_1);
        bindingRequest.putAttribute(changeRequest);
*/
        Request actualReturn = MessageFactory.createBindingRequest();
        assertEquals("return value", expectedReturn, actualReturn);
    }

    public void testCreateBindingResponse()
        throws Exception
    {
        Response bindingResponse = new Response();
        bindingResponse.setMessageType(Message.BINDING_SUCCESS_RESPONSE);

        Attribute mappedAddress = AttributeFactory.createMappedAddressAttribute(
            new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
                                  MsgFixture.ADDRESS_ATTRIBUTE_PORT,
                                  Transport.UDP));

        bindingResponse.putAttribute(mappedAddress);

        Attribute sourceAddress = AttributeFactory.createSourceAddressAttribute(
            new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_2,
                                  MsgFixture.ADDRESS_ATTRIBUTE_PORT_2,
                                  Transport.UDP));

        bindingResponse.putAttribute(sourceAddress);

        Attribute changedAddress = AttributeFactory.
            createChangedAddressAttribute(
                new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_3,
                                      MsgFixture.ADDRESS_ATTRIBUTE_PORT_3,
                                      Transport.UDP));

        bindingResponse.putAttribute(changedAddress);

        Message expectedReturn = bindingResponse;
        Message actualReturn = MessageFactory.create3489BindingResponse(
            new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
                                  MsgFixture.ADDRESS_ATTRIBUTE_PORT,
                                  Transport.UDP),
            new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_2,
                                  MsgFixture.ADDRESS_ATTRIBUTE_PORT_2,
                                  Transport.UDP),
            new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_3,
                                  MsgFixture.ADDRESS_ATTRIBUTE_PORT_3,
                                  Transport.UDP));
        assertEquals("return value", expectedReturn, actualReturn);
    }
}
