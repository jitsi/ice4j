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

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.stack.*;
import org.junit.jupiter.api.*;

public class MessageTest
{
    private Message bindingRequest       = null;
    private Message bindingResponse      = null;

    private MappedAddressAttribute  mappedAddress = null;
    private SourceAddressAttribute  sourceAddress = null;
    private ChangedAddressAttribute changedAddress = null;

    private ChangeRequestAttribute  changeRequest = null;

    private MsgFixture msgFixture;

    /**
     * The <tt>StunStack</tt> used by this <tt>MessageTest</tt>.
     */
    private StunStack stunStack;

    @BeforeEach
    public void setUp() throws Exception
    {
        System.clearProperty(StackProperties.ALWAYS_SIGN);
        System.clearProperty(StackProperties.SOFTWARE);
        msgFixture = new MsgFixture();

        stunStack = new StunStack();

        //binding request
        bindingRequest = new Request();
        bindingRequest.setMessageType(Message.BINDING_REQUEST);

        changeRequest = AttributeFactory.createChangeRequestAttribute(
                   MsgFixture.CHANGE_IP_FLAG_1, MsgFixture.CHANGE_PORT_FLAG_1);
        bindingRequest.putAttribute(changeRequest);
        bindingRequest.setTransactionID(MsgFixture.TRANSACTION_ID);

        //binding response
        bindingResponse = new Response();
        bindingResponse.setMessageType(Message.BINDING_SUCCESS_RESPONSE);

        mappedAddress = AttributeFactory.createMappedAddressAttribute(
            new TransportAddress(
                            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
                            MsgFixture.ADDRESS_ATTRIBUTE_PORT,
                            Transport.UDP));

        bindingResponse.putAttribute(mappedAddress);

        sourceAddress = AttributeFactory.createSourceAddressAttribute(
            new TransportAddress(
                            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_2,
                            MsgFixture.ADDRESS_ATTRIBUTE_PORT_2,
                            Transport.UDP));

        bindingResponse.putAttribute(sourceAddress);

        changedAddress = AttributeFactory.createChangedAddressAttribute(
            new TransportAddress( MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_3,
                        MsgFixture.ADDRESS_ATTRIBUTE_PORT_3, Transport.UDP));

        bindingResponse.putAttribute(changedAddress);
        bindingResponse.setTransactionID(MsgFixture.TRANSACTION_ID);
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        bindingRequest = null;
        bindingResponse = null;
        mappedAddress = null;
        sourceAddress = null;
        changedAddress = null;
        changeRequest = null;

        stunStack = null;

        msgFixture = null;
    }

    /**
     * Adds and gets an attribute and test that they are the same then adds a
     * another attribute (same typ different value) and verifies that the first
     * one is properly replaced.
     *
     */
    @Test
    public void testAddAndGetAttribute()
    {
        Response   message = new Response();
        message.setMessageType(Message.BINDING_SUCCESS_RESPONSE);
        message.putAttribute(mappedAddress);

        Attribute getResult;

        getResult = message.getAttribute(mappedAddress.getAttributeType());
        assertEquals(mappedAddress, getResult,
            "Originally added attribute did not match the returned");

        //do it again
        message.putAttribute(sourceAddress);

        getResult = message.getAttribute(sourceAddress.getAttributeType());

        assertEquals(sourceAddress, getResult,
            "The second attribute could not be extracted.");
    }

    /**
     * Decodes a bindingRequest and then a binding response and checks whether
     * they match the corresponding objects.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testEncode()
        throws StunException
    {
        //Binding Request
        byte[] expectedReturn = msgFixture.bindingRequest;

        byte[] actualReturn = bindingRequest.encode(stunStack);
        assertArrayEquals(expectedReturn, actualReturn,
            "A binding request was not properly encoded");

        //Binding Response
        expectedReturn = msgFixture.bindingResponse;

        actualReturn = bindingResponse.encode(stunStack);

        assertArrayEquals(expectedReturn, actualReturn,
            "A binding response was not properly encoded");
    }

    /**
     * Encodes a bindingRequest and then a binding response and checks whether
     * they match the corresponding binary arrays.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    @Test
    public void testDecode()
        throws Exception
    {
        //Binding Request
        Message expectedReturn = bindingRequest;

        Message actualReturn = Message.decode(msgFixture.bindingRequest,
                                     0,
                                     msgFixture.bindingRequest.length);

        assertEquals(expectedReturn, actualReturn,
            "A binding request was not properly decoded");

        //Binding Response
        expectedReturn = bindingResponse;

        actualReturn = Message.decode(msgFixture.bindingResponse,
                                     0,
                                     msgFixture.bindingResponse.length);

        assertEquals(expectedReturn, actualReturn,
            "A binding response was not properly decoded");
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    @Test
    public void testEquals()
        throws StunException
    {
        assertNotEquals(bindingRequest, null,
            "Equals failed against a null target");

        assertNotEquals(bindingResponse, null,
            "Equals failed against a null target");

        //different
        assertNotEquals(bindingRequest, bindingResponse,
            "Equals failed against a different target");

        assertNotEquals(bindingResponse, bindingRequest,
            "Equals failed against a different target");

        //Create a binding request with the same attributes as
        //this.bindingRequest
        Request binReqTarget = new Request();
        binReqTarget.setMessageType(Message.BINDING_REQUEST);
        binReqTarget.putAttribute(changeRequest);
        assertEquals(bindingRequest, binReqTarget,
            "Equals failed against an equal target");

        //Create a binding response with the same attributes as
        //this.bindingRequest
        Response binResTarget = new Response();
        binResTarget.setMessageType(Message.BINDING_SUCCESS_RESPONSE);
        binResTarget.putAttribute(mappedAddress);
        binResTarget.putAttribute(sourceAddress);
        binResTarget.putAttribute(changedAddress);
        assertEquals(bindingResponse, binResTarget,
            "Equals failed against a different target");
    }

    /**
     * Tests  whether attributes are properly counted
     */
    @Test
    public void testGetAttributeCount()
    {
        int expectedReturn = 1;
        int actualReturn = bindingRequest.getAttributeCount();
        assertEquals(expectedReturn, actualReturn,
            "getAttributeCount failed for a bindingRequest");
        expectedReturn = 3;
        actualReturn = bindingResponse.getAttributeCount();
        assertEquals(expectedReturn, actualReturn,
            "getAttributeCount failed for a bindingRequest");
    }

    /**
     * Test whether attributes are properly removed.
     */
    @Test
    public void testRemoveAttribute()
    {

        bindingRequest.removeAttribute(changeRequest.getAttributeType());

        assertNull(bindingRequest.getAttribute(changeRequest.getAttributeType()),
            "An attribute was still in the request after being removed");

        //test count
        int expectedReturn = 0;
        int actualReturn = bindingRequest.getAttributeCount();
        assertEquals(expectedReturn, actualReturn,
            "Attribute count did not change after removing an attribute");
    }
}
