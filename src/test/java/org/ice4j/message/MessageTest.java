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

import java.util.*;

import junit.framework.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.stack.*;

public class MessageTest extends TestCase
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

    protected void setUp() throws Exception
    {
        super.setUp();

        msgFixture = new MsgFixture();
        msgFixture.setUp();

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

    protected void tearDown() throws Exception
    {
        bindingRequest = null;
        bindingResponse = null;
        mappedAddress = null;
        sourceAddress = null;
        changedAddress = null;
        changeRequest = null;
        changeRequest = null;

        stunStack = null;

        msgFixture.tearDown();
        msgFixture = null;

        super.tearDown();
    }

    /**
     * Adds and gets an attribute and test that they are the same then adds a
     * another attribute (same typ different value) and veriies that the first
     * one is properly replaced.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testAddAndGetAttribute() throws StunException
    {

        Response   message = new Response();
        message.setMessageType(Message.BINDING_SUCCESS_RESPONSE);
        message.putAttribute(mappedAddress);

        Attribute getResult = null;


        getResult = message.getAttribute(mappedAddress.getAttributeType());
        assertEquals("Originally added attribute did not match the one retrned "
                     +"by getAttribute()",
                     mappedAddress,
                     getResult);

        //do it again
        message.putAttribute(sourceAddress);

        getResult = message.getAttribute(sourceAddress.getAttributeType());


        assertEquals("The second attribute could not be extracted.",
                    sourceAddress,
                    getResult);
    }

    /**
     * Decodes a bindingRequest and then a binding response and checks whether
     * they match the corresponding objects.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testEncode()
        throws StunException
    {
        //Binding Request
        byte[] expectedReturn = msgFixture.bindingRequest;

        byte[] actualReturn = bindingRequest.encode(stunStack);
        assertTrue("A binding request was not properly encoded",
                   Arrays.equals(  expectedReturn, actualReturn ) );

        //Binding Response
        expectedReturn = msgFixture.bindingResponse;

        actualReturn = bindingResponse.encode(stunStack);

        assertTrue("A binding response was not properly encoded",
                     Arrays.equals(  expectedReturn, actualReturn ) );
    }

    /**
     * Encodes a bindingRequest and then a binding response and checks whether
     * they match the corresponding binary arrays.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    public void testDecode()
        throws Exception
    {
        //Binding Request
        Message expectedReturn = bindingRequest;

        Message actualReturn = Message.decode(msgFixture.bindingRequest,
                                     (char)0,
                                     (char)msgFixture.bindingRequest.length);

        assertEquals("A binding request was not properly decoded",
                     expectedReturn, actualReturn );

        //Binding Response
        expectedReturn = bindingResponse;

        actualReturn = Message.decode(msgFixture.bindingResponse,
                                     (char)0,
                                     (char)msgFixture.bindingResponse.length);

        assertEquals("A binding response was not properly decoded",
                     expectedReturn, actualReturn );
    }

    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     *
     * @throws StunException java.lang.Exception if we fail
     */
    public void testEquals()
        throws StunException
    {
        Object target = null;
        boolean expectedReturn = false;
        boolean actualReturn = bindingRequest.equals(target);
        assertEquals("Equals failed against a null target",
                        expectedReturn, actualReturn);

        actualReturn = bindingResponse.equals(target);
        assertEquals("Equals failed against a null target",
                        expectedReturn, actualReturn);

        //different
        actualReturn = bindingRequest.equals(bindingResponse);
        assertEquals("Equals failed against a different target",
                        expectedReturn, actualReturn);

        actualReturn = bindingResponse.equals(bindingRequest);
        assertEquals("Equals failed against a different target",
                        expectedReturn, actualReturn);

        //same
        expectedReturn = true;

        //Create a binding request with the same attributes as
        //this.bindingRequest
        Request binReqTarget = new Request();
        binReqTarget.setMessageType(Message.BINDING_REQUEST);
        binReqTarget.putAttribute(changeRequest);
        actualReturn = bindingRequest.equals(binReqTarget);
        assertEquals("Equals failed against an equal target",
                        expectedReturn, actualReturn);

        //Create a binding response with the same attributes as
        //this.bindingRequest
        Response binResTarget = new Response();
        binResTarget.setMessageType(Message.BINDING_SUCCESS_RESPONSE);
        binResTarget.putAttribute(mappedAddress);
        binResTarget.putAttribute(sourceAddress);
        binResTarget.putAttribute(changedAddress);
        actualReturn = bindingResponse.equals(binResTarget);
        assertEquals("Equals failed against a different target",
                        expectedReturn, actualReturn);
    }

    /**
     * Tests  whether attributes are properly counted
     */
    public void testGetAttributeCount()
    {
        int expectedReturn = 1;
        int actualReturn = bindingRequest.getAttributeCount();
        assertEquals("getAttributeCount failed for a bindingRequest",
                     expectedReturn, actualReturn);
        expectedReturn = 3;
        actualReturn = bindingResponse.getAttributeCount();
        assertEquals("getAttributeCount failed for a bindingRequest",
                     expectedReturn, actualReturn);
    }

    /**
     * Test whether attributes are properly removed.
     */
    public void testRemoveAttribute()
    {

        bindingRequest.removeAttribute(changeRequest.getAttributeType());

        assertNull("An attribute was still in the request after being removed",
               bindingRequest.getAttribute(changeRequest.getAttributeType()));

        //test count
        int expectedReturn = 0;
        int actualReturn = bindingRequest.getAttributeCount();
        assertEquals(
            "Attribute count did not change after removing an attribute",
            expectedReturn, actualReturn);
    }
}
