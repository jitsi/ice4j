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
package org.ice4j.stunclient;

import junit.framework.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * Makes basic stun tests for cases where local network addresses and the public
 * NAT address are using different IP versions. (e.g. Local addresses are v4
 * public NAT address is v6 or vice versa)
 *
 *
 * The StunAddressDiscovererTest_XXX set of tests were created to verify stun
 * operation for scenarios of some basic types of firewalls. The purpose of
 * these tests is to make sure that transaction retransmissions and rereceptions
 * are handled transparently by the stack, as well as verify overall protocol
 * operations for IPv4/IPv6 and mixed environments.
 *
 * <p>Company: Net Research Team, Louis Pasteur University</p>
 * @author Emil Ivov
 */
public class StunAddressDiscovererTest_v4v6 extends TestCase
{
    private NetworkConfigurationDiscoveryProcess stunAddressDiscoverer_v6
        = null;
    private NetworkConfigurationDiscoveryProcess stunAddressDiscoverer_v4
        = null;

    private TransportAddress discovererAddress_v4
            = new TransportAddress("127.0.0.1", 17555, Transport.UDP);
    private TransportAddress discovererAddress_v6
            = new TransportAddress("::1", 17555, Transport.UDP);

    private ResponseSequenceServer responseServer_v6 = null;
    private ResponseSequenceServer responseServer_v4 = null;

    private TransportAddress responseServerAddress_v6
        = new TransportAddress("::1", 21999, Transport.UDP);
    private TransportAddress responseServerAddress_v4
        = new TransportAddress("127.0.0.1", 21999, Transport.UDP);

    private TransportAddress mappedClientAddress_v6 = new TransportAddress(
                    "2001:660:4701:1001:ff::1", 17612, Transport.UDP);
    private TransportAddress mappedClientAddress_v6_Port2
        = new TransportAddress(
                        "2001:660:4701:1001:ff::1", 17611, Transport.UDP);

    private TransportAddress mappedClientAddress_v4
        = new TransportAddress("130.79.99.55", 17612, Transport.UDP);
    private TransportAddress mappedClientAddress_v4_Port2
        = new TransportAddress("130.79.99.55", 17611, Transport.UDP);

    public StunAddressDiscovererTest_v4v6(String name)
        throws StunException
    {
        super(name);
    }

    protected void setUp()
        throws Exception
    {
        super.setUp();

        StunStack stunStack = new StunStack();

        responseServer_v6
            = new ResponseSequenceServer(stunStack, responseServerAddress_v6);
        responseServer_v4
            = new ResponseSequenceServer(stunStack, responseServerAddress_v4);

        stunAddressDiscoverer_v6
            = new NetworkConfigurationDiscoveryProcess(
                    stunStack,
                    discovererAddress_v6, responseServerAddress_v6);
        stunAddressDiscoverer_v4
            = new NetworkConfigurationDiscoveryProcess(
                    stunStack,
                    discovererAddress_v4, responseServerAddress_v4);

        stunAddressDiscoverer_v6.start();
        stunAddressDiscoverer_v4.start();
        responseServer_v6.start();
        responseServer_v4.start();

        System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER , "100");
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "2");
    }

    protected void tearDown()
        throws Exception
    {
        System.clearProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER);
        System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);

        responseServer_v6.shutDown();
        responseServer_v4.shutDown();
        stunAddressDiscoverer_v6.shutDown();
        stunAddressDiscoverer_v6 = null;
        stunAddressDiscoverer_v4.shutDown();
        stunAddressDiscoverer_v4 = null;

        //give the sockets the time to clear out
        Thread.sleep(1000);

        super.tearDown();
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Symmetric NAT.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    public void testRecognizeSymmetricNat_Local_v6_Public_v4()
        throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v4,
            responseServerAddress_v6,
            responseServerAddress_v6);
        Response testIResponse2 = null;
        Response testIResponse3 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v4_Port2,
            responseServerAddress_v6,
            responseServerAddress_v6);

        responseServer_v6.addMessage(testIResponse1);
        responseServer_v6.addMessage(testIResponse2);
        responseServer_v6.addMessage(testIResponse3);


        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.SYMMETRIC_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress_v4);

        StunDiscoveryReport actualReturn
            = stunAddressDiscoverer_v6.determineAddress();
        assertEquals("The StunAddressDiscoverer failed for a v4-v6 sym env.",
                     expectedReturn, actualReturn);

    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Symmetric NAT.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    public void testRecognizeSymmetricNat_Local_v4_Public_v6() throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v6,
            responseServerAddress_v4,
            responseServerAddress_v4);
        Response testIResponse2 = null;
        Response testIResponse3 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v6_Port2,
            responseServerAddress_v4,
            responseServerAddress_v4);

        responseServer_v4.addMessage(testIResponse1);
        responseServer_v4.addMessage(testIResponse2);
        responseServer_v4.addMessage(testIResponse3);


        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.SYMMETRIC_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress_v6);

        StunDiscoveryReport actualReturn
            = stunAddressDiscoverer_v4.determineAddress();
        assertEquals(
            "The StunAddressDiscoverer failed for a no-udp environment.",
            expectedReturn,
            actualReturn);

    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Full Cone.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    public void testRecognizeFullCone_Local_v6_Public_v4() throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v4,
            responseServerAddress_v6,
            responseServerAddress_v6);
        Response testIResponse2 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v4,
            responseServerAddress_v6,
            responseServerAddress_v6);

        responseServer_v6.addMessage(testIResponse1);
        responseServer_v6.addMessage(testIResponse2);

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.FULL_CONE_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress_v4);

        StunDiscoveryReport actualReturn = stunAddressDiscoverer_v6.
            determineAddress();
        assertEquals(
            "The StunAddressDiscoverer failed for a no-udp environment.",
            expectedReturn, actualReturn);

    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Full Cone.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    public void testRecognizeFullCone_Local_v4_Public_v6() throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v6,
            responseServerAddress_v4,
            responseServerAddress_v4);
        Response testIResponse2 = MessageFactory.create3489BindingResponse(
            mappedClientAddress_v6,
            responseServerAddress_v4,
            responseServerAddress_v4);

        responseServer_v4.addMessage(testIResponse1);
        responseServer_v4.addMessage(testIResponse2);

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.FULL_CONE_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress_v6);

        StunDiscoveryReport actualReturn = stunAddressDiscoverer_v4.
            determineAddress();
        assertEquals(
            "The StunAddressDiscoverer failed for a no-udp environment.",
            expectedReturn, actualReturn);

    }
}
