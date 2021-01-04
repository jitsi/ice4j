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

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;
import org.junit.jupiter.api.*;

/**
 * The StunAddressDiscovererTest_XXX set of tests were created to verify stun
 * operation for scenarios of some basic types of firewalls. The purpose of
 * these tests is to make sure that transaction retransmissions and rereceptions
 * are handled transparently by the stack, as well as verify overal protocol
 * operations for IPv4/IPv6 and mixed environments.
 *
 * <p>Company: Net Research Team, Louis Pasteur University</p>
 * @author Emil Ivov
 */
public class StunAddressDiscovererTest_v6
{
    private NetworkConfigurationDiscoveryProcess  stunAddressDiscoverer = null;
    private final TransportAddress discovererAddress
        = new TransportAddress("::1", 16555, Transport.UDP);

    private ResponseSequenceServer responseServer = null;
    private final TransportAddress responseServerAddress
        = new TransportAddress("::1", 20999, Transport.UDP);

    private final TransportAddress mappedClientAddress = new TransportAddress(
                    "2001:660:4701:1001:ff::1", 16612, Transport.UDP);
    private final TransportAddress mappedClientAddressPort2 = new TransportAddress(
                    "2001:660:4701:1001:ff::1", 16611, Transport.UDP);

    @BeforeEach
    public void setUp() throws Exception
    {
        StunStack stunStack = new StunStack();

        responseServer
            = new ResponseSequenceServer(stunStack, responseServerAddress);
        stunAddressDiscoverer
            = new NetworkConfigurationDiscoveryProcess(
                    stunStack,
                    discovererAddress, responseServerAddress);

        stunAddressDiscoverer.start();
        responseServer.start();

        System.setProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER, "100");
        System.setProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS, "2");
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        System.clearProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER);
        System.clearProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);
        responseServer.shutDown();
        stunAddressDiscoverer.shutDown();
        stunAddressDiscoverer = null;
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it's in a network where UDP is blocked.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizeBlockedUDP()
        throws Exception
    {

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.UDP_BLOCKING_FIREWALL);
        expectedReturn.setPublicAddress(null);

        StunDiscoveryReport actualReturn
            = stunAddressDiscoverer.determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Symmetric NAT.
     *
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizeSymmetricNat()
        throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
             mappedClientAddress, responseServerAddress, responseServerAddress);
        Response testIResponse2 = null;
        Response testIResponse3 = MessageFactory.create3489BindingResponse(
             mappedClientAddressPort2,
             responseServerAddress,
             responseServerAddress);

        responseServer.addMessage(testIResponse1);
        responseServer.addMessage(testIResponse2);
        responseServer.addMessage(testIResponse3);


        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.SYMMETRIC_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress);

        StunDiscoveryReport actualReturn
            = stunAddressDiscoverer.determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Port Restricted Cone.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizePortRestrictedCone()
        throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);
        Response testIResponse2 = null;
        Response testIResponse3 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);
        Response testIResponse4 = null;

        responseServer.addMessage(testIResponse1);
        responseServer.addMessage(testIResponse2);
        responseServer.addMessage(testIResponse3);
        responseServer.addMessage(testIResponse4);


        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.PORT_RESTRICTED_CONE_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress);

        StunDiscoveryReport actualReturn
            = stunAddressDiscoverer.determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Restricted Cone.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizeRestrictedCone()
        throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);
        Response testIResponse2 = null;
        Response testIResponse3 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);
        Response testIResponse4 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);

        responseServer.addMessage(testIResponse1);
        responseServer.addMessage(testIResponse2);
        responseServer.addMessage(testIResponse3);
        responseServer.addMessage(testIResponse4);

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.RESTRICTED_CONE_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress);

        StunDiscoveryReport actualReturn
            = stunAddressDiscoverer.determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Full Cone.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizeFullCone() throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);
        Response testIResponse2 = MessageFactory.create3489BindingResponse(
            mappedClientAddress, responseServerAddress, responseServerAddress);

        responseServer.addMessage(testIResponse1);
        responseServer.addMessage(testIResponse2);

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.FULL_CONE_NAT);
        expectedReturn.setPublicAddress(mappedClientAddress);

        StunDiscoveryReport actualReturn = stunAddressDiscoverer
            .determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a UDP Symmetric Firewall.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizeUdpSymmetricFirewall()
        throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            discovererAddress, responseServerAddress, responseServerAddress);
        Response testIResponse2 = null;

        responseServer.addMessage(testIResponse1);
        responseServer.addMessage(testIResponse2);

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.SYMMETRIC_UDP_FIREWALL);
        expectedReturn.setPublicAddress(discovererAddress);

        StunDiscoveryReport actualReturn = stunAddressDiscoverer
            .determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }

    /**
     * Performs a test where no responces are given the stun client so that
     * it concludes it is behind a Open Internet.
     * @throws Exception if anything goes wrong ( surprised? ).
     */
    @Test
    public void testRecognizeOpenInternet()
        throws Exception
    {
        //define the server response sequence
        Response testIResponse1 = MessageFactory.create3489BindingResponse(
            discovererAddress, responseServerAddress, responseServerAddress);
        Response testIResponse2 = MessageFactory.create3489BindingResponse(
            discovererAddress, responseServerAddress, responseServerAddress);

        responseServer.addMessage(testIResponse1);
        responseServer.addMessage(testIResponse2);

        StunDiscoveryReport expectedReturn = new StunDiscoveryReport();

        expectedReturn.setNatType(StunDiscoveryReport.OPEN_INTERNET);
        expectedReturn.setPublicAddress(discovererAddress);

        StunDiscoveryReport actualReturn = stunAddressDiscoverer.
            determineAddress();
        assertEquals(expectedReturn, actualReturn,
            "The StunAddressDiscoverer failed for a no-udp environment.");
    }
}
