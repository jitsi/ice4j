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

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;
import org.junit.jupiter.api.*;
/**
 *
 * @author Emil Ivov
 */
public class AddressAttributeTest
{
    private AddressAttribute addressAttribute = null;
    private MsgFixture msgFixture;

    @BeforeEach
    public void setUp() throws Exception
    {
        addressAttribute = new MappedAddressAttribute();
        msgFixture = new MsgFixture();
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        addressAttribute = null;
        msgFixture = null;
    }

    /**
     * Verify that AddressAttribute descendants have correctly set types and
     * names.
     */
    @Test
    public void testAddressAttributeDescendants()
    {
        char expectedType;
        char actualType;
        String expectedName;
        String actualName;

        //MAPPED-ADDRESS
        addressAttribute = new MappedAddressAttribute();

        expectedType = Attribute.MAPPED_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "MAPPED-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "MappedAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "MappedAddressAttribute does not the right name.");


        //SOURCE-ADDRESS
        addressAttribute = new SourceAddressAttribute();

        expectedType = Attribute.SOURCE_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "SOURCE-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "SourceAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "SourceAddressAttribute does not the right name.");


        //CHANGED-ADDRESS
        addressAttribute = new ChangedAddressAttribute();

        expectedType = Attribute.CHANGED_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "CHANGED-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "ChangedAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "ChangedAddressAttribute does not the right name.");


        //RESPONSE-ADDRESS
        addressAttribute = new ResponseAddressAttribute();

        expectedType = Attribute.RESPONSE_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "RESPONSE-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "ResponseAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "ResponseAddressAttribute does not the right name.");


        //REFLECTED-FROM
        addressAttribute = new ReflectedFromAttribute();

        expectedType = Attribute.REFLECTED_FROM;
        actualType = addressAttribute.getAttributeType();

        expectedName = "REFLECTED-FROM";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "ReflectedFromAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "ReflectedFromAttribute does not the right name.");

        //REFLECTED-FROM
        addressAttribute = new ReflectedFromAttribute();

        expectedType = Attribute.REFLECTED_FROM;
        actualType = addressAttribute.getAttributeType();

        expectedName = "REFLECTED-FROM";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "ReflectedFromAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "ReflectedFromAttribute does not the right name.");

        //XOR-MAPPED-ADDRESS
        addressAttribute = new XorMappedAddressAttribute();

        expectedType = Attribute.XOR_MAPPED_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "XOR-MAPPED-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "XorMappedAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "XorMappedAddressAttribute does not the right name.");

        /* ALTERNATE-SERVER */
        addressAttribute = new AlternateServerAttribute();

        expectedType = Attribute.ALTERNATE_SERVER;
        actualType = addressAttribute.getAttributeType();

        expectedName = "ALTERNATE-SERVER";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "AlternateServerAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "AlternateAttribute does not the right name.");


        /* XOR-PEER-ADDRESS */
        addressAttribute = new XorPeerAddressAttribute();

        expectedType = Attribute.XOR_PEER_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "XOR-PEER-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "XorPeerAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "XorPeerAddressAttribute does not the right name.");

        /* XOR-RELAYED-ADDRESS */
        addressAttribute = new XorRelayedAddressAttribute();

        expectedType = Attribute.XOR_RELAYED_ADDRESS;
        actualType = addressAttribute.getAttributeType();

        expectedName = "XOR-RELAYED-ADDRESS";
        actualName = addressAttribute.getName();

        assertEquals(expectedType, actualType,
            "XorRelayedAddressAttribute does not the right type.");
        assertEquals(expectedName, actualName,
            "XorRelayedAddressAttribute does not the right name.");
    }

    /**
     * Verifies that xorred address-es are properly xor-ed for IPv4 addresses.
     */
    @Test
    public void testXorMappedAddressXoring_v4()
    {
        XorMappedAddressAttribute addressAttribute = new XorMappedAddressAttribute();
        TransportAddress testAddress =
            new TransportAddress("130.79.95.53", 12120, Transport.UDP);

        addressAttribute.setAddress(testAddress);

        //do a xor with an id equal to the v4 address itself so that we get 0000..,
        TransportAddress xorredAddr = addressAttribute.applyXor(
                new byte[]{(byte)130,79,95,53,0,0,0,0,0,0,0,0,0,0,0,0,0});

        assertArrayEquals(
            xorredAddr.getAddressBytes(), new byte[] { 0, 0, 0, 0 },
            "Xorring the address with itself didn't return 00000...");

        assertNotEquals(xorredAddr.getPort(), testAddress.getPort(),
            "Port was not xorred");

        //Test xor-ing the original with the xored - should get the xor code
        addressAttribute.setAddress(testAddress);
        xorredAddr = addressAttribute.applyXor(
                new byte[]{21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36});

        xorredAddr =
            addressAttribute.applyXor(xorredAddr.getAddressBytes());

        assertArrayEquals(
            xorredAddr.getAddressBytes(), new byte[] { 21, 22, 23, 24 },
            "Xorring the original with the xor-ed didn't return the code.");

        assertNotEquals(0xFFFF, testAddress.getPort(), "Port was not xorred");

        //Test double xor-ing - should get the original
        addressAttribute.setAddress(testAddress);
        xorredAddr = addressAttribute.applyXor(
                new byte[]{21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36});

        addressAttribute.setAddress(xorredAddr);
        xorredAddr = addressAttribute.applyXor(
                new byte[]{21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36});

        assertEquals(testAddress, xorredAddr,
            "Double xorring didn't give the original");
    }

    /**
     * Verifies that xorred address-es are properly xor-ed for IPv6 addresses.
     */
    @Test
    public void testXorMappedAddressXoring_v6()
    {
        XorMappedAddressAttribute addressAttribute
            = new XorMappedAddressAttribute();
        TransportAddress testAddress = new TransportAddress(
                "2001:660:4701:1001:202:8aff:febe:130b", 12120, Transport.UDP);

        addressAttribute.setAddress(testAddress);

        //do a xor with an id equal to the v4 address itself so that we get 0000..,
        TransportAddress xorredAddr =
            addressAttribute.applyXor(
                new byte[]{(byte)0x20, (byte)0x01, (byte)0x06, (byte)0x60,
                           (byte)0x47, (byte)0x01, (byte)0x10, (byte)0x01,
                           (byte)0x02, (byte)0x02, (byte)0x8a, (byte)0xff,
                           (byte)0xfe, (byte)0xbe, (byte)0x13, (byte)0x0b});

        assertArrayEquals(
            xorredAddr.getAddressBytes(), new byte[] { 0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0 },
            "Xorring the address with itself didn't return 00000...");

        assertNotEquals(testAddress.getPort(), xorredAddr.getPort(),
            "Port was not xorred");

        //Test xor-ing the original with the xored - should get the xor code
        addressAttribute.setAddress(testAddress);
        xorredAddr = addressAttribute.applyXor(
                  new byte[]{21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36});

        xorredAddr = addressAttribute.applyXor(xorredAddr.getAddressBytes());

        assertArrayEquals(
            xorredAddr.getAddressBytes(),
            new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
                35, 36 },
            "Xorring the original with the xor-ed didn't return the code.");
        
        assertNotEquals(0xFFFF, testAddress.getPort(), "Port was not xorred");

        //Test double xor-ing - should get the original
        addressAttribute.setAddress(testAddress);
        xorredAddr = addressAttribute.applyXor(
                  new byte[]{21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36});

        addressAttribute.setAddress(xorredAddr);
        xorredAddr = addressAttribute.applyXor(
                  new byte[]{21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36});

        assertEquals(testAddress, xorredAddr,
            "Double xorring didn't give the original");
    }

    /**
     * Test whether sample binary arrays are correctly decoded.
     *
     * @throws StunException if something goes wrong
     */
    @Test
    public void testDecodeAttributeBody() throws StunException {
        byte[] attributeValue = msgFixture.mappedAddress;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(attributeValue.length - offset);

        addressAttribute.decodeAttributeBody(attributeValue, offset, length);


        assertEquals(
            MsgFixture.ADDRESS_ATTRIBUTE_PORT, addressAttribute.getPort(),
            "AddressAttribute.decode() did not properly decode the port field.");
        assertArrayEquals(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
            addressAttribute.getAddressBytes(),
            "AddressAttribute.decode() did not properly decode the address field.");


    }

    /**
     * Test whetner sample binary arrays are correctly decoded.
     * @throws StunException if something goes wrong
     */
    @Test
    public void testDecodeAttributeBodyv6() throws StunException {
        byte[] attributeValue = msgFixture.mappedAddressv6;
        char offset = Attribute.HEADER_LENGTH;
        char length = (char)(attributeValue.length - offset);

        addressAttribute.decodeAttributeBody(attributeValue, offset, length);


        assertEquals(MsgFixture.ADDRESS_ATTRIBUTE_PORT,
                     addressAttribute.getPort(),
            "decode() failed for an IPv6 Addr's port.");
        assertArrayEquals(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6,
            addressAttribute.getAddressBytes(),
            "AddressAttribute.decode() failed for an IPv6 address.");
    }

    /**
     * Test whether attributes are properly encoded.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    @Test
    public void testEncode()
        throws Exception
    {
        byte[] expectedReturn = msgFixture.mappedAddress;

        addressAttribute.setAddress(
            new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
                                 MsgFixture.ADDRESS_ATTRIBUTE_PORT,
                                 Transport.UDP));

        byte[] actualReturn = addressAttribute.encode();
        assertArrayEquals(expectedReturn, actualReturn,
            "AddressAttribute.encode() did not properly encode a sample attribute");
    }

    /**
     * Test whether attributes are properly encoded.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    @Test
    public void testEncodev6()
        throws Exception
    {
        byte[] expectedReturn = msgFixture.mappedAddressv6;

        addressAttribute.setAddress(
            new TransportAddress(MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6,
                        MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));

        byte[] actualReturn = addressAttribute.encode();
        assertArrayEquals(expectedReturn, actualReturn,
            "An AddressAttribute did not properly encode an IPv6 addr.");
    }


    /**
     * Tests the equals method against a null, a different and an identical
     * object.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    @Test
    public void testEquals()
        throws Exception
    {
        //null test
        AddressAttribute target = null;
        boolean expectedReturn = false;
        boolean actualReturn = addressAttribute.equals(target);

        assertEquals(expectedReturn, actualReturn,
            "AddressAttribute.equals() failed against a null target.");

        //difference test
        target = new MappedAddressAttribute();

        char port = (char)(MsgFixture.ADDRESS_ATTRIBUTE_PORT + 1 );
        target.setAddress(  new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS, port, Transport.UDP));

        addressAttribute.setAddress( new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT,
            Transport.UDP));

        expectedReturn = false;
        actualReturn = addressAttribute.equals(target);
        assertEquals(expectedReturn, actualReturn,
            "AddressAttribute.equals() failed against a different target.");

        //equality test
        target.setAddress( new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP ));

        expectedReturn = true;
        actualReturn = addressAttribute.equals(target);
        assertEquals(expectedReturn, actualReturn,
            "AddressAttribute.equals() failed against an equal target.");

        //ipv6 equality test
        target.setAddress(  new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));

        addressAttribute.setAddress(new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT,
            Transport.UDP));

        expectedReturn = true;
        actualReturn = addressAttribute.equals(target);
        assertEquals(expectedReturn, actualReturn,
            "AddressAttribute.equals() failed for IPv6 addresses.");
    }

    /**
     * Tests whether data length is properly calculated.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    @Test
    public void testGetDataLength()
        throws Exception
    {
        char expectedReturn = 8;//1-padding + 1-family + 2-port + 4-address

        addressAttribute.setAddress( new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT,
            Transport.UDP));

        char actualReturn = addressAttribute.getDataLength();

        assertEquals(expectedReturn, actualReturn,
            "Datalength is not propoerly calculated");

        expectedReturn = 20;//1-padding + 1-family + 2-port + 16-address
        addressAttribute.setAddress( new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));

        actualReturn = addressAttribute.getDataLength();

        assertEquals(expectedReturn, actualReturn,
            "Datalength is not propoerly calculated");
    }

    /**
     * Tests that the address family is always 1.
     *
     * @throws Exception java.lang.Exception if we fail
     */
    @Test
    public void testGetFamily()
        throws Exception
    {
        byte expectedReturn = 1;
        addressAttribute.setAddress(new TransportAddress(
            MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS,
            MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        byte actualReturn = addressAttribute.getFamily();
        assertEquals(expectedReturn, actualReturn,
            "Address family was not 1 for an IPv4");

        //ipv6
        expectedReturn = 2;
        addressAttribute.setAddress(new TransportAddress(
                       MsgFixture.ADDRESS_ATTRIBUTE_ADDRESS_V6,
                       MsgFixture.ADDRESS_ATTRIBUTE_PORT, Transport.UDP));
        actualReturn = addressAttribute.getFamily();
        assertEquals(expectedReturn, actualReturn,
            "Address family was not 2 for an IPv6 address");
    }
}
