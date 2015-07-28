/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import junit.framework.*;

import java.util.*;

import org.ice4j.*;

/**
 * @author Emil Ivov
 */
public class XorOnlyTest extends TestCase
{
    private XorOnlyAttribute xorOnly = null;
    private MsgFixture msgFixture = null;

    protected void setUp() throws Exception
    {
        super.setUp();
        xorOnly = new XorOnlyAttribute();
        msgFixture = new MsgFixture();
    }

    protected void tearDown() throws Exception
    {
        xorOnly = null;
        msgFixture = null;
        super.tearDown();
    }

    /**
     * Just makes sure that no exceptions are thrown when calling it as the
     * decode method doesn't do anything in the XorOnly att.
     * @throws StunException if sth happens
     */
    public void testDecodeAttributeBody() throws StunException
    {
        byte[] attributeValue = new byte[]{};
        char offset = 0;
        char length = 0;
        xorOnly.decodeAttributeBody(attributeValue, offset, length);
    }

    /**
     * Test encoding XorOnly attributes.
     */
    public void testEncode()
    {
        byte[] expectedReturn = new byte[]{Attribute.XOR_ONLY>>8,
                                           Attribute.XOR_ONLY&0x00FF,
                                            0, 0};
        byte[] actualReturn = xorOnly.encode();
        assertTrue("XorOnly failed to encode",
                     Arrays.equals( expectedReturn, actualReturn));
    }

    /**
     * Test positive and negative XorOnly.equals() returns
     * @throws Exception if decoding fails
     */
    public void testEquals() throws Exception
    {
        XorOnlyAttribute xor2 = new XorOnlyAttribute();
        assertEquals("equals() failes for XorOnly", xorOnly, xor2);

        MappedAddressAttribute maatt =  new MappedAddressAttribute();
        maatt.decodeAttributeBody( msgFixture.mappedAddress,
                                   (char) 0,
                                   (char) msgFixture.mappedAddress.length );


        assertFalse("equals failed to see a difference", xorOnly.equals(maatt));
        assertFalse("equals failed for null", xorOnly.equals(null));
    }

    /**
     * Makes sure the data langth is 0
     */
    public void testGetDataLength()
    {
        char expectedReturn = 0;
        char actualReturn = xorOnly.getDataLength();
        assertEquals("data length was not 0", expectedReturn, actualReturn);
    }

    /**
     * Verifies the name (do we really need this?).
     */
    public void testGetName()
    {
        String expectedReturn = "XOR-ONLY";
        String actualReturn = xorOnly.getName();
        assertEquals("Is name correct", expectedReturn, actualReturn);
    }
}
