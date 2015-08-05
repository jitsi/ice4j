/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import junit.framework.*;

/**
 * Contains pseudo TCP tests.
 *
 * @author Pawel Domas
 */
public class PseudoTcpTestSuite
    extends TestCase
{

    /**
     * Creates a new instance of the suite
     *
     * @param s test name
     */
    public PseudoTcpTestSuite(String s)
    {
        super(s);
    }

    /**
     * Returns the suite of tests to run.
     * @return the suite of tests to run.
     */
    public static Test suite()
    {
        TestSuite suite = new TestSuite();

        // byte fifo buffer
        suite.addTestSuite(org.ice4j.pseudotcp.util.ByteFifoBufferTest.class);
        // transfer
        suite.addTestSuite(org.ice4j.pseudotcp.PseudoTcpTestTransfer.class);
        // ping pong
        suite.addTestSuite(org.ice4j.pseudotcp.PseudoTcpTestPingPong.class);
        // receive window
        suite.addTestSuite(org.ice4j.pseudotcp.PseudoTcpTestRecvWindow.class);
        // stream
        suite.addTestSuite(org.ice4j.pseudotcp.PseudoTcpStreamTest.class);

        return suite;
    }
}
