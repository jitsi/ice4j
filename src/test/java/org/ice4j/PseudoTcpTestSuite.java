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
