/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

import junit.framework.*;

/**
 * Contains all tests in the ice4j project.
 *
 * @author Emil Ivov
 */
public class StunTestSuite
    extends TestCase
{

    /**
     * Creates a new instance of the suite
     *
     * @param s test name
     */
    public StunTestSuite(String s)
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

        //attributes
        suite.addTestSuite(org.ice4j.attribute.
                           AddressAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           XorOnlyTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           AttributeDecoderTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           ChangeRequestAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           ErrorCodeAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           UnknownAttributesAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           SoftwareAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.
                           OptionalAttributeAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.UsernameAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.NonceAttributeTest.class);
        suite.addTestSuite(org.ice4j.attribute.RealmAttributeTest.class);

        //messages
        suite.addTestSuite(org.ice4j.message.MessageFactoryTest.class);
        suite.addTestSuite(org.ice4j.message.MessageTest.class);

        //stack
        suite.addTestSuite(org.ice4j.stack.ShallowStackTest.class);

        //event dispatching
        suite.addTestSuite(org.ice4j.MessageEventDispatchingTest.class);
        /*
        //transactions
        suite.addTestSuite(org.ice4j.TransactionSupportTests.class);

        //client
        suite.addTestSuite(org.ice4j.stunclient.StunAddressDiscovererTest.class);
        suite.addTestSuite(org.ice4j.stunclient.StunAddressDiscovererTest_v6.class);
        suite.addTestSuite(org.ice4j.stunclient.StunAddressDiscovererTest_v4v6.class);
*/
        return suite;
    }
}
