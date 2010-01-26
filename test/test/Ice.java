/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package test;

import org.ice4j.*;
import org.ice4j.ice.*;

/**
 * Simple ice4j testing scenarios.
 *
 * @author Emil Ivov
 */
public class Ice
{

    /**
     * Runs the test
     * @param args cmd line args
     */
    public static void main(String[] args)
    {
        Agent agent = new Agent();
        IceMediaStream stream = agent.createMediaStream("audio");

        //rtp
        //Component rtpComp = stream.createComponent(Transport.UDP, 9090);
        //rtcpComp
        //Component rtcpComp = stream.createComponent(Transport.UDP, 9091);
    }

}
