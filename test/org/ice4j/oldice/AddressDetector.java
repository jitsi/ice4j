/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.stunclient.*;


/**
 * Detect the public address.
 * 
 * @author Emil Ivov
 */
public class AddressDetector
{
    /**
     * Entry point of the program.
     * @param args array of arguments
     */
    public static void main(String[] args)
        throws Exception
    {
        SimpleAddressDetector detector = new SimpleAddressDetector(
                                new TransportAddress(args.length > 0 ? args[0] : "stun01.sipphone.com", 3478));
        detector.start();
        TransportAddress mappedAddr = detector.getMappingFor(5060);

        System.out.println("address is " + mappedAddr);

        detector.shutDown();
    }
}

