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
 * Discover the connection type.
 *
 * @author Emil Ivov
 */
public class Discovery 
{
    /**
     * Entry point of the program.
     * @param args array of arguments
     */
    public static void main(String[] args)
        throws Exception
    {
        TransportAddress localAddr = null;
        TransportAddress serverAddr = null;
        if(args.length == 4)
        {
            localAddr = new TransportAddress(args[2],
                                        Integer.valueOf(args[3]).intValue());
            serverAddr = new TransportAddress(args[0],
                                         Integer.valueOf(args[1]).intValue());
        }
        else
        {
            localAddr = new TransportAddress(InetAddress.getLocalHost(), 5678);
            serverAddr = new TransportAddress("stun01.sipphone.com", 3478);
        }

        NetworkConfigurationDiscoveryProcess addressDiscovery
            = new NetworkConfigurationDiscoveryProcess(localAddr, serverAddr);

        addressDiscovery.start();
        StunDiscoveryReport report = addressDiscovery.determineAddress();
        System.out.println(report);
        System.exit(0);
    }
}

