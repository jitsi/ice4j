/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package test;

import java.lang.reflect.*;
import java.net.*;
import java.util.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.ice.harvest.*;

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
     *
     * @throws Throwable if bad stuff happens.
     */
    public static void main(String[] args) throws Throwable
    {
        Agent agent = new Agent();

        StunCandidateHarvester stunHarv = new StunCandidateHarvester(
            new TransportAddress("sip-communicator.net", 3478, Transport.UDP));
        StunCandidateHarvester stun6Harv = new StunCandidateHarvester(
            new TransportAddress("ipv6.sip-communicator.net",
                                 3478, Transport.UDP));

        agent.addCandidateHarvester(stunHarv);
        agent.addCandidateHarvester(stun6Harv);

        IceMediaStream stream = agent.createMediaStream("audio");

        long startTime = System.currentTimeMillis();
        //rtp
        Component rtpComp = agent.createComponent(
                        stream, Transport.UDP, 9090, 9090, 10000);
        System.out.println("rtpComp:" + rtpComp);
        long endTime = System.currentTimeMillis();
        System.out.println("Componente created in "
                        + (endTime - startTime) +" ms");
        startTime = endTime;
        //rtcpComp
        Component rtcpComp = agent.createComponent(
                        stream, Transport.UDP, 9091, 9090, 10000);

        System.out.println("rtcpComp:" + rtcpComp);
        endTime = System.currentTimeMillis();
        System.out.println("Componente created in "
                        + (endTime - startTime) +" ms");
    }

    /**
     * Runs the test
     * @param args cmd line args
     *
     * @throws Throwable if bad stuff happens.
     */
    public static void main2(String[] args) throws Throwable
    {
        //Agent agent = new Agent();
        //IceMediaStream stream = agent.createMediaStream("audio");

        //rtp
        //Component rtpComp = stream.createComponent(Transport.UDP, 9090);
        //rtcpComp
        //Component rtcpComp = stream.createComponent(Transport.UDP, 9091);

        // find a loopback interface


        Enumeration<NetworkInterface> interfaces
                                    = NetworkInterface.getNetworkInterfaces();

        while (interfaces.hasMoreElements())
        {
            NetworkInterface iface = interfaces.nextElement();

            System.out.println(iface.getName()
                            + " isLoopback=" + isLoop(iface));
            System.out.println(iface.getName()
                            + " isUp=" + isUp(iface));
            System.out.println(iface.getName()
                            + " isVirtual=" + isVirtual(iface));
        }
    }

    public static boolean isLoop(NetworkInterface iface)
    {
        try
        {
            Method method = iface.getClass().getMethod("isLoopback");

            System.out.println("It works!");

            return ((Boolean)method.invoke(iface)).booleanValue();
        }
        catch(Throwable t)
        {
            //apparently we are not running in a JVM that supports the
            //is Loopback method. we'll try another approach.
            System.out.println("Doesn't work");
        }

        Enumeration<InetAddress> addresses = iface.getInetAddresses();

        return addresses.hasMoreElements()
            && addresses.nextElement().isLoopbackAddress();
    }

    public static boolean isUp(NetworkInterface iface)
    {
        try
        {
            Method method = iface.getClass().getMethod("isUp");

            System.out.println("It works!");

            return ((Boolean)method.invoke(iface)).booleanValue();
        }
        catch(Throwable t)
        {
            //apparently we are not running in a JVM that supports the
            //is Loopback method. we'll try another approach.
            System.out.println("Doesn't work");
        }

        return true;
    }

    public static boolean isVirtual(NetworkInterface iface)
    {
        try
        {
            Method method = iface.getClass().getMethod("isVirtual");

            System.out.println("It works!");

            return ((Boolean)method.invoke(iface)).booleanValue();
        }
        catch(Throwable t)
        {
            //apparently we are not running in a JVM that supports the
            //is Loopback method. we'll try another approach.
            System.out.println("Doesn't work");
        }

        return false;
    }
}
