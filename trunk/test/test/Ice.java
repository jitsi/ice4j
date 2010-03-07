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
     * @param args command line arguments
     *
     * @throws Throwable if bad stuff happens.
     */
    public static void main(String[] args) throws Throwable
    {
        long startTime = System.currentTimeMillis();

        Agent localAgent = createAgent(9090);
        Agent remotePeer = createAgent(6060);

        localAgent.setControlling(true);
        remotePeer.setControlling(false);

        long endTime = System.currentTimeMillis();

        transferRemoteCandidates(localAgent, remotePeer);

        System.out.println("Total candidate gathering time: "
                        + (endTime - startTime) + "ms");
        System.out.println("LocalAgent:\n" + localAgent);

        localAgent.startChecks();

        System.out.println("Local audio clist:\n" + localAgent.getCheckList());

        System.out.println("Total execution time: "
                        + (endTime - startTime) + "ms");
    }

    /**
     * Installs remote candidates in <tt>localAgent</tt>..
     *
     * @param localAgent a reference to the agent that we will pretend to be the
     * local
     * @param remotePeer a reference to what we'll pretend to be a remote agent.
     */
    private static void transferRemoteCandidates(Agent localAgent,
                                                 Agent remotePeer)
    {
        List<IceMediaStream> streams = localAgent.getStreams();

        for(IceMediaStream localStream : streams)
        {
            String streamName = localStream.getName();

            //get a reference to the local stream
            IceMediaStream remoteStream = remotePeer.getStream(streamName);

            if(remoteStream != null)
                transferRemoteCandidates(localStream, remoteStream);
            else
            {
                localAgent.removeStream(localStream);
            }
        }
    }

    /**
     * Installs remote candidates in <tt>localStream</tt>..
     *
     * @param localStream the stream where we will be adding remote candidates
     * to.
     * @param remoteStream the stream that we should extract remote candidates
     * from.
     */
    private static void transferRemoteCandidates(IceMediaStream localStream,
                                                 IceMediaStream remoteStream)
    {
        List<Component> localComponents = localStream.getComponents();

        for(Component localComponent : localComponents)
        {
            int id = localComponent.getComponentID();

            Component remoteComponent = remoteStream.getComponnet(id);

            if(remoteComponent != null)
                transferRemoteCandidates(localComponent, remoteComponent);
            else
            {
                localStream.removeComponent(localComponent);
            }
        }
    }

    /**
     * Adds to <tt>localComponent</tt> a list of remote candidates that are
     * actually the local candidates from <tt>remoteComponent</tt>.
     *
     * @param localComponent the <tt>Component</tt> where that we should be
     * adding <tt>remoteCandidate</tt>s to.
     * @param remoteComponent the source of remote candidates.
     */
    private static void transferRemoteCandidates(Component localComponent,
                                                 Component remoteComponent)
    {
        List<LocalCandidate> remoteCandidates
                                = remoteComponent.getLocalCandidates();

        localComponent.setDefaultRemoteCandidate(
                        remoteComponent.getDefaultCandidate());

        for(Candidate rCand : remoteCandidates)
        {
            localComponent.addRemoteCandidate(new RemoteCandidate(
                            rCand.getTransportAddress(),
                            localComponent,
                            rCand.getType(),
                            rCand.getFoundation(),
                            rCand.getPriority()));
        }
    }

    /**
     * Creates an ICE <tt>Agent</tt> and adds to it an audio and a video stream
     * with RTP and RTCP components.
     *
     * @param rtpPort the port that we should try to bind the RTP component on
     * (the RTCP one would automatically go to rtpPort + 1)
     * @return an ICE <tt>Agent</tt> with an audio stream with RTP and RTCP
     * components.
     *
     * @throws Throwable if anything goes wrong.
     */
    private static Agent createAgent(int rtpPort)
        throws Throwable
    {
        Agent agent = new Agent();

        StunCandidateHarvester stunHarv = new StunCandidateHarvester(
            new TransportAddress("sip-communicator.net", 3478, Transport.UDP));
        StunCandidateHarvester stun6Harv = new StunCandidateHarvester(
            new TransportAddress("ipv6.sip-communicator.net",
                                 3478, Transport.UDP));

        agent.addCandidateHarvester(stunHarv);
        agent.addCandidateHarvester(stun6Harv);

        createStream(rtpPort, "audio", agent);
        createStream(rtpPort + 2, "video", agent);

        return agent;
    }

    /**
     * Creates an <tt>IceMediaStrean</tt> and adds to it an RTP and and RTCP
     * component.
     *
     * @param rtpPort the port that we should try to bind the RTP component on
     * (the RTCP one would automatically go to rtpPort + 1)
     * @param streamName the name of the stream to create
     * @param agent the <tt>Agent</tt> that should create the stream.
     *
     *@return the newly created <tt>IceMediaStream</tt>.
     * @throws Throwable if anything goes wrong.
     */
    private static IceMediaStream createStream(int    rtpPort,
                                               String streamName,
                                               Agent  agent)
        throws Throwable
    {
        IceMediaStream stream = agent.createMediaStream(streamName);

        long startTime = System.currentTimeMillis();

        //TODO: component creation should probably be part of the library. it
        //should also be started after we've defined all components to be
        //created so that we could run the harvesting for everyone of them
        //simultaneously with the others.

        //rtp
        Component rtpComp = agent.createComponent(
                stream, Transport.UDP, rtpPort, rtpPort, rtpPort + 100);

        long endTime = System.currentTimeMillis();
        System.out.println("RTP Component created in "
                        + (endTime - startTime) +" ms");
        startTime = endTime;
        //rtcpComp
        Component rtcpComp = agent.createComponent(
                stream, Transport.UDP, rtpPort + 1, rtpPort + 1, rtpPort + 101);

        endTime = System.currentTimeMillis();
        System.out.println("RTCP Component created in "
                        + (endTime - startTime) +" ms");

        return stream;
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
