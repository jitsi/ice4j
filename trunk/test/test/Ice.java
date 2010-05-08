/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package test;

import java.beans.*;
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
     * Start time for debugging purposes.
     */
    static long startTime;

    /**
     * Runs the test
     * @param args command line arguments
     *
     * @throws Throwable if bad stuff happens.
     */
    public static void main(String[] args) throws Throwable
    {
        startTime = System.currentTimeMillis();

        Agent localAgent = createAgent(9090);
        Agent remotePeer = createAgent(6060);

        localAgent.addStateChangeListener(new IceProcessingListener());

        //let them fight ... fights forge character.
        localAgent.setControlling(true);
        remotePeer.setControlling(false);

        long endTime = System.currentTimeMillis();

        transferRemoteCandidates(localAgent, remotePeer);
        localAgent.setRemoteUfrag(remotePeer.getLocalUfrag());
        localAgent.setRemotePassword(remotePeer.getLocalPassword());

        remotePeer.setRemoteUfrag(localAgent.getLocalUfrag());
        remotePeer.setRemotePassword(localAgent.getLocalPassword());

        System.out.println("Total candidate gathering time: "
                        + (endTime - startTime) + "ms");
        System.out.println("LocalAgent:\n" + localAgent);

        localAgent.startConnectivityEstablishment();

        System.out.println("Local audio clist:\n"
                        + localAgent.getStream("audio").getCheckList());

        IceMediaStream videoStream = localAgent.getStream("video");

        if(videoStream != null)
            System.out.println("Local video clist:\n"
                            + videoStream.getCheckList());

        //Give processing enough time to finish. We'll System.exit() anyway
        //as soon as localAgent enters a final state.
        Thread.sleep(60000);
    }

    /**
     * The listener that would end example execution once we enter the
     * completed state.
     */
    public static final class IceProcessingListener
        implements PropertyChangeListener
    {
        /**
         * System.exit()s as soon as ICE processing enters a final state.
         *
         * @param evt the {@link PropertyChangeEvent} containing the old and new
         * states of ICE processing.
         */
        public void propertyChange(PropertyChangeEvent evt)
        {
            long processingEndTime = System.currentTimeMillis();

            System.out.println("Agent entered the " + evt.getNewValue()
                            + " state.");
            if(evt.getNewValue() == IceProcessingState.COMPLETED
               || evt.getNewValue() == IceProcessingState.FAILED)
            {
                System.out.println("Total ICE processing time: "
                                + (processingEndTime - startTime) + "ms");
                Agent agent = (Agent)evt.getSource();
                List<IceMediaStream> streams = agent.getStreams();

                for(IceMediaStream stream : streams)
                {
                    String streamName = stream.getName();
                    System.out.println("Pairs selected for stream: "
                                        + streamName);
                    List<Component> components = stream.getComponents();

                    for(Component cmp : components)
                    {
                        String cmpName = cmp.getName();
                        System.out.println(cmpName + ": "
                                        + cmp.getSelectedPair());
                    }
                }

                System.out.println("Printing the check lists:");
                for(IceMediaStream stream : streams)
                {
                    String streamName = stream.getName();
                    System.out.println("Check list for  stream: "
                                        + streamName);
                    //uncomment for a more verbose output
                    System.out.println(stream.getCheckList());
                }
            }
            else if(evt.getNewValue() == IceProcessingState.TERMINATED)
            {
                System.exit(0);
            }
        }
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
        //createStream(rtpPort + 2, "video", agent);

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
        agent.createComponent(
                stream, Transport.UDP, rtpPort, rtpPort, rtpPort + 100);

        long endTime = System.currentTimeMillis();
        System.out.println("RTP Component created in "
                        + (endTime - startTime) +" ms");
        startTime = endTime;
        //rtcpComp
        //agent.createComponent(
        //        stream, Transport.UDP, rtpPort + 1, rtpPort + 1, rtpPort + 101);

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
