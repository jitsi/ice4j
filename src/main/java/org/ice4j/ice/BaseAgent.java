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
package org.ice4j.ice;

import java.io.*;
import java.math.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.stack.*;

/**
 * Implements a (common) base of full and lite ICE agents (within the ice4j
 * library).
 *
 * @author Lyubomir Marinov
 */
public class BaseAgent
{
    /**
     * The <tt>Logger</tt> used by the <tt>BaseAgent</tt> class and its
     * instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(BaseAgent.class.getName());

    /**
     * Adds or removes ICE characters (i.e. ALPHA, DIGIT, +, or /) to or from a
     * specific <tt>String</tt> in order to produce a <tt>String</tt> with a
     * length within a specific range.
     *
     * @param s the <tt>String</tt> to add or remove characters to or from in
     * case its length is less than <tt>min</tt> or greater than <tt>max</tt>
     * @param min the minimum length in (ICE) characters of the returned
     * <tt>String</tt>
     * @param max the maximum length in (ICE) characters of the returned
     * <tt>String</tt>
     * @return <tt>s</tt> if its length is greater than or equal to
     * <tt>min</tt> and less than or equal to <tt>max</tt>; a new
     * <tt>String</tt> which is equal to <tt>s</tt> with prepended ICE
     * characters if the length of <tt>s</tt> is less than <tt>min</tt>; a new
     * <tt>String</tt> which is composed of the first <tt>max</tt> characters of
     * <tt>s</tt> if the length of <tt>s</tt> is greater than <tt>max</tt>
     * @throws IllegalArgumentException if <tt>min</tt> is negative or
     * <tt>max</tt> is less than <tt>min</tt>
     * @throws NullPointerException if <tt>s</tt> is equal to <tt>null</tt>
     */
    private static String ensureIceAttributeLength(String s, int min, int max)
    {
        if (s == null)
            throw new NullPointerException("s");
        if (min < 0)
            throw new IllegalArgumentException("min " + min);
        if (max < min)
            throw new IllegalArgumentException("max " + max);

        int length = s.length();
        int numberOfIceCharsToAdd = min - length;

        if (numberOfIceCharsToAdd > 0)
        {
            StringBuilder sb = new StringBuilder(min);

            for (; numberOfIceCharsToAdd > 0; --numberOfIceCharsToAdd)
            {
                sb.append('0');
            }
            sb.append(s);
            s = sb.toString();
        }
        else if (max < length)
        {
            s = s.substring(0, max);
        }
        return s;
    }

    /**
     * The entity that will be taking care of incoming connectivity checks.
     */
    private final ConnectivityCheckServer connCheckServer;

    /**
     * Determines whether this is the controlling agent in a an ICE interaction.
     * The default value of {@code BaseAgent} is {@code false} since it is
     * unable to perform connectivity checks.
     */
    private boolean controlling = false;

    /**
     * We use the <tt>FoundationsRegistry</tt> to keep track of the foundations
     * we assign within a session (i.e. the entire life time of a
     * <tt>BaseAgent</tt>.)
     */
    private final FoundationsRegistry foundationsRegistry
        = new FoundationsRegistry();

    /**
     * The candidate harvester that we use to gather candidate on the local
     * machine.
     */
    private final HostCandidateHarvester hostHarvester
        = new HostCandidateHarvester();

    /**
     * A list of additional <tt>CandidateHarvester</tt>s which will be used to
     * harvest candidates synchronously, and previously to harvesting by
     * non-host <tt>CandidateHarvester</tt>s (if implemented by extenders).
     */
    private final List<CandidateHarvester> hostHarvesters = new LinkedList<>();

    /**
     * The <tt>LinkedHashMap</tt> used to store the <tt>IceMediaStream</tt>s.
     * Preserves the insertion order.
     */
    private final Map<String, IceMediaStream> mediaStreams
        = new LinkedHashMap<>();

    /**
     * The password that we should use for the ice-pwd attribute.
     */
    private final String password;

    protected final SecureRandom random = new SecureRandom();

    /**
     * The <tt>StunStack</tt> used by this <tt>BaseAgent</tt>.
     */
    private StunStack stunStack;

    /**
     * The user fragment that we should use for the ice-ufrag attribute.
     */
    private final String ufrag;

    /**
     * The flag which specifies whether {@link #hostHarvester} is (to be) used.
     */
    private Boolean useHostHarvester;

    /**
     * Creates an empty <tt>BaseAgent</tt> with no streams, and no address.
     */
    public BaseAgent()
    {
        connCheckServer = new ConnectivityCheckServer(this);

        //add the FINGERPRINT attribute to all messages.
        System.setProperty(StackProperties.ALWAYS_SIGN, "true");

        //add the software attribute to all messages
        if (StackProperties.getString(StackProperties.SOFTWARE) == null)
            System.setProperty(StackProperties.SOFTWARE, "ice4j.org");

        ufrag
            = ensureIceAttributeLength(
                    new BigInteger(24, random).toString(32)
                        + BigInteger
                            .valueOf(System.currentTimeMillis())
                                .toString(32),
                    /* min */ 4, /* max */ 256);
        password
            = ensureIceAttributeLength(
                    new BigInteger(128, random).toString(32),
                    /* min */ 22, /* max */ 256);
    }

    /**
     * Adds <tt>harvester</tt> to the list of host harvesters that this agent
     * will use when gathering <tt>Candidate</tt>s.
     *
     * @param harvester a <tt>CandidateHarvester</tt> that this agent should use
     * when gathering candidates.
     */
    protected void addHostHarvester(CandidateHarvester harvester)
    {
        if (harvester.isHostHarvester())
            hostHarvesters.add(harvester);
        else
            throw new IllegalArgumentException("harvester.isHostHarvester");
    }

    /**
     * Returns the number of host {@link Candidate}s in this {@code BaseAgent}.
     *
     * @return the number of host {@link Candidate}s in this {@code BaseAgent}.
     */
    protected int countHostCandidates()
    {
        int num = 0;

        synchronized (mediaStreams)
        {
            Collection<IceMediaStream> streamsCol = mediaStreams.values();

            for( IceMediaStream stream : streamsCol)
                num += stream.countHostCandidates();
        }

        return num;
    }

    /**
     * Creates a new {@link Component} for the specified <tt>stream</tt> and
     * allocates potentially all local candidates that should belong to it.
     *
     * @param stream the {@link IceMediaStream} that the new {@link Component}
     * should belong to.
     * @param transport the transport protocol used by the component
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @return the newly created {@link Component} and with a list containing
     * all and only local candidates.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort >
     * maxPort</tt>, or if <tt>transport</tt> is not currently supported.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is using sockets.
     * @throws BindException if we couldn't find a free port between
     * <tt>minPort</tt> and <tt>maxPort</tt> before reaching the maximum allowed
     * number of retries.
     */
    public Component createComponent(
            IceMediaStream stream,
            Transport transport,
            int preferredPort, int minPort, int maxPort)
        throws IllegalArgumentException,
               IOException,
               BindException
    {
        if(transport != Transport.UDP)
        {
            throw new IllegalArgumentException(
                    "This implementation does not currently support transport: "
                        + transport);
        }

        Component component = stream.createComponent();

        gatherCandidatesAndSelectDefaultCandidate(
                component,
                preferredPort, minPort, maxPort);

        for(Candidate<?> candidate : component.getLocalCandidates())
        {
            logger.info(
                    "\t" + candidate.getTransportAddress() + " ("
                        + candidate.getType() + ")");
        }

        /*
         * Lyubomir: After we've gathered the LocalCandidate for a Component and
         * before we've made them available to the caller, we have to make sure
         * that the ConnectivityCheckServer is started. If there's been a
         * previous connectivity establishment which has completed, it has
         * stopped the ConnectivityCheckServer. If the ConnectivityCheckServer is
         * not started after we've made the gathered LocalCandidates available
         * to the caller, the caller may send them and a connectivity check may
         * arrive from the remote Agent.
         */
        connCheckServer.start();

        return component;
    }

    /**
     * Creates a new media stream and stores it.
     *
     * @param mediaStreamName the name of the media stream
     * @return the newly created and stored <tt>IceMediaStream</tt>
     */
    public IceMediaStream createMediaStream(String mediaStreamName)
    {
        logger.fine("Create media stream for " + mediaStreamName);

        IceMediaStream mediaStream = new IceMediaStream(this, mediaStreamName);

        mediaStreams.put(mediaStreamName, mediaStream);

        return mediaStream;
    }

    /**
     * Returns the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@code BaseAgent}'s
     * streams or <tt>null</tt> if it doesn't.
     *
     * @param localAddress the {@link TransportAddress} we are looking for.
     *
     * @return the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@code BaseAgent}'s
     * streams or <tt>null</tt> if it doesn't.
     */
    public LocalCandidate findLocalCandidate(TransportAddress localAddress)
    {
        for(IceMediaStream stream : mediaStreams.values())
        {
            LocalCandidate cnd = stream.findLocalCandidate(localAddress);

            if(cnd != null)
                return cnd;
        }
        return null;
    }

    /**
     * Returns the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@code BaseAgent}'s
     * streams or <tt>null</tt> if it doesn't.
     *
     * @param localAddress the {@link TransportAddress} we are looking for.
     * @param ufrag local ufrag
     * @return the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@code BaseAgent}'s
     * streams or <tt>null</tt> if it doesn't.
     */
    public LocalCandidate findLocalCandidate(
            TransportAddress localAddress,
            String ufrag)
    {
        for(IceMediaStream stream : mediaStreams.values())
        {
            for(Component c : stream.getComponents())
            {
                for(LocalCandidate cnd : c.getLocalCandidates())
                {
                    if(cnd != null
                            && cnd.getUfrag() != null
                            && cnd.getUfrag().equals(ufrag))
                    {
                        return cnd;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Uses all <tt>CandidateHarvester</tt>s currently registered with this
     * <tt>Agent</tt> to obtain whatever addresses they can discover.
     * <p>
     * Not that the method would only use existing harvesters so make sure
     * you've registered all harvesters that you would want to use before
     * calling it.
     * </p>
     * @param component the <tt>Component</tt> that we'd like to gather
     * candidates for.
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort &gt;
     * maxPort</tt>.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is gathering candidates and we end up without even a single one.
     */
    protected void gatherCandidates(
            Component component,
            int preferredPort, int minPort, int maxPort)
        throws IllegalArgumentException,
               IOException
    {
        logger.info(
                "Gather candidates for component " + component.toShortString());

        if (useHostHarvester())
        {
            hostHarvester.harvest(
                    component,
                    preferredPort, minPort, maxPort,
                    Transport.UDP);
        }
        else if (hostHarvesters.isEmpty())
        {
            logger.warning("No host harvesters available!");
        }

        for (CandidateHarvester harvester : hostHarvesters)
        {
            harvester.harvest(component);
        }

        if (component.getLocalCandidateCount() == 0)
            logger.warning("Failed to gather any host candidates!");
    }

    /**
     * Uses all <tt>CandidateHarvester</tt>s currently registered with this
     * <tt>Agent</tt> to obtain whatever addresses they can discover.
     * <p>
     * Not that the method would only use existing harvesters so make sure
     * you've registered all harvesters that you would want to use before
     * calling it.
     * </p>
     * @param component the <tt>Component</tt> that we'd like to gather
     * candidates for.
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort &gt;
     * maxPort</tt>.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is gathering candidates and we end up without even a single one.
     */
    private void gatherCandidatesAndSelectDefaultCandidate(
            Component component,
            int preferredPort, int minPort, int maxPort)
        throws IllegalArgumentException,
               IOException
    {
        gatherCandidates(component, preferredPort, minPort, maxPort);

        logger.fine(
                "Candidate count in first harvest: "
                        + component.getLocalCandidateCount());

        //select the candidate to put in the media line.
        component.selectDefaultCandidate();
    }

    /**
     * Returns the {@link FoundationsRegistry} this agent is using to assign
     * candidate foundations. We use the <tt>FoundationsRegistry</tt> to keep
     * track of the foundations we assign within a session (i.e. the entire life
     * time of a <tt>BaseAgent</tt>.)
     */
    public final FoundationsRegistry getFoundationsRegistry()
    {
        return foundationsRegistry;
    }

    /**
     * Returns that password that should be advertised in session descriptions
     * containing ICE data from this agent.
     *
     * @return that password that should be advertised in session descriptions
     * containing ICE data from this agent.
     */
    public String getLocalPassword()
    {
        return password;
    }

    /**
     * Returns that user name that should be advertised in session descriptions
     * containing ICE data from this agent.
     *
     * @return that user name that should be advertised in session descriptions
     * containing ICE data from this agent.
     */
    public String getLocalUfrag()
    {
        return ufrag;
    }

    /**
     * Returns the <tt>IceMediaStream</tt> with the specified <tt>name</tt> or
     * <tt>null</tt> if no such stream has been registered with this
     * <tt>BaseAgent</tt> yet.
     *
     * @param name the name of the stream that we'd like to obtain a reference
     * to.
     *
     * @return the <tt>IceMediaStream</tt> with the specified <tt>name</tt> or
     * <tt>null</tt> if no such stream has been registered with this
     * <tt>BaseAgent</tt> yet.
     */
    public IceMediaStream getStream(String name)
    {
        synchronized(mediaStreams)
        {
            return mediaStreams.get(name);
        }
    }

    /**
     * Returns the number of <tt>IceMediaStream</tt>s currently registered with
     * this agent.
     *
     * @return  the number of <tt>IceMediaStream</tt>s currently registered with
     * this agent.
     *
     */
    public int getStreamCount()
    {
        synchronized(mediaStreams)
        {
            return mediaStreams.size();
        }
    }

    /**
     * Returns a <tt>List</tt> containing the names of all currently registered
     * media streams.
     *
     * @return a <tt>List</tt> containing the names of all currently registered
     * media streams.
     */
    public List<String> getStreamNames()
    {
        synchronized(mediaStreams)
        {
            return new LinkedList<>(mediaStreams.keySet());
        }
    }

    /**
     * Returns a <tt>List</tt> containing all <tt>IceMediaStream</tt>s currently
     * registered with this agent.
     *
     * @return a <tt>List</tt> containing all <tt>IceMediaStream</tt>s currently
     * registered with this agent.
     */
    public List<IceMediaStream> getStreams()
    {
        synchronized(mediaStreams)
        {
            return new LinkedList<>(mediaStreams.values());
        }
    }

    /**
     * Gets the <tt>StunStack</tt> used by this <tt>BaseAgent</tt>.
     *
     * @return the <tt>StunStack</tt> used by this <tt>BaseAgent</tt>
     */
    public synchronized StunStack getStunStack()
    {
        if (stunStack == null)
            stunStack = new StunStack();
        return stunStack;
    }

    /**
     * Determines whether this agent has the controlling role in an ICE
     * exchange.
     *
     * @return <tt>true</tt> if this is to be the controlling <tt>BaseAgent</tt>
     * and <tt>false</tt> otherwise.
     */
    public boolean isControlling()
    {
        return controlling;
    }

    /**
     * Removes <tt>stream</tt> and all its child <tt>Component</tt>s and
     * <tt>Candidate</tt>s from the this agent and releases all resources that
     * they had allocated (like sockets for example)
     *
     * @param stream the <tt>Component</tt> we'd like to remove and free.
     */
    public void removeStream(IceMediaStream stream)
    {
        synchronized (mediaStreams)
        {
            mediaStreams.remove(stream.getName());
        }
        /*
         * XXX The invocation of IceMediaStream#free() on stream has been moved
         * out of the synchronized block in order to reduce the chances of a
         * deadlock. There was no obvious reason why it should stay in the
         * synchronized block at the time of the modification.
         */
        stream.free();
    }

    /**
     * Specifies whether this agent has the controlling role in an ICE exchange.
     *
     * @param controlling <tt>true</tt> if this is to be the controlling
     * <tt>BaseAgent</tt> and <tt>false</tt> otherwise.
     */
    public void setControlling(boolean controlling)
    {
        this.controlling = controlling;
    }

    /**
     * Sets the <tt>StunStack</tt> to be used by this <tt>BaseAgent</tt>.
     *
     * @param stunStack the <tt>StunStack</tt> to be used by this
     * <tt>BaseAgent</tt>.
     */
    public void setStunStack(StunStack stunStack)
    {
        this.stunStack = stunStack;
    }

    /**
     * Sets the flag which indicates whether the dynamic host harvester (i.e.
     * {@link #hostHarvester}) is (to be) used by this <tt>BaseAgent</tt>.
     *
     * @param useHostHarvester {@code true} to use the dynamic host harvester;
     * otherwise, {@code false}.
     */
    public void setUseHostHarvester(boolean useHostHarvester)
    {
        this.useHostHarvester = useHostHarvester;
    }

    /**
     * Determines whether the dynamic host harvester (i.e.
     * {@link #hostHarvester}) is (to be) used.
     *
     * @return <tt>true</tt> if the dynamic host harvester is (to be) used;
     * <tt>false</tt>, otherwise.
     */
    public boolean useHostHarvester()
    {
        if (useHostHarvester == null)
        {
            useHostHarvester
                = StackProperties.getBoolean(
                        StackProperties.USE_DYNAMIC_HOST_HARVESTER,
                        true);
        }
        return useHostHarvester;
    }
}
