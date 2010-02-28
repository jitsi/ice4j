/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
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

/**
 * An IceAgent could be described as the main class (i.e. the chef d'orchestre)
 * of an ICE implementation.
 * <p>
 * As defined in RFC 3264, an agent is the protocol implementation involved in
 * the offer/answer exchange. There are two agents involved in an offer/answer
 * exchange.
 * <p>
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class Agent
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(Agent.class.getName());

    /**
     * The LinkedHashMap used to store the media streams
     * This map preserves the insertion order of the media streams.
     */
    private Map<String, IceMediaStream> mediaStreams
                                = new LinkedHashMap<String, IceMediaStream>();

    /**
     * The candidate harvester that we use to gather candidate on the local
     * machine.
     */
    private final HostCandidateHarvester hostCandidateHarvester
                                                = new HostCandidateHarvester();

    /**
     * The list of harvesters (i.e. STUN, TURN, and others) that the agent
     * should use when gathering candidates for components.
     */
    private final List<CandidateHarvester> harvesters
                                        = new ArrayList<CandidateHarvester>();

    /**
     * We use the <tt>FoundationsRegistry</tt> to keep track of the foundations
     * we assign within a session (i.e. the entire life time of an
     * <tt>Agent</tt>)
     */
    private FoundationsRegistry foundationsRegistry = new FoundationsRegistry();

    /**
     * The user fragment that we should use for the ice-ufrag attribute.
     */
    private final String ufrag;

    /**
     * The password that we should use for the ice-pwd attribute.
     */
    private final String password;

    /**
     * Creates an empty <tt>Agent</tt> with no streams, and no address
     */
    public Agent()
    {
        SecureRandom random = new SecureRandom();

        ufrag = new BigInteger(24, random).toString(32);
        password = new BigInteger(128, random).toString(32);
    }

    /**
     * Creates a new media stream and stores it
     *
     * @param mediaStreamName    the name of the media stream
     *
     * @return a reference to the newly created <tt>IceMediaStream</tt>.
     */
    public IceMediaStream createMediaStream(String mediaStreamName)
    {
        IceMediaStream mediaStream
            = new IceMediaStream(Agent.this, mediaStreamName);
        mediaStreams.put(mediaStreamName, mediaStream);

        return mediaStream;
    }

    /**
     * Creates a new {@link Component} for the specified <tt>stream</tt> and
     * allocates all local candidates that should belong to it.
     *
     * @param stream the {@link IceMediaStream} that the new {@link Component}
     * should belong to.
     * @param transport the transport protocol used by the component
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwinG an exception.
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
    public Component createComponent(  IceMediaStream stream,
                                       Transport      transport,
                                       int            preferredPort,
                                       int            minPort,
                                       int            maxPort)
        throws IllegalArgumentException,
               IOException,
               BindException
    {
        if(transport != Transport.UDP)
            throw new IllegalArgumentException("This implementation does not "
                            +" currently support transport: " + transport);
        Component component = stream.createComponent(transport);

        gatherCandidates(component, preferredPort, minPort, maxPort );
        return component;
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
     * before giving up and throwinG an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort >
     * maxPort</tt>.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is gathering candidates and we end up without even a single one.
     */
    private void gatherCandidates( Component      component,
                                   int            preferredPort,
                                   int            minPort,
                                   int            maxPort)
        throws IllegalArgumentException,
               IOException
    {
        hostCandidateHarvester.harvest(
                        component, preferredPort, minPort, maxPort);

        //apply other harvesters here:
        //todo: run harvesters in a parallel manner
        synchronized(harvesters)
        {
            for (CandidateHarvester h : harvesters )
            {
                h.harvest(component);
            }
        }

        computeFoundations(component);

        //make sure we compute priorities only after we have all candidates
        component.prioritizeCandidates();

        //eliminate redundant candidates
        component.eliminateRedundantCandidates();

        //select the candidate to put in the media line.
        component.selectDefaultCandidate();
    }

    /**
     * Computes and sets the foundations foundation for all <tt>Candidate</tt>s
     * currently found in <tt>component</tt>.
     *
     * @param component the component whose candidate foundations we'd like to
     * compute and assign.
     */
    private void computeFoundations(Component component)
    {
        List<Candidate> candidates = component.getLocalCandidates();

        for (Candidate cand : candidates)
        {
            foundationsRegistry.assignFoundation(cand);
        }
    }

    /**
     * Adds <tt>harvester</tt> to the list of harvesters that this agent will
     * use when gathering <tt>Candidate</tt>s.
     *
     * @param harvester a <tt>CandidateHarvester</tt> that this agent should use
     * when gathering candidates.
     */
    public void addCandidateHarvester(CandidateHarvester harvester)
    {
        synchronized(harvesters)
        {
            harvesters.add(harvester);
        }
    }

    /**
     * Returns that user name that should be advertised in session descriptions
     * containing ICE data from this agent.
     *
     * @return that user name that should be advertised in session descriptions
     * containing ICE data from this agent.
     */
    public String getUserName()
    {
        return ufrag;
    }

    /**
     * Returns that password that should be advertised in session descriptions
     * containing ICE data from this agent.
     *
     * @return that password that should be advertised in session descriptions
     * containing ICE data from this agent.
     */
    public String getPassword()
    {
        return password;
    }

}