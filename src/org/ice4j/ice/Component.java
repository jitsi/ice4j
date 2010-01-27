/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.util.*;

import org.ice4j.*;

/**
 * A component is a piece of a media stream requiring a single transport
 * address; a media stream may require multiple components, each of which has
 * to work for the media stream as a whole to work. For media streams based on
 * RTP, there are two components per media stream - one for RTP, and one for
 * RTCP.
 * <p>
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class Component
{
    /**
     * A component id is a positive integer between 1 and 256 which identifies
     * the specific component of the media stream for which this is a candidate.
     * It MUST start at 1 and MUST increment by 1 for each component of a
     * particular candidate. For media streams based on RTP, candidates for the
     * actual RTP media MUST have a component ID of 1, and candidates for RTCP
     * MUST have a component ID of 2. Other types of media streams which
     * require multiple components MUST develop specifications which define the
     * mapping of components to component IDs. See Section 14 for additional
     * discussion on extending ICE to new media streams.
     */
    private int componentID = -1;

    /**
     * The component ID to use with RTP streams.
     */
    public static final int RTP = 1;

    /**
     * The component ID to use with RTCP streams.
     */
    public static final int RTCP = 2;

    /**
     * The transport that this component is using.
     */
    private final Transport transport;

    /**
     * The <tt>IceMediaStream</tt> that this <tt>Component</tt> belongs to.
     */
    private final IceMediaStream parentStream;

    /**
     * The list locally gathered candidates for this media stream.
     */
    private List<Candidate> localCandidates = null;

    /**
     * The list of candidates that the peer agent sent for this stream.
     */
    private List<Candidate> remoteCandidates = null;

    /**
     * Creates a new <tt>Component</tt> with the specified <tt>componentID</tt>
     * as a child of the specified <tt>MediaStream</tt>.
     *
     * @param componentID the id of this component.
     * @param transport the protocol that this component will be using (e.g.
     * TCP/UDP/TLS/DTLS).
     * @param mediaStream the {@link IceMediaStream} instance that would be the
     * parent of this component.
     */
    protected Component(int            componentID,
                        Transport      transport,
                        IceMediaStream mediaStream)
    {
        // the max value for componentID is 256
        this.componentID = componentID;
        this.transport = transport;
        this.parentStream = mediaStream;
    }

    /**
     * Add a local candidate to this component.
     *
     * @param candidate the candidate object to be added
     */
    public void addLocalCandidate(Candidate candidate)
    {
        synchronized(localCandidates)
        {
            localCandidates.add(candidate);
        }
    }

    /**
     * Adds a remote <tt>Candidate</tt>s to this media-stream component.
     *
     * @param candidate the <tt>Candidate</tt> instance to add.
     */
    public void addRemoteCandidate(Candidate candidate)
    {
        synchronized(remoteCandidates)
        {
            remoteCandidates.add(candidate);
        }
    }

    /**
     * Adds a list of local <tt>Candidate</tt>s to this media-stream component.
     *
     * @param candidates a <tt>List</tt> of candidates to be added
     */
    public void addLocalCandidates(List<Candidate> candidates)
    {
        synchronized(localCandidates)
        {
            localCandidates.addAll(candidates);
        }
    }

    /**
     * Adds a List of remote <tt>Candidate</tt>s as reported by a remote agent.
     *
     * @param candidates the <tt>List</tt> of <tt>Candidate</tt>s reported by
     * the remote agent for this component.
     */
    public void addRemoteCandidates(List<Candidate> candidates)
    {
        synchronized(remoteCandidates)
        {
            remoteCandidates.addAll(candidates);
        }
    }

    /**
     * Returns a reference to the <tt>IceMediaStream</tt> that this
     * <tt>Component</tt> belongs to.
     *
     * @return  a reference to the <tt>IceMediaStream</tt> that this
     * <tt>Component</tt> belongs to.
     */
    public IceMediaStream getParentStream()
    {
        return parentStream;
    }

    /**
     * Returns the ID of this <tt>Component</tt>. For RTP/RTCP flows this would
     * be <tt>1</tt> for RTP and 2 for <tt>RTCP</tt>.
     *
     * @return the ID of this <tt>Component</tt>.
     */
    public int getComponentID()
    {
        return componentID;
    }

    /**
     * Returns the transport protocol of this component
     *
     * @return a {@link Transport} instance representing the the transport
     * protocol that this media stream <tt>Component</tt> uses.
     */
    public Transport getTransport()
    {
        return transport;
    }
}
