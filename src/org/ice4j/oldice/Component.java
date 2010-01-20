/*
 * SIP Communicator, the OpenSource Java VoIP and Instant Messaging client.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

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
     * The <tt>MediaStream</tt> that this component belongs to.
     */
    private MediaStream mediaStream = null;

    /**
     * The default candidate of this component
     */
    private Candidate defaultCandidate = null;

    /**
     * The transport protocol used by this component
     */
    private String transportProtocol = null;

    /**
     * Creates a new instance of <tt>Component</tt>.
     *
     * @param componentID the id of this component.
     * @param transportProtocol the protocol that this component will be using (e.g.
     * TCP/UDP/TLS/DTLS).
     */
    protected Component(int componentID,
                        String transportProtocol,
                        TransportAddress defaultAddress,
                        MediaStream mediaStream)
    {
        this.componentID = componentID;   // the max value for componentID is 256
        this.transportProtocol = transportProtocol;
        this.defaultCandidate = new Candidate(defaultAddress, Component.this);
        this.mediaStream = mediaStream;
    }

    /**
     * The default destination for a <tt>Component</tt> is the transport address
     * that would be used by an agent that is not ICE aware. For the RTP
     * component, the default IP address is in the c line of the SDP, and the
     * port in the m line. For the RTCP component it is in the rtcp attribute
     * when present, and when not present, the IP address in the c line and 1
     * plus the port in the m line. A default candidate for a component is one
     * whose transport address matches the default destination for that
     * component.
     *
     * @return the default destination/candidate for this <tt>Component</tt>.
     */
    public Candidate getDefaultCandidate()
    {
        return defaultCandidate;
    }

    /**
     * Sets the default candidate of the candidate
     *
     * @param tpAddress the transport address which contains the default value
     */
    public void setDefaultCandidate(TransportAddress tpAddress)
    {
        this.defaultCandidate = new Candidate(tpAddress, this);
    }

    /**
     * Returns the id of this component. A component id is a positive integer
     * between 1 and 256 which identifies the specific component of the media
     * stream for which this is a candidate. It MUST start at 1 and MUST
     * increment by 1 for each component of a particular candidate. For media
     * streams based on RTP, candidates for the actual RTP media MUST have a
     * component ID of 1, and candidates for RTCP MUST have a component ID of 2.
     * Other types of media streams which require multiple components MUST
     * develop specifications which define the mapping of components to
     * component IDs. See Section 14 for additional discussion on extending ICE
     * to new media streams.
     *
     * @return the component ID for this <tt>Component</tt>.
     */
    public int getComponentID()
    {
        return componentID;
    }

    /**
     * Returns the IceAgent that this component belongs to.
     */
    public IceAgent getParentAgent()
    {
        return mediaStream.getParentAgent();
    }

    /**
     * Returns a reference to the media stream that this component belongs to.
     *
     * @return a reference to the <tt>MediaStream</tt> that this component
     * belongs to.
     */
    public MediaStream getParentMediaStream()
    {
        return mediaStream;
    }

    /**
     * Adds a local candidate for this component
     *
     * @param candidateAddress  the candidate to be added
     */
    public void addLocalCandidate(TransportAddress candidateAddress)
    {
        Candidate candidate = new Candidate(candidateAddress, Component.this);
        mediaStream.addLocalCandidate(candidate);
    }

    /**
     * Returns the transport protocol of this component
     *
     * @return  the string representing the the transport protocol
     */
    public String getTransportProtocol()
    {
        return transportProtocol;
    }
}
