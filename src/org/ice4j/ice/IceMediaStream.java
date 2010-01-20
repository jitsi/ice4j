/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.util.*;
import java.util.logging.*;

/**
 * The class represents a media stream from the ICE perspective, i.e. a
 * collection of components.
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class IceMediaStream
{
    /**
     * Our class logger.
     */
    private static final Logger logger =
        Logger.getLogger(IceMediaStream.class.getName());

    /**
     * The name of this media stream. The name is equal to the value specified
     * in the SDP description.
     */
    private final String name;

    /**
     * Returns the list of components that this media stream consists of. A
     * component is a piece of a media stream requiring a single transport
     * address; a media stream may require multiple components, each of which
     * has to work for the media stream as a whole to work.
     */
    private LinkedHashMap<Integer, Component> components
                                    = new LinkedHashMap<Integer, Component>();

    /**
     * The agent that this media stream belongs to.
     */
    private final Agent parentAgent;

    /**
     * Initializes a new <tt>IceMediaStream</tt> object.
     *
     * @param name the name of the media stream
     * @param parentAgent the agent that is handling the session that this
     * media stream is a part of
     */
    protected IceMediaStream(Agent parentAgent, String name)
    {
        this.name = name;
        this.parentAgent = parentAgent;
    }
}
