/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

/**
 * RFC 5245 mentions that ICE processing across all media streams also has a
 * state associated with it. This state is equal to <tt>Running</tt> while ICE
 * processing is under way. The state is Completed when ICE processing is
 * complete and Failed if it failed without success. For convenience reasons
 * we are also adding an extra <tt>Waiting</tt> state that reflects the state
 * of an {@link Agent} before it starts processing. This is also an {@link
 * Agent}'s default state.
 *
 * @author Emil Ivov
 */
public enum IceProcessingState
{
    /**
     * The state is equal to <tt>Waiting</tt> if ICE processing has not started
     * for the corresponding {@link Agent}.
     */
    WAITING("Waiting"),

    /**
     * The state is equal to <tt>Running</tt> while ICE processing is under way.
     */
    RUNNING("Running"),

    /**
     * The state is Completed when ICE processing is complete.
     */
    COMPLETED("Completed"),

    /**
     * The state is Completed when ICE processing is Failed if processing
     * failed without success.
     */
    FAILED("Failed");

    /**
     * The name of this <tt>IceProcessingState</tt> instance.
     */
    private final String stateName;

    /**
     * Creates an <tt>IceProcessingState</tt> instance with the specified name.
     *
     * @param stateName the name of the <tt>IceProcessingState</tt> instance
     * we'd like to create.
     */
    private IceProcessingState(String stateName)
    {
        this.stateName = stateName;
    }

    /**
     * Returns the name of this <tt>IceProcessingState</tt> (e.g. "Running",
     * "Completed", or "Failed").
     *
     * @return the name of this <tt>IceProcessingState</tt> (e.g. "Running",
     * "Completed", or "Failed").
     */
    @Override
    public String toString()
    {
        return stateName;
    }
}
