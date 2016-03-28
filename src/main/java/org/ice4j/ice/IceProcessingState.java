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

/**
 * RFC 5245 mentions that ICE processing across all media streams also has a
 * state associated with it. This state is equal to <tt>Running</tt> while ICE
 * processing is under way. The state is Completed when ICE processing is
 * complete and Failed if it failed without success. For convenience reasons
 * we are also adding two extra states. The first one is the <tt>Waiting</tt>
 * state that reflects the state of an {@link Agent} before it starts
 * processing. This is also an {@link Agent }'s default state. The second one
 * is the "Terminated" state. RFC 5245 says that once ICE processing
 * has reached the Completed state for all peers for media streams using
 * those candidates, the agent SHOULD wait an additional three seconds,
 * and then it MAY cease responding to checks or generating triggered
 * checks on that candidate.  It MAY free the candidate at that time.
 * which reflects the state where an Agent does not need to handle incoming
 * checks any more and is ready for garbage collection. This is the state we
 * refer to with "Terminated".
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
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
    FAILED("Failed"),

    /**
     * Once ICE processing has reached the Completed state for all peers for
     * media streams using those candidates, the agent SHOULD wait an
     * additional three seconds, and then it MAY cease responding to checks
     * or generating triggered checks on that candidate.  It MAY free the
     * candidate at that time. This is also when an agent would enter the
     * terminated state.
     */
    TERMINATED("Terminated");

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

    /**
     * Determines whether an {@link Agent} in this state has finished its ICE
     * processing.
     *
     * @return {@code true} if an {@code Agent} in this state has finished its
     * ICE processing; otherwise, {@code false}
     */
    public boolean isOver()
    {
        return
            COMPLETED.equals(this)
                || FAILED.equals(this)
                || TERMINATED.equals(this);
    }

    /**
     * Returns <tt>true</tt> iff the state is one in which a connection
     * has been established, that is either <tt>COMPLETED</tt> or
     * <tt>TERMINATED</tt>.
     *
     * @return <tt>true</tt> iff the state is one in which a connection
     * has been established, that is either <tt>COMPLETED</tt> or
     * <tt>TERMINATED</tt>.
     */
    public boolean isEstablished()
    {
        return this == COMPLETED || this == TERMINATED;
    }
}
