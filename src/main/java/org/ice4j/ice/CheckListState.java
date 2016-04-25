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
 * Everty <tt>CheckList</tt> is associated with a state, which captures the
 * state of ICE checks for that media stream. There are three states:
 * <br>
 * Running:  In this state, ICE checks are still in progress for this
 * media stream.
 * <br>
 * Completed:  In this state, ICE checks have produced nominated pairs
 * for each component of the media stream.  Consequently, ICE has succeeded and
 * media can be sent.
 * <br>
 * Failed:  In this state, the ICE checks have not completed successfully for
 * this media stream.
 * <br>
 * When a check list is first constructed as the consequence of an offer/answer
 * exchange, it is placed in the Running state.
 *
 * @author Emil Ivov
 */
public enum CheckListState
{
    /**
     * In this state, ICE checks are still in progress for this media stream.
     */
    RUNNING("Running"),

    /**
     * In this state, ICE checks have produced nominated pairs for each
     * component of the media stream.  Consequently, ICE has succeeded and
     * media can be sent.
     */
    COMPLETED("Completed"),

    /**
     * In this state, the ICE checks have not completed successfully for this
     * media stream.
     */
    FAILED("Failed");

    /**
     * The name of this <tt>CheckListState</tt> instance.
     */
    private final String stateName;

    /**
     * Creates a <tt>CheckListState</tt> instance with the specified name.
     *
     * @param stateName the name of the <tt>CheckListState</tt> instance
     * we'd like to create.
     */
    private CheckListState(String stateName)
    {
        this.stateName = stateName;
    }

    /**
     * Returns the name of this <tt>CheckListStae</tt> (i.e.. "Running",
     * "Completed", or "Failed").
     *
     * @return the name of this <tt>CheckListStae</tt> (i.e.. "Running",
     * "Completed", or "Failed").
     */
    @Override
    public String toString()
    {
        return stateName;
    }
}
