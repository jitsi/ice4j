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
package org.ice4j;

/**
 * @author Lubomir Marinov
 */
public abstract class AbstractResponseCollector
    implements ResponseCollector
{

    /**
     * Notifies this <tt>ResponseCollector</tt> that a transaction described by
     * the specified <tt>BaseStunMessageEvent</tt> has failed. The possible
     * reasons for the failure include timeouts, unreachable destination, etc.
     *
     * @param event the <tt>BaseStunMessageEvent</tt> which describes the failed
     * transaction and the runtime type of which specifies the failure reason
     */
    protected abstract void processFailure(BaseStunMessageEvent event);

    /**
     * Notifies this collector that no response had been received after repeated
     * retransmissions of the original request (as described by rfc3489) and
     * that the request should be considered unanswered.
     *
     * @param event the <tt>StunTimeoutEvent</tt> containing a reference to the
     * transaction that has just failed.
     */
    public void processTimeout(StunTimeoutEvent event)
    {
        processFailure(event);
    }

    /**
     * Notifies this collector that the destination of the request has been
     * determined to be unreachable and that the request should be considered
     * unanswered.
     *
     * @param event the <tt>StunFailureEvent</tt> containing the
     * <tt>PortUnreachableException</tt> that has just occurred.
     */
    public void processUnreachable(StunFailureEvent event)
    {
        processFailure(event);
    }
}
