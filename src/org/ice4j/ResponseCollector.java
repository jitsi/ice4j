/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j;

import java.net.*;

/**
 * The interface is used as a callback when sending a request. The response
 * collector is then used as a means of dispatching the response.
 *
 * <p>Organization: Louis Pasteur University, Strasbourg, France</p>
 * <p>Network Research Team (http://www-r2.u-strasbg.fr)</p>
 * @author Emil Ivov
 * @version 0.1
 */
public interface ResponseCollector
{
    /**
     * Dispatch the specified response.
     * @param response the response to dispatch.
     */
    public void processResponse(StunMessageEvent response);

    /**
     * Notify the collector that no response had been received
     * after repeated retransmissions of the original request (as described
     * by rfc3489) and that the request should be considered unanswered.
     */
    public void processTimeout();

    /**
     * Notifies this collector that the destination of the request has been
     * determined to be unreachable and that the request should be considered
     * unanswered.
     *
     * @param exception the <tt>PortUnreachableException</tt> which signaled
     * that the destination of the request was found to be unreachable
     */
    public void processUnreachable(PortUnreachableException exception);
}
