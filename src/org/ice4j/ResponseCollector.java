/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j;

/**
 * The interface is used as a callback when sending a request. The response
 * collector is then used as a means of dispatching the response.
 *
 * @author Emil Ivov
 */
public interface ResponseCollector
{
    /**
     * Dispatch the specified response.
     *
     * @param response the response to dispatch.
     */
    public void processResponse(StunMessageEvent response);

    /**
     * Notify the collector that no response had been received
     * after repeated retransmissions of the original request (as described
     * by rfc3489) and that the request should be considered unanswered.
     *
     * @param event the <tt>StunTimeoutEvent</tt> containing a reference to
     * the transaction that has just failed.
     */
    public void processTimeout(StunTimeoutEvent event);

    /**
     * Notifies this collector that the destination of the request has been
     * determined to be unreachable and that the request should be considered
     * unanswered.
     *
     * @param event the <tt>StunFailureEvent</tt> containing the
     * <tt>PortUnreachableException</tt> that has just occurred.
     */
    public void processUnreachable(StunFailureEvent event);
}
