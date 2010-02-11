/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.util.*;

import org.ice4j.*;


/**
 * This is a utility class used for dispatching incoming request events. We use
 * this class mainly (and probably solely) for its ability to handle listener
 * proxies (i.e. listeners interested in requests received on a particular
 * NetAccessPoint only).
 *
 * @author Emil Ivov
 */
public class EventDispatcher
{

    /**
     * All property change listeners registered so far.
     */
    private final Vector<RequestListener> requestListeners
                                                = new Vector<RequestListener>();

    /**
     * Hashtable for managing property change listeners registered for specific
     * properties. Maps property names to PropertyChangeSupport objects.
     */
    private final Hashtable<TransportAddress, EventDispatcher>
        requestListenersChildren
            = new Hashtable<TransportAddress, EventDispatcher>();

    /**
     * Constructs an <tt>EventDispatcher</tt> object.
     */
    public EventDispatcher()
    {
    }

    /**
     * Add a RequestListener to the listener list. The listener is registered
     * for requests coming from no matter which NetAccessPoint.
     *
     * @param listener  The ReuqestListener to be added
     */
    public synchronized void addRequestListener(RequestListener listener)
    {
        synchronized(requestListeners)
        {
            if(!requestListeners.contains(listener))
                requestListeners.addElement(listener);
        }
    }

    /**
     * Add a RequestListener for a specific NetAccessPoint. The listener
     * will be invoked only when a call on fireRequestReceived is issued for
     * that specific NetAccessPoint.
     *
     * @param localAddr  The NETAP descriptor that we're interested in.
     * @param listener  The ConfigurationChangeListener to be added
     */

    public synchronized void addRequestListener( TransportAddress localAddr,
                                                 RequestListener  listener)
    {
        synchronized(requestListenersChildren)
        {
            EventDispatcher child = requestListenersChildren.get(localAddr);
            if (child == null)
            {
                child = new EventDispatcher();
                requestListenersChildren.put(localAddr, child);
            }
            child.addRequestListener(listener);
        }
    }

    /**
     * Remove a RquestListener from the listener list.
     * This removes a RequestListener that was registered
     * for all NetAccessPoints and would not remove listeners registered for
     * specific NetAccessPointDescriptors.
     *
     * @param listener The RequestListener to be removed
     */
    public synchronized void removeRequestListener(
        RequestListener listener)
    {
        synchronized(requestListeners)
        {
            requestListeners.removeElement(listener);
        }
    }

    /**
     * Remove a RequestListener for a specific NetAccessPointDescriptor. This
     * would only remove the listener for the specified NetAccessPointDescriptor
     * and would not remove it if it was also registered as a wildcard listener.
     *
     * @param localAddr  The NetAPDescriptor that was listened on.
     * @param listener  The RequestListener to be removed
     */
    public synchronized void removeRequestListener(TransportAddress localAddr,
                                                   RequestListener  listener)
    {
        synchronized(requestListenersChildren)
        {
            EventDispatcher child = requestListenersChildren.get( localAddr );

            if (child == null)
            {
                return;
            }
            child.removeRequestListener(listener);
        }
    }


    /**
     * Dispatch a StunMessageEvent to any registered listeners.
     *
     * @param evt  The request event to be delivered.
     */
    public void fireMessageEvent(StunMessageEvent evt)
    {
        TransportAddress localAddr = evt.getLocalAddress();
        synchronized(requestListeners)
        {
            List<RequestListener> listenersCopy = null;
            synchronized(requestListeners)
            {
                listenersCopy
                    = new ArrayList<RequestListener>(requestListeners);
            }

            for (RequestListener target : listenersCopy)
                target.requestReceived(evt);
        }

        synchronized(requestListenersChildren)
        {
            EventDispatcher child = requestListenersChildren.get(localAddr);

            if (child != null)
            {
                child.fireMessageEvent(evt);
            }
        }
    }

    /**
     * Check if there are any listeners for a specific address.
     * (Generic listeners count as well)
     *
     * @param localAddr the NetAccessPointDescriptor.
     * @return true if there are one or more listeners for the specified
     * NetAccessPointDescriptor
     */
    public boolean hasRequestListeners(TransportAddress localAddr)
    {
        synchronized(requestListeners)
        {
            if(!requestListeners.isEmpty())
            {
                // there is a generic listener
                return true;
            }
        }

        synchronized(requestListenersChildren)
        {
            if (!requestListenersChildren.isEmpty())
            {
                EventDispatcher child = requestListenersChildren.get(localAddr);
                if (child != null && child.requestListeners != null)
                {
                    return !child.requestListeners.isEmpty();
                }
            }
        }

        return false;
    }

    /**
     * Removes (absolutely all listeners for this event dispatcher).
     */
    public void removeAllListeners()
    {
        if(requestListeners != null)
            requestListeners.removeAllElements();
        requestListenersChildren.clear();
    }
}
