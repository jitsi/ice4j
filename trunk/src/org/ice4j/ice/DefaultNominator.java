/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.beans.*;

/**
 * Implements nomination strategies
 * @author Emil Ivov
 */
public class DefaultNominator
    implements PropertyChangeListener
{
    private final Agent parentAgent;

    public DefaultNominator(Agent parentAgent)
    {
        this.parentAgent = parentAgent;
    }

    public void propertyChange(PropertyChangeEvent evt)
    {

    }
}
