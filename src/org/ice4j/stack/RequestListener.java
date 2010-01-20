/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stack;

import org.ice4j.*;

/**
 * <p>Title: Stun4J.</p>
 * <p>Description: Simple Traversal of UDP Through NAT.</p>
 * <p>Copyright: Copyright (c) 2003.</p>
 * <p>Organisation: <p> Louis Pasteur University, Strasbourg, France.</p>
 * <p>Network Research Team (http://www-r2.u-strasbg.fr).</p></p>
 * @author Emil Ivov
 * @version 0.1
 */

public interface RequestListener
{
    public void requestReceived(StunMessageEvent evt);
}
