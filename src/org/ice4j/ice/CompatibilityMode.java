/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

/**
 * ICE compatibility mode.
 *
 * @author Sebastien Vincent
 */
public enum CompatibilityMode
{
    /**
     * Standard ICE from RFC5245;
     */
    RFC5245,

    /**
     * Google ICE dialect used by Google Talk (web and application).
     */
    GTALK;
}
