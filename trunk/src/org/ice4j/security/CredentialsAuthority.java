/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.security;

/**
 * The {@link CredentialsAuthority} interface is implemented by applications
 * in order to allow the stack to verify the integrity of incoming messages
 * containing the <tt>MessageIntegrity</tt> attribute.
 *
 * @author Emil Ivov
 */
public interface CredentialsAuthority
{
    /**
     * Returns the key (password) that corresponds to the specified username,
     * an empty array if there was no password for that username or
     * <tt>null</tt> if the username is not known to this
     * <tt>CredentialsAuthority</tt>.
     *
     * @param username the user name whose credentials we'd like to obtain.
     *
     * @return the key (password) that corresponds to the specified username,
     * an empty array if there was no password for that username or
     * <tt>null</tt> if the username is not known to this
     * <tt>CredentialsAuthority</tt>.
     */
    public byte[] getKey(String username);
}
