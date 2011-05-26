/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.security;

import java.util.*;

/**
 * The <tt>CredentialsManager</tt> allows an application to handle verification
 * of incoming <tt>MessageIntegrityAttribute</tt>s by registering a
 * {@link CredentialsAuthority} implementation. The point of this mechanism
 * is to allow use in both applications that would handle large numbers of
 * possible users (such as STUN/TURN servers) or others that would only work
 * with a few, like for example an ICE implementation.
 *
 * @todo just throwing a user name at the manager and expecting it to find
 * an authority that knows about it may lead to ambiguities so we may need
 * to add other parameters in here that would allow us to better select an
 * authority.
 *
 * @author Emil Ivov
 */
public class CredentialsManager
{
    /**
     * The list of <tt>CredentialsAuthority</tt>s registered with this manager
     * as being able to provide credentials.
     */
    private final List<CredentialsAuthority> authorities =
        new LinkedList<CredentialsAuthority>();

    /**
     * Queries all currently registered {@link CredentialsAuthority}s for a
     * password corresponding to the specified local <tt>username</tt> or user
     * frag and returns the first non-<tt>null</tt> one.
     *
     * @param username a local user name or user frag whose credentials we'd
     * like to obtain.
     *
     * @return <tt>null</tt> if username was not a recognized local user name
     * for none of the currently registered <tt>CredentialsAuthority</tt>s or
     * a <tt>byte</tt> array containing the first non-<tt>null</tt> password
     * that one of them returned.
     */
    public byte[] getLocalKey(String username)
    {
        synchronized(authorities)
        {
            for (CredentialsAuthority auth : authorities)
            {
                byte[] passwd = auth.getLocalKey(username);

                if (passwd != null)
                {
                    return passwd;
                }
            }
        }
        return null;
    }

    /**
     * Queries all currently registered {@link CredentialsAuthority}s for a
     * password corresponding to the specified remote <tt>username</tt> or user
     * frag and returns the first non-<tt>null</tt> one.
     *
     * @param username a remote user name or user frag whose credentials we'd
     * like to obtain.
     * @param media the media name that we want to get remote key.
     *
     * @return <tt>null</tt> if username was not a recognized remote user name
     * for none of the currently registered <tt>CredentialsAuthority</tt>s or
     * a <tt>byte</tt> array containing the first non-<tt>null</tt> password
     * that one of them returned.
     */
    public byte[] getRemoteKey(String username, String media)
    {
        synchronized(authorities)
        {
            for (CredentialsAuthority auth : authorities)
            {
                byte[] passwd = auth.getRemoteKey(username, media);

                if (passwd != null)
                {
                    /** @todo: we should probably add SASLprep here.*/
                    return passwd;
                }
            }
        }
        return null;
    }

    /**
     * Verifies whether <tt>username</tt> is currently known to any of the
     * {@link CredentialsAuthority}s registered with this manager and
     * and returns <tt>true</tt> if so. Returns <tt>false</tt> otherwise.
     *
     * @param username the user name whose validity we'd like to check.
     *
     * @return <tt>true</tt> if <tt>username</tt> is known to any of the
     * <tt>CredentialsAuthority</tt>s registered here and <tt>false</tt>
     * otherwise.
     */
    public boolean checkLocalUserName(String username)
    {
        synchronized(authorities)
        {
            for (CredentialsAuthority auth : authorities)
            {
                if( auth.checkLocalUserName(username))
                    return true;
            }
        }
        return false;
    }

    /**
     * Adds <tt>authority</tt> to the list of {@link CredentialsAuthority}s
     * registered with this manager.
     *
     * @param authority the {@link CredentialsAuthority} to add to this manager.
     */
    public void registerAuthority(CredentialsAuthority authority)
    {
        synchronized(authorities)
        {
            if(!authorities.contains(authority))
                authorities.add(authority);
        }
    }

    /**
     * Removes <tt>authority</tt> from the list of {@link CredentialsAuthority}s
     * registered with this manager.
     *
     * @param authority the {@link CredentialsAuthority} to remove from this
     * manager.
     */
    public void unregisterAuthority(CredentialsAuthority authority)
    {
        synchronized(authorities)
        {
            authorities.remove(authority);
        }
    }
}
