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
package org.ice4j.security;

/**
 * The {@link CredentialsAuthority} interface is implemented by applications
 * in order to allow the stack to verify the integrity of incoming messages
 * containing the <tt>MessageIntegrityAttribute</tt>.
 *
 * @author Emil Ivov
 */
public interface CredentialsAuthority
{
    /**
     * Returns the key (password) that corresponds to the specified local
     * username or user frag,  an empty array if there was no password for that
     * username or <tt>null</tt> if the username is not a local user name
     * recognized by this <tt>CredentialsAuthority</tt>.
     *
     * @param username the local user name or user frag whose credentials we'd
     * like to obtain.
     *
     * @return the key (password) that corresponds to the specified local
     * username or user frag,  an empty array if there was no password for that
     * username or <tt>null</tt> if the username is not a local user name
     * recognized by this <tt>CredentialsAuthority</tt>.
     */
    public byte[] getLocalKey(String username);

    /**
     * Returns the key (password) that corresponds to the specified remote
     * username or user frag,  an empty array if there was no password for that
     * username or <tt>null</tt> if the username is not a remote user name
     * recognized by this <tt>CredentialsAuthority</tt>.
     *
     * @param username the remote user name or user frag whose credentials we'd
     * like to obtain.
     * @param media the media name that we want to get remote key.
     *
     * @return the key (password) that corresponds to the specified remote
     * username or user frag,  an empty array if there was no password for that
     * username or <tt>null</tt> if the username is not a remote user name
     * recognized by this <tt>CredentialsAuthority</tt>.
     */
    public byte[] getRemoteKey(String username, String media);

    /**
     * Verifies whether <tt>username</tt> is currently known to this authority
     * and returns <tt>true</tt> if so. Returns <tt>false</tt> otherwise.
     *
     * @param username the user name whose validity we'd like to check.
     *
     * @return <tt>true</tt> if <tt>username</tt> is known to this
     * <tt>CredentialsAuthority</tt> and <tt>false</tt> otherwise.
     */
    public boolean checkLocalUserName(String username);
}
