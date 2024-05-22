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
package org.ice4j.ice.harvest;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;
import java.util.stream.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.socket.*;

import static org.ice4j.ice.harvest.HarvestConfig.config;

/**
 * A <tt>HostCandidateHarvester</tt> gathers host <tt>Candidate</tt>s for a
 * specified {@link org.ice4j.ice.Component}. Most <tt>CandidateHarvester</tt>s
 * would rely on the output of the host harvester, that is all host addresses,
 * to be already present and bound in a <tt>Component</tt> before being able to
 * harvest the type of addresses that they are responsible for.
 *
 * @author Emil Ivov
 * @author George Politis
 * @author Boris Grozev
 */
public class HostCandidateHarvester
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(HostCandidateHarvester.class.getName());

    /**
     * Manages statistics about harvesting time.
     */
    private HarvestStatistics harvestStatistics = new HarvestStatistics();

    /**
     * @return the list of all local IP addresses from all allowed network
     * interfaces, which are allowed addresses.
     */
    public static List<InetAddress> getAllAllowedAddresses()
    {
        List<InetAddress> addresses = new LinkedList<>();
        for (NetworkInterface iface : getAllowedInterfaces())
        {
            Enumeration<InetAddress> ifaceAddresses = iface.getInetAddresses();
            while (ifaceAddresses.hasMoreElements())
            {
                InetAddress address = ifaceAddresses.nextElement();
                if (isAddressAllowed(address))
                {
                    addresses.add(address);
                }
            }
        }

        return addresses;
    }

    /**
     * Gathers all candidate addresses on the local machine, binds sockets on
     * them and creates {@link HostCandidate}s. The harvester would always
     * try to bind the sockets on the specified <tt>preferredPort</tt> first.
     * If that fails we will move through all ports between <tt>minPort</tt> and
     * <tt>maxPort</tt> and give up if still can't find a free port.
     *
     * If 0, 0, 0 are specified for preferred, min and max port, an ephemeral port will be used instead.
     *
     * @param component the {@link Component} that we'd like to gather candidate
     * addresses for.
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     * @param transport transport protocol used
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number, <tt>minPort &gt;
     * maxPort</tt> or if transport is not supported.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is using sockets.
     */
    public void harvest(Component component,
                        int       preferredPort,
                        int       minPort,
                        int       maxPort,
                        Transport transport)
        throws IllegalArgumentException,
               IOException
    {
        harvestStatistics.startHarvestTiming();

        if (transport != Transport.UDP && transport != Transport.TCP)
        {
            throw new IllegalArgumentException("Transport protocol not supported: " + transport);
        }

        boolean boundAtLeastOneSocket = false;
        boolean foundAtLeastOneUsableInterface = false;
        boolean foundAtLeastOneUsableAddress = false;
        for (NetworkInterface iface: getAllowedInterfaces())
        {
            foundAtLeastOneUsableInterface = true;

            Enumeration<InetAddress> addresses = iface.getInetAddresses();

            while (addresses.hasMoreElements())
            {
                InetAddress addr = addresses.nextElement();

                if (!isAddressAllowed(addr))
                {
                    continue;
                }

                foundAtLeastOneUsableAddress = true;

                IceSocketWrapper sock = null;
                try
                {
                    if (transport == Transport.UDP)
                    {
                        sock = createDatagramSocket(addr, preferredPort, minPort, maxPort);
                        boundAtLeastOneSocket = true;
                    }
                    else if (transport == Transport.TCP)
                    {
                        if (addr instanceof Inet6Address)
                        {
                            continue;
                        }
                        sock = createServerSocket(
                                addr,
                                preferredPort,
                                minPort,
                                maxPort,
                                component);
                        boundAtLeastOneSocket = true;
                    }
                }
                catch (IOException exc)
                {
                    // There seems to be a problem with this particular
                    // address let's just move on for now and hope we will
                    // find better
                    if (logger.isLoggable(Level.WARNING))
                    {
                        logger.warning(
                                "Failed to create a socket for:"
                                        + "\naddr:" + addr
                                        + "\npreferredPort:" + preferredPort
                                        + "\nminPort:" + minPort
                                        + "\nmaxPort:" + maxPort
                                        + "\nprotocol:" + transport
                                        + "\nContinuing with next address");
                    }
                    continue;
                }

                HostCandidate candidate = new HostCandidate(sock, component, transport);
                candidate.setVirtual(iface.isVirtual());
                component.addLocalCandidate(candidate);

                if (transport == Transport.TCP)
                {
                    // have to wait a client connection to add a STUN socket
                    // to the StunStack
                    continue;
                }

                // We are most certainly going to use all local host
                // candidates for sending and receiving STUN connectivity
                // checks. In case we have enabled STUN, we are going to use
                // them as well while harvesting reflexive candidates.
                createAndRegisterStunSocket(candidate);

                ComponentSocket componentSocket = component.getComponentSocket();
                if (componentSocket != null)
                {
                    componentSocket.add(sock);
                }
            }
        }

        if (!boundAtLeastOneSocket)
        {
            throw new IOException(
                "Failed to bind even a single host candidate for component:"
                            + component
                            + " preferredPort=" + preferredPort
                            + " minPort=" + minPort
                            + " maxPort=" + maxPort
                            + " foundAtLeastOneUsableInterface="
                            + foundAtLeastOneUsableInterface
                            + " foundAtLeastOneUsableAddress="
                            + foundAtLeastOneUsableAddress);
        }

        this.harvestStatistics.stopHarvestTiming(component.getLocalCandidateCount());
    }

    /**
     * Returns a boolean value indicating whether ice4j should allocate a host candidate for the specified interface.
     * <p/>
     * Returns <code>false</code> if the interface is loopback, is not currently up, or is not allowed by the
     * configuration.
     *
     * @param iface The {@link NetworkInterface}.
     */
    public static boolean isInterfaceAllowed(NetworkInterface iface)
    {
        Objects.requireNonNull(iface);
        try
        {
            if (iface.isLoopback() || !iface.isUp())
            {
                return false;
            }
        }
        catch (SocketException se)
        {
            logger.warning("Failed to check state of interface: " + se);
            return false;
        }

        // gp: use getDisplayName() on Windows and getName() on Linux. Also
        // see NetworkAddressManagementServiceImpl in Jitsi.
        String ifName = (System.getProperty("os.name") == null
                || System.getProperty("os.name").startsWith("Windows"))
                ? iface.getDisplayName()
                : iface.getName();

        if (!config.getAllowedInterfaces().isEmpty())
        {
            // If an allowlist is configured, just check against it.
            return config.getAllowedInterfaces().contains(ifName);
        }
        else
        {
            // Otherwise, check against the blocked list.
            return !config.getBlockedInterfaces().contains(ifName);
        }
    }

    /**
     * Get the list of network interfaces suitable for host candidate harvesting, that is they are up, non-loopback
     * and are allowed by configuration.
     */
    public static List<NetworkInterface> getAllowedInterfaces()
    {
        try
        {
            return NetworkInterface.networkInterfaces()
                    .filter(HostCandidateHarvester::isInterfaceAllowed).collect(Collectors.toList());
        }
        catch (IOException ioe)
        {
            logger.warning("Failed to get network interfaces: " + ioe.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Returns <tt>true</tt> if <tt>address</tt> is allowed to be used for the purposes of candidate allocation, and
     * <tt>false</tt> otherwise.
     * <p/>
     * An address is considered allowed, if:
     * 1. It is not a loopback address.
     * 2. Link-local addresses are allowed or the address is not link-local.
     * 3. IPv6 addresses are allowed or the address is not IPv6
     * 4. It is allowed by configuration, that is, it either:
     *      -- Is present in the allowlist
     *      -- No allowlist is configured and it isn't present in the block list.
     *
     * @param address the address to check
     * @return <tt>true</tt> if <tt>address</tt> is allowed to be used by this <tt>HostCandidateHarvester</tt>.
     */
    static boolean isAddressAllowed(InetAddress address)
    {
        if (address.isLoopbackAddress())
        {
            return false;
        }
        if (!config.useLinkLocalAddresses() && address.isLinkLocalAddress())
        {
            return false;
        }
        if (!config.useIpv6() && address instanceof Inet6Address)
        {
            return false;
        }

        if (!config.getAllowedAddresses().isEmpty())
        {
            return config.getAllowedAddresses().contains(address);
        }
        return !config.getBlockedAddresses().contains(address);
    }

    /**
     * Creates a <tt>ServerSocket</tt> and binds it to the specified
     * <tt>localAddress</tt> and a port in the range specified by the
     * <tt>minPort</tt> and <tt>maxPort</tt> parameters.
     *
     * If 0, 0, 0 are specified for preferred, min and max port, an ephemeral port will be used instead.
     *
     * @param laddr the address that we'd like to bind the socket on.
     * @param preferredPort the port number that we should try to bind to first.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @return the newly created <tt>DatagramSocket</tt>.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort &gt;
     * maxPort</tt>.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is using sockets.
     * @throws BindException if we couldn't find a free port between
     * <tt>minPort</tt> and <tt>maxPort</tt> before reaching the maximum allowed
     * number of retries.
     */
    private IceSocketWrapper createServerSocket(InetAddress laddr,
        int preferredPort, int minPort, int maxPort,
        Component component)
        throws IllegalArgumentException,
               IOException,
               BindException
    {
        // make sure port numbers are valid
        boolean ephemeral = checkPorts(preferredPort, minPort, maxPort);
        if (ephemeral)
        {
            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(laddr, 0));
            if (logger.isLoggable(Level.FINEST))
            {
                logger.finest("Bound using an ephemeral port to " + socket.getLocalSocketAddress());
            }
            return new IceTcpServerSocketWrapper(new DelegatingServerSocket(socket), component);
        }

        int bindRetries = StackProperties.getInt(
                        StackProperties.BIND_RETRIES,
                        StackProperties.BIND_RETRIES_DEFAULT_VALUE);

        int port = preferredPort;
        for (int i = 0; i < bindRetries; i++)
        {
            try
            {
                ServerSocket sock = new ServerSocket();
                sock.setReuseAddress(true);
                sock.bind(new InetSocketAddress(laddr, port));
                IceSocketWrapper socket
                    = new IceTcpServerSocketWrapper(
                            new DelegatingServerSocket(sock),
                            component);

                if (logger.isLoggable(Level.FINEST))
                {
                    logger.log(
                            Level.FINEST,
                            "just bound to: " + sock.getLocalSocketAddress());
                }
                return socket;
            }
            catch (SocketException se)
            {
                logger.log(
                        Level.INFO,
                        "Retrying a bind because of a failure to bind to"
                            + " address " + laddr
                            + " and port " + port
                            + " (" + se.getMessage() +")");
                logger.log(Level.INFO, "", se);
            }

            port ++;

            if (port > maxPort)
                port = minPort;
        }

        throw new BindException("Could not bind to any port between " + minPort + " and " + (port - 1));
    }

    /**
     * Creates a <tt>DatagramSocket</tt> and binds it to the specified
     * <tt>localAddress</tt> and a port in the range specified by the
     * <tt>minPort</tt> and <tt>maxPort</tt> parameters. We first try to bind
     * the newly created socket on the <tt>preferredPort</tt> port number
     * (unless it is outside the <tt>[minPort, maxPort]</tt> range in which case
     * we first try the <tt>minPort</tt>) and then proceed incrementally upwards
     * until we succeed or reach the bind retries limit. If we reach the
     * <tt>maxPort</tt> port number before the bind retries limit, we will then
     * start over again at <tt>minPort</tt> and keep going until we run out of
     * retries.
     *
     * If 0, 0, 0 are specified for preferred, min and max port, an ephemeral port will be used instead.
     *
     * @param laddr the address that we'd like to bind the socket on.
     * @param preferredPort the port number that we should try to bind to first.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @return the newly created <tt>DatagramSocket</tt>.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort &gt;
     * maxPort</tt>.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is using sockets.
     * @throws BindException if we couldn't find a free port between
     * <tt>minPort</tt> and <tt>maxPort</tt> before reaching the maximum allowed
     * number of retries.
     */
    private IceSocketWrapper createDatagramSocket(InetAddress laddr,
                                                int preferredPort,
                                                int minPort,
                                                int maxPort)
        throws IllegalArgumentException,
               IOException,
               BindException
    {
        // make sure port numbers are valid.
        boolean ephemeral = checkPorts(preferredPort, minPort, maxPort);
        if (ephemeral)
        {
            DatagramSocket socket = new MultiplexingDatagramSocket(0, laddr);
            if (logger.isLoggable(Level.FINEST))
            {
                logger.finest("Bound using ephemeral port to " + socket.getLocalSocketAddress());
            }
            return new IceUdpSocketWrapper(socket);
        }

        int bindRetries = StackProperties.getInt(
                        StackProperties.BIND_RETRIES,
                        StackProperties.BIND_RETRIES_DEFAULT_VALUE);

        int port = preferredPort;
        for (int i = 0; i < bindRetries; i++)
        {
            try
            {
                IceSocketWrapper sock
                                = new IceUdpSocketWrapper(new
                                    MultiplexingDatagramSocket(port, laddr));

                if (logger.isLoggable(Level.FINEST))
                {
                    logger.log(
                            Level.FINEST,
                            "just bound to: " + sock.getLocalSocketAddress());
                }
                return sock;
            }
            catch (SocketException se)
            {
                logger.log(
                        Level.INFO,
                        "Retrying a bind because of a failure to bind to"
                            + " address " + laddr
                            + " and port " + port
                            + " (" + se.getMessage() +")");
                logger.log(Level.FINEST, "", se);
            }

            port ++;

            if (port > maxPort)
                port = minPort;
        }

        throw new BindException("Could not bind to any port between "
                        + minPort + " and " + (port - 1));
    }

    /**
     * Since we are most certainly going to use all local host candidates for
     * sending and receiving STUN connectivity checks, and possibly for STUN
     * harvesting too, we might as well create their STUN sockets here and
     * register them with the StunStack. This allows us to avoid conflicts
     * between the STUN harvester and the connectivity checks later on.
     *
     * @param candidate the candidate whose stun socket we'd like to initialize
     * and register with the StunStack.
     */
    private void createAndRegisterStunSocket(HostCandidate candidate)
    {
        IceSocketWrapper stunSocket = candidate.getStunSocket(null);

        candidate.getStunStack().addSocket(stunSocket);
    }

    /**
     * Checks if the different ports are correctly set. If not, throws {@link IllegalArgumentException}. The
     * special values 0, 0, 0 for the parameters are interpreted as "use an ephemeral port".
     *
     * @return {@code true} if the params specify that an ephemeral port should be used, and {@code false} otherwise.
     *
     * @param preferredPort the port number that we should try to bind to first.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort</tt> is
     * greater than <tt>maxPort</tt>.
     */
    private static boolean checkPorts(int preferredPort, int minPort, int maxPort)
        throws IllegalArgumentException
    {
        if (preferredPort == 0 && minPort == 0 && maxPort == 0)
        {
            return true;
        }

        // make sure port numbers are valid
        if (!NetworkUtils.isValidPortNumber(minPort)
                        || !NetworkUtils.isValidPortNumber(maxPort))
        {
            throw new IllegalArgumentException("minPort (" + minPort
                            + ") and maxPort (" + maxPort + ") "
                            + "should be integers between 1024 and 65535.");
        }

        // make sure minPort comes before maxPort.
        if (minPort > maxPort)
        {
            throw new IllegalArgumentException("minPort (" + minPort
                            + ") should be less than or "
                            + "equal to maxPort (" + maxPort + ")");
        }

        // if preferredPort is not  in the allowed range, place it at min.
        if (minPort > preferredPort || preferredPort > maxPort)
        {
            throw new IllegalArgumentException("preferredPort ("+preferredPort
                            +") must be between minPort (" + minPort
                            + ") and maxPort (" + maxPort + ")");
        }

        return false;
    }

    /**
     * Returns the statistics describing how well the various harvests of this
     * harvester went.
     *
     * @return The {@link HarvestStatistics} describing this harvester's
     * harvests.
     */
    public HarvestStatistics getHarvestStatistics()
    {
        return harvestStatistics;
    }
}
