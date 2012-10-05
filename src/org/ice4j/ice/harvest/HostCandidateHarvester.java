/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.socket.*;

/**
 * A <tt>HostCandidateHarvester</tt> gathers host <tt>Candidate</tt>s for a
 * specified {@link org.ice4j.ice.Component}. Most <tt>CandidateHarvester</tt>s
 * would rely on the output of the host harvester, that is all host addresses,
 * to be already present and bound in a <tt>Component</tt> before being able to
 * harvest the type of addresses that they are responsible for.
 *
 * @author Emil Ivov
 */
public class HostCandidateHarvester
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(HostCandidateHarvester.class.getName());

    /**
     * Manages statisics about harvesting time.
     */
    private HarvestingTimeStat harvestingTimeStat = new HarvestingTimeStat();

    /**
     * Gathers all candidate addresses on the local machine, binds sockets on
     * them and creates {@link HostCandidate}s. The harvester would always
     * try to bind the sockets on the specified <tt>preferredPort</tt> first.
     * If that fails we will move through all ports between <tt>minPort</tt> and
     * <tt>maxPort</tt> and give up if still can't find a free port.
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
     * <tt>maxPort</tt> is not a valid port number, <tt>minPort >
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
        this.startHarvesting();

        Enumeration<NetworkInterface> interfaces
                        = NetworkInterface.getNetworkInterfaces();

        boolean isIPv6Disabled = StackProperties.getBoolean(
                StackProperties.DISABLE_IPv6,
                false);

        if(transport != Transport.UDP && transport != Transport.TCP)
        {
            throw new IllegalArgumentException(
                "Transport protocol not supported: " + transport);
        }

        boolean boundAtLeastOneSocket = false;
        while (interfaces.hasMoreElements())
        {
            NetworkInterface iface = interfaces.nextElement();

            if (NetworkUtils.isInterfaceLoopback(iface)
                || !NetworkUtils.isInterfaceUp(iface))
            {
                //this one is obviously not going to do
                continue;
            }

            Enumeration<InetAddress> addresses = iface.getInetAddresses();

            while(addresses.hasMoreElements())
            {
                InetAddress addr = addresses.nextElement();

                if((addr instanceof Inet4Address) || !isIPv6Disabled)
                {
                    IceSocketWrapper sock = null;
                    try
                    {
                        if(transport == Transport.UDP)
                        {
                            sock = createDatagramSocket(
                                addr, preferredPort, minPort, maxPort);
                            boundAtLeastOneSocket = true;
                        }
                        else if(transport == Transport.TCP)
                        {
                            if(addr instanceof Inet6Address)
                                continue;
                            sock = createServerSocket(
                                    addr,
                                    preferredPort,
                                    minPort,
                                    maxPort,
                                    component);
                            boundAtLeastOneSocket = true;
                        }
                    }
                    catch(IOException exc)
                    {
                        // There seems to be a problem with this particular
                        // address let's just move on for now and hope we will
                        // find better
                        if (logger.isLoggable(Level.WARNING))
                        {
                            logger.warning(
                                    "Failed to create a socket for:"
                                        +"\naddr:" + addr
                                        +"\npreferredPort:" + preferredPort
                                        +"\nminPort:" + minPort
                                        +"\nmaxPort:" + maxPort
                                        +"\nprotocol:" + transport
                                        +"\nContinuing with next address");
                        }
                        continue;
                    }

                    HostCandidate candidate
                        = new HostCandidate(sock, component, transport);
                    candidate.setVirtual(
                            NetworkUtils.isInterfaceVirtual(iface));
                    component.addLocalCandidate(candidate);

                    if(transport == Transport.TCP)
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
                }
            }
        }

        if(!boundAtLeastOneSocket)
        {
            throw new IOException(
                "Failed to bind even a single host candidate for component:"
                            + component
                            + " preferredPort=" + preferredPort
                            + " minPort=" + minPort
                            + " maxPort=" + maxPort);
        }

        this.stopHarvesting();
        logger.info(
                "End candidate harvest within "
                + this.getHarvestingTime()
                + " ms, for "
                + this.getClass().getName()
                + ", component: " + component.getComponentID());
    }

    /**
     * Creates a <tt>ServerSocket</tt> and binds it to the specified
     * <tt>localAddress</tt> and a port in the range specified by the
     * <tt>minPort</tt> and <tt>maxPort</tt> parameters.
     *
     * @param laddr the address that we'd like to bind the socket on.
     * @param preferredPort the port number that we should try to bind to first.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwinG an exception.
     *
     * @return the newly created <tt>DatagramSocket</tt>.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort >
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
        this.checkPorts(preferredPort, minPort, maxPort);

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
                                = new IceTcpServerSocketWrapper(sock,
                                    component);

                if(logger.isLoggable(Level.FINEST))
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

        throw new BindException("Could not bind to any port between "
                        + minPort + " and " + (port - 1));
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
     * @param laddr the address that we'd like to bind the socket on.
     * @param preferredPort the port number that we should try to bind to first.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwinG an exception.
     *
     * @return the newly created <tt>DatagramSocket</tt>.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort >
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
        this.checkPorts(preferredPort, minPort, maxPort);

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

                if(logger.isLoggable(Level.FINEST))
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
                logger.log(Level.INFO, "", se);
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
     * Checks if the different ports are correctly set. If not, throws an
     * IllegalArgumentException.
     *
     * @param preferredPort the port number that we should try to bind to first.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwinG an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort</tt> is
     * greater than <tt>maxPort</tt>.
     */
    private void checkPorts(int preferredPort, int minPort, int maxPort)
        throws IllegalArgumentException
    {
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
    }

    /**
     * Starts the harvesting timer. Called when the harvest begins.
     */
    public void startHarvesting()
    {
        this.harvestingTimeStat.startHarvesting();
    }

    /**
     * Stops the harvesting timer. Called when the harvest ends.
     */
    public void stopHarvesting()
    {
        this.harvestingTimeStat.stopHarvesting();
    }

    /**
     * Returns the current harvesting time in ms. If this harvester is not
     * currently harvesting, then returns the value of the last harvesting time.
     * 0 if this harvester has nerver harvested.
     *
     * @return The current harvesting time in ms. If this harvester is not
     * currently harvesting, then returns the value of the last harvesting time.
     * 0 if this harvester has nerver harvested.
     */
    public long getHarvestingTime()
    {
        return this.harvestingTimeStat.getHarvestingTime();
    }

    /**
     * Returns the number of harvesting for this harvester.
     *
     * @return The number of harvesting for this harvester.
     */
    public int getNbHarvesting()
    {
        return this.harvestingTimeStat.getNbHarvesting();
    }
}
