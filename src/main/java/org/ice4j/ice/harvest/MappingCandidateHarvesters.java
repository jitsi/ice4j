/*
 * Copyright @ 2015-2016 Atlassian Pty Ltd
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

import org.ice4j.*;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * Manages a static list of {@link MappingCandidateHarvester} instances, created
 * according to configuration provided as system properties.
 *
 * The instances in the set are safe to use by any {@code Agent}s.
 *
 * @author Damian Minkov
 * @author Boris Grozev
 */
public class MappingCandidateHarvesters
{
    /**
     * The {@link Logger} used by the {@link MappingCandidateHarvesters}
     * class for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(MappingCandidateHarvesters.class.getName());

    /**
     * The name of the property that specifies the local address, if any, for
     * the pre-configured NAT harvester.
     */
    public static final String NAT_HARVESTER_LOCAL_ADDRESS_PNAME
        = "org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS";

    /**
     * The name of the property that specifies the public address, if any, for
     * the pre-configured NAT harvester.
     */
    public static final String NAT_HARVESTER_PUBLIC_ADDRESS_PNAME
        = "org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS";

    /**
     * The name of the property used to disable the AWS harvester.
     */
    public static final String DISABLE_AWS_HARVESTER_PNAME
        = "org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER";

    /**
     * The name of the property which forces the use of the AWS harvester.
     */
    public static final String FORCE_AWS_HARVESTER_PNAME
        = "org.ice4j.ice.harvest.FORCE_AWS_HARVESTER";

    /**
     * The name of the property which contains the addresses of the STUN servers
     * to use for the STUN mapping harvester. The property should contain a
     * comma-separated list of addresses (pairs of IP address and port,
     * separated by a colon). Example:
     * {@code stun1.example.com:12345,stun2.example.com:23456}
     */
    public static final String STUN_MAPPING_HARVESTER_ADDRESSES_PNAME
        = "org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES";

    /**
     * Whether {@link #harvesters} has been initialized.
     */
    private static boolean initialized = false;

    /**
     * The list of already configured harvesters.
     */
    private static MappingCandidateHarvester[] harvesters;

    /**
     * Whether the discovery of a public address via STUN has failed.
     * It is considered failed if the configuration included at least one STUN
     * server, but we failed to receive at least one valid response.
     * Note that this defaults to false and is only raised after we are certain
     * we failed (i.e. after our STUN transactions timeout).
     */
    public static boolean stunDiscoveryFailed = false;

    /**
     * @return the list of configured harvesters.
     */
    public static MappingCandidateHarvester[] getHarvesters()
    {
        initialize();
        return harvesters;
    }

    /**
     * Initializes {@link #harvesters}.
     * First it reads the configuration and instantiates harvesters accordingly,
     * waiting for their initialization (which may include network communication
     * and thus take a long time). Then it removes harvesters which failed to
     * initialize properly and remove any harvesters with duplicate addresses.
     *
     * Three types of mapping harvesters are supported: NAT (with
     * pre-configured addresses), AWS and STUN.
     */
    public static synchronized void initialize()
    {
        if (initialized)
            return;
        initialized = true;

        long start = System.currentTimeMillis();
        List<MappingCandidateHarvester> harvesterList = new LinkedList<>();


        // Pre-configured NAT harvester.
        String localAddressStr
            = StackProperties.getString(NAT_HARVESTER_LOCAL_ADDRESS_PNAME);
        String publicAddressStr
            = StackProperties.getString(NAT_HARVESTER_PUBLIC_ADDRESS_PNAME);

        if (localAddressStr != null && publicAddressStr != null)
        {
            // the port number is unused, 9 is for "discard"
            TransportAddress localAddress
                = new TransportAddress(localAddressStr, 9, Transport.UDP);
            TransportAddress publicAddress
                = new TransportAddress(publicAddressStr, 9, Transport.UDP);

            harvesterList.add(
                new MappingCandidateHarvester(publicAddress, localAddress));
        }

        // AWS harvester
        boolean disableAwsHarvester
            = StackProperties.getBoolean(DISABLE_AWS_HARVESTER_PNAME, false);
        boolean forceAwsHarvester
            = StackProperties.getBoolean(FORCE_AWS_HARVESTER_PNAME, false);

        if (logger.isLoggable(Level.FINE))
        {
            logger.fine("AWS configuration: disable=" + disableAwsHarvester
                        + "; force=" + forceAwsHarvester);
        }

        if (!disableAwsHarvester &&
            (forceAwsHarvester || AwsCandidateHarvester.smellsLikeAnEC2()))
        {
            harvesterList.add(new AwsCandidateHarvester());
        }

        // STUN harvesters
        String stunServers
            = StackProperties.getString(STUN_MAPPING_HARVESTER_ADDRESSES_PNAME);
        if (stunServers != null && !stunServers.isEmpty())
        {
            // Create STUN harvesters (and wait for all of their discovery to
            // finish).
            List<StunMappingCandidateHarvester> stunHarvesters
                = createStunHarvesters(stunServers.split(","));

            // We have STUN servers configured, so flag the failure if none of
            // them were able to discover an address.
            stunDiscoveryFailed = stunHarvesters.isEmpty();

            harvesterList.addAll(stunHarvesters);
        }

        harvesterList = prune(harvesterList);
        harvesters
            = harvesterList.toArray(
                    new MappingCandidateHarvester[harvesterList.size()]);

        for (MappingCandidateHarvester harvester : harvesters)
        {
            logger.info("Using " + harvester);
        }
        logger.info("Initialized mapping harvesters (delay="
                        + (System.currentTimeMillis() - start) + "ms). "
                        + " stunDiscoveryFailed=" + stunDiscoveryFailed);
    }

    /**
     * Prunes a list of mapping harvesters, removing the ones without valid
     * addresses and those with duplicate addresses.
     * @param harvesters the list of harvesters.
     * @return the pruned list.
     */
    private static List<MappingCandidateHarvester> prune(
        List<MappingCandidateHarvester> harvesters)
    {
        List<MappingCandidateHarvester> pruned = new LinkedList<>();
        for (MappingCandidateHarvester harvester : harvesters)
        {
            maybeAdd(harvester, pruned);
        }
        return pruned;
    }

    /**
     * Adds {@code harvester} to {@code harvesters}, if it has valid addresses
     * and {@code harvesters} doesn't already contain a harvester with the same
     * addresses.
     * @param harvester the harvester to add.
     * @param harvesters the list to add to.
     */
    private static void maybeAdd(
        MappingCandidateHarvester harvester,
        List<MappingCandidateHarvester> harvesters)
    {
        TransportAddress face = harvester.getFace();
        TransportAddress mask = harvester.getMask();
        if (face == null || mask == null || face.equals(mask))
        {
            logger.info("Discarding a mapping harvester: " + harvester);
            return;
        }

        for (MappingCandidateHarvester h : harvesters)
        {
            if (face.getAddress().equals(h.getFace().getAddress()) && mask.getAddress().equals(h.getMask().getAddress()))
            {
                logger.info("Discarding a mapping harvester with duplicate "
                            + "addresses: " + harvester + ". Kept: " + h);
                return;
            }
        }

        harvesters.add(harvester);
    }

    /**
     * Creates STUN mapping harvesters for each of the given STUN servers, and
     * waits for address discovery to finish for all of them.
     * @param stunServers an array of STUN server addresses (ip_address:port
     * pairs).
     * @return  the list of those who were successful in discovering an address.
     */
    private static List<StunMappingCandidateHarvester> createStunHarvesters(
            String[] stunServers)
    {
        List<StunMappingCandidateHarvester> stunHarvesters = new LinkedList<>();

        if (stunServers == null || stunServers.length == 0)
        {
            logger.severe("No STUN servers configured.");
            return stunHarvesters;
        }

        List<Callable<StunMappingCandidateHarvester>> tasks = new LinkedList<>();

        // Create a StunMappingCandidateHarvester for each local:remote address
        // pair.
        List<InetAddress> localAddresses
            = HostCandidateHarvester.getAllAllowedAddresses();
        for (String stunServer : stunServers)
        {
            String[] addressAndPort = stunServer.split(":");
            if (addressAndPort.length < 2)
            {
                logger.severe("Failed to parse STUN server address: "
                                  + stunServer);
                continue;
            }
            int port;
            try
            {
                port = Integer.parseInt(addressAndPort[1]);
            }
            catch (NumberFormatException nfe)
            {
                logger.severe("Invalid STUN server port: " + addressAndPort[1]);
                continue;
            }

            TransportAddress remoteAddress
                = new TransportAddress(
                addressAndPort[0],
                port,
                Transport.UDP);

            for (InetAddress localInetAddress : localAddresses)
            {
                if (localInetAddress instanceof Inet6Address)
                {
                    // This is disabled, because it is broken for an unknown
                    // reason and it is not currently needed.
                    continue;
                }

                TransportAddress localAddress
                    = new TransportAddress(localInetAddress, 0, Transport.UDP);

                final StunMappingCandidateHarvester stunHarvester
                    = new StunMappingCandidateHarvester(
                            localAddress,
                            remoteAddress);

                Callable<StunMappingCandidateHarvester> task
                    = new Callable<StunMappingCandidateHarvester>()
                {
                    @Override
                    public StunMappingCandidateHarvester call()
                        throws Exception
                    {
                        stunHarvester.discover();
                        return stunHarvester;
                    }
                };
                tasks.add(task);
            }
        }

        // Now run discover() on all created harvesters in parallel and pick
        // the ones which succeeded.
        ExecutorService es = Executors.newFixedThreadPool(tasks.size());

        List<Future<StunMappingCandidateHarvester>> futures;
        try
        {
            futures = es.invokeAll(tasks);
        }
        catch (InterruptedException ie)
        {
            Thread.currentThread().interrupt();
            return stunHarvesters;
        }

        for (Future<StunMappingCandidateHarvester> future : futures)
        {
            try
            {
                StunMappingCandidateHarvester harvester = future.get();

                // The STUN server replied successfully.
                if (harvester.getMask() != null)
                {
                    stunHarvesters.add(harvester);
                }
            }
            catch (ExecutionException ee)
            {
                // The harvester failed for some reason, discard it.
            }
            catch(InterruptedException ie)
            {
                Thread.currentThread().interrupt();
                throw new RuntimeException(ie);
            }
        }

        return stunHarvesters;
    }

    /**
     * Prevent instance creation.
     */
    private MappingCandidateHarvesters()
    {
    }
}
