/*
 * Jitsi Videobridge, OpenSource video conferencing.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.ice4j.ice.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

/**
 * Uses the Amazon AWS APIs to retrieve the public and private IPv4 addresses
 * for an EC2 instance.
 *
 * @author Emil Ivov
 */
public class AwsCandidateHarvester
    extends MappingCandidateHarvester
{
    /**
     * The <tt>Logger</tt> used by the <tt>AwsCandidateHarvester</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(AwsCandidateHarvester.class.getName());

    /**
     * The URL where one obtains AWS public addresses.
     */
    private static final String PUBLIC_IP_URL
        = "http://169.254.169.254/latest/meta-data/public-ipv4";

    /**
     * The URL where one obtains AWS private/local addresses.
     */
    private static final String LOCAL_IP_URL
        = "http://169.254.169.254/latest/meta-data/local-ipv4";

    /**
     * The addresses that we will use as a mask
     */
    private static TransportAddress mask;

    /**
     * The addresses that we will be masking
     */
    private static TransportAddress face;

    /**
     * Creates an AWS harvester. The actual addresses wil be retrieved later,
     * during the first harvest.
     */
    public AwsCandidateHarvester()
    {
        super(null, null);
    }
    /**
     * Maps all candidates to this harvester's mask and adds them to
     * <tt>component</tt>.
     *
     * @param component the {@link Component} that we'd like to map candidates
     * to.
     * @return  the <tt>LocalCandidate</tt>s gathered by this
     * <tt>CandidateHarvester</tt> or <tt>null</tt> if no mask is specified.
     */
    public Collection<LocalCandidate> harvest(Component component)
    {

        if (mask == null || face == null)
        {
            if(!obtainEC2Addresses())
                return null;
        }


        /*
         * Report the LocalCandidates gathered by this CandidateHarvester so
         * that the harvest is sure to be considered successful.
         */
        Collection<LocalCandidate> candidates = new HashSet<LocalCandidate>();

        for (Candidate<?> cand : component.getLocalCandidates())
        {
            if (!(cand instanceof HostCandidate)
                || !cand.getTransportAddress().getHostAddress()
                            .equals(face.getHostAddress()))
            {
                continue;
            }

            TransportAddress mappedAddress = new TransportAddress(
                mask.getHostAddress(),
                cand.getHostAddress().getPort(),
                cand.getHostAddress().getTransport());

            ServerReflexiveCandidate mappedCandidate
                = new ServerReflexiveCandidate(
                    mappedAddress,
                    (HostCandidate)cand,
                    cand.getStunServerAddress(),
                    CandidateExtendedType.STATICALLY_MAPPED_CANDIDATE);

            //try to add the candidate to the component and then
            //only add it to the harvest not redundant
            if( !candidates.contains(mappedCandidate)
                && component.addLocalCandidate(mappedCandidate))
            {
                candidates.add(mappedCandidate);
            }
        }

        return candidates;
    }

    /**
     * Sends HTTP GET queries to
     * <tt>http://169.254.169.254/latest/meta-data/local-ipv4</tt> and
     * <tt>http://169.254.169.254/latest/meta-data/public-ipv4</tt> to learn the
     * private (face) and public (mask) addresses of this EC2 instance.
     *
     * @return <tt>true</tt> if we managed to obtain addresses or someone else
     * had already achieved that before us, <tt>false</tt> otherwise.
     */
    private static synchronized boolean obtainEC2Addresses()
    {
        if(mask != null && face != null)
            return true;

        String localIPStr = null;
        String publicIPStr = null;

        try
        {
            localIPStr = fetch(LOCAL_IP_URL);
            publicIPStr = fetch(PUBLIC_IP_URL);

            //now let's cross our fingers and hope that what we got above are
            //real IP addresses
            face = new TransportAddress(localIPStr, 9, Transport.UDP);
            mask = new TransportAddress(publicIPStr, 9, Transport.UDP);

            logger.info("Detected AWS local IP: " + face);
            logger.info("Detected AWS public IP: " + mask);


        }
        catch (Exception exc)
        {
            //whatever happens, we just log and bail
            logger.log(Level.INFO, "We failed to obtain EC2 instance addresses "
                + "for the following reason: ", exc);
            logger.info("String for local IP: " + localIPStr);
            logger.info("String for public IP: " + publicIPStr);

        }

        return true;
    }

    /**
     * Determines if there is a decent chance for the box executing this
     * application to be an AWS EC2 instance and returns <tt>true</tt> if so.
     * Note that this method does not provide any guarantees. It just tries
     * to provide a way to quickly determine if we are unlikely to be running
     * an EC2 so as to avoid the GET queries during harvesting. Running those
     * queries on a non-EC2 machine takes them a while to expire.
     *
     * @return <tt>true</tt> if there appear to be decent chances for this
     * machine to be an AWS EC2 (i.e. ec2metadata executes) and <tt>false</tt>
     * otherwise.
     */
    public static boolean smellsLikeAnEC2()
    {
        try
        {
            if(new File("/usr/bin/ec2metadata").exists())
                return true;

            //the command below seems to be freezing on some systems.
            //Runtime.getRuntime().exec("ec2metadata --help");

            //if this is an AWS EC2 we would throw an exception above and not
            //get here, so ... be happy
            return true;
        }
        catch(Exception exc)
        {
            //ah! I knew you weren't one of those ...
            return false;
        }
    }

    /**
     * Retrieves the content at the specified <tt>url</tt>. No more, no less.
     *
     * @param url the URL we'd like to open and query.
     *
     * @return the String we retrieved from the URL.
     *
     * @throws Exception if anything goes wrong.
     */
    private static String fetch(String url)
        throws Exception
    {
        URLConnection conn = new URL(url).openConnection();
        BufferedReader in = new BufferedReader(new InputStreamReader(
                    conn.getInputStream(),  "UTF-8"));

        String retString = in.readLine();

        in.close();

        return retString;
    }
}
