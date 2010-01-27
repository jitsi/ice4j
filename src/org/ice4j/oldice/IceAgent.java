/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.stack.*;
import org.ice4j.stunclient.*;


/**
 * An IceAgent could be described as the main class (i.e. the chef d'orchestre)
 * of an ICE implementation.
 * <p>
 * As defined in RFC 3264, an agent is the protocol implementation involved in
 * the offer/answer exchange. There are two agents involved in an offer/answer
 * exchange.
 * <p>
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class IceAgent
{
    /**
     * Our class logger.
     */
    private final Logger logger
        = Logger.getLogger(IceAgent.class.getName());

    /**
     * The STUN server used to create mappings for gathered candidates
     */
    private TransportAddress stunServer = null;

    /**
     * The TURN server used to allocate a relayed address.
     */
    private TransportAddress turnServer = null;

    /**
     * The singleton STUN stack object used by IceAgent
     */
    private StunStack stunStack;

    /**
     * Indicates whether the client is controlling or controlled
     */
    private boolean isControlling = false;

    /**
     * The STUN Client used by IceAgent to perform connectivity checks
     */
    private StunClient stunClient;

    /**
     * The <code>long</code> tie-breaker value used
     * to resolve IceAgent Role conflicts
     */
    private long tiebreaker;

    /**
     * The LinkedHashMap used to store the media streams
     * This map preserves the insertion order of the media streams.
     */
    private Map<String, MediaStream> mediaStreams
                                    = new LinkedHashMap<String, MediaStream>();

    /**
     * Creates an IceAgent objects
     */
    public IceAgent()
    {
        super();
        stunStack = StunStack.getInstance();
        stunClient = new StunClient(stunStack);

        //creating a Randomizer with current time as seed used to get
        Random random = new Random(System.currentTimeMillis());
        tiebreaker = random.nextLong();
    }

    /**
     * Configures the <tt>IceAgent</tt> with the STUN server address that we
     * need to use to obtain server reflexive candidates.
     *
     * @param stunServer the address of the StunServer that we should be using
     * to obtain server reflexive candidates.
     */
    public void setStunServerAddress(TransportAddress stunServer)
    {
        this.stunServer = stunServer;
    }

    /**
     * Creates a new media stream and stores it
     *
     * @param mediaStreamName    the name of the media stream
     * @throws IceException if a key already exists for the specified media
     * stream name
     */
    public void addMediaStream(String mediaStreamName)
        throws IceException
    {
        if(mediaStreams.containsKey(mediaStreamName))
        {
            throw new IceException();
        }
        else
        {
            mediaStreams.put(mediaStreamName,
                            new MediaStream(IceAgent.this, mediaStreamName));
        }
    }

    /**
     * Returns a media-stream object corresponding to the given name
     *
     * @param name the name of the Media-Stream
     * @return     the Media-stream object corresponding to the given name
     * @throws IceException    if name is not a valid media-stream name
     */
    public MediaStream getMediaStream(String name)
        throws IceException
    {
        if(!mediaStreams.containsKey(name))
        {
            throw new IceException("MediaStream : " + name + " does not exist");
        }
        else
        {
            return mediaStreams.get(name);
        }
    }

    /**
     * Returns the list of media stream according to the order which they
     * were added to IceAgent
     *
     * @return List containing MediaStreams in IceAgent
     */
    public List<MediaStream> getOrederedMediaStreams()
    {
        List<MediaStream> msList = new ArrayList<MediaStream>();
        Iterator<MediaStream> msiterator = mediaStreams.values().iterator();
        while(msiterator.hasNext())
        {
            msList.add(msiterator.next());
        }
        return msList;
    }

    /**
     * Returns the Tie-breaker for this IceAgent
     *
     * @return long value indicating the tie-breaker
     */
    public long getTieBreaker()
    {
        return tiebreaker;
    }

    /**
     * Sets a new Tie-Breaker for this IceAgent
     * @param tieBreaker   the long value that is used as the new tie-breaker
     */
    public void setTieBreaker(long tieBreaker)
    {
        this.tiebreaker = tieBreaker;
    }


    /**
     * This is the first step of ICE protocol
     * This must be called only after media streams and their corresponding
     * components are created and stunServer address is set on the StunClient
     *
     * @throws IceException if a problem occurs while gathering candidates.
     */
    public void gatherCandidates()
        throws IceException
    {
        // holds all of the Host IP addresses of the machine
        ArrayList<InetAddress> inetAddresses = new ArrayList<InetAddress>();

        // if the stun server is not installed, throw an exception
        if(stunServer == null)
        {
            logger.log(Level.SEVERE, "Stun Server Address not set in IceAgent");
            throw new IceException("Stun Server is null");
        }

        try
        {
            // retrieve all the network interfaces available in the machine as
            // an enumeration
            Enumeration<NetworkInterface> netifs
                = NetworkInterface.getNetworkInterfaces();
            for(NetworkInterface netif : Collections.list(netifs))
            {
                // for each Network interface, if it is not the Loop-back and
                //is up and running
                /* FIXME - uncomment.
                if(netif.isUp() && !netif.isLoopback())
                {
                    // enumerate all the IP addresses for that network interface
                    Enumeration<InetAddress> addrs = netif.getInetAddresses();
                    ArrayList<InetAddress> addrList = Collections.list(addrs);

                    // append all the discovered IP addresses to the
                    // inetAddresses ArrayList
                    inetAddresses.addAll(addrList);
                }
                */
            }

            // collection of the media-streams of this agent in the order
            // which they were added
            Collection<MediaStream> mds = mediaStreams.values();
            List<Component> componentList;

            // for each media stream
            for(MediaStream mediaStream : mds)
            {
                List<Candidate> candidateList = new ArrayList<Candidate>();
                List<TransportAddress> traList = new ArrayList<TransportAddress>();
                TransportAddress tpAddress;
                TransportAddress reflxAddress;
                Candidate hostCandidate;
                Candidate serverReflxCandidate;

                // retrieve the component list
                componentList = mediaStream.getComponentsList();

                // for each component in that list
                for(Component component : componentList)
                {
                    // create Host type transport addresses
                    for(int i = 0; i < inetAddresses.size(); i++)
                    {


is(inetAddresses.get(i), 0));

                        NetAccessPointDescriptor apDes = stunStack.installNetAccessPoint(sock);

                        tpAddress = apDes.getAddress();

                        traList.add(tpAddress);

                        // create Host candidates
                        hostCandidate = new Candidate(tpAddress, component);
                        hostCandidate.setCandidateType(Candidate.HOST_CANDIDATE);
                        hostCandidate.setBase(hostCandidate);
                        candidateList.add(hostCandidate);

                        logger.log(Level.INFO, "Host-Candidate created for [Component " +
                                component.getComponentID() + "] of [Mediastream : " + mediaStream.getName() +
                                "] with binding " + tpAddress.toString());

                        // execute address-discovery for every transport, using blocking mode of stun-client
                        // get server-reflexive addresses
                        // create candidate with the specified type
                        reflxAddress = stunClient.determineAddress(tpAddress, stunServer);

                        if(reflxAddress != null)
                        {
                            serverReflxCandidate = new Candidate(reflxAddress, component);
                            serverReflxCandidate.setCandidateType(
                                    Candidate.SERVER_REFLEXIVE_CANDIDATE);
                            serverReflxCandidate.setBase(hostCandidate);
                            candidateList.add(serverReflxCandidate);

                            logger.log(Level.INFO, "ServerReflexive-Candidate created for [Component " +
                                    component.getComponentID() + "] of [Mediastream : " + mediaStream.getName() +
                                    "] with binding " + reflxAddress.toString());
                        }
                    }
                }
                // add all of the candidates using addLocalCandidate in MediaStream
                mediaStream.addLocalCandidates(candidateList);


            }

            /* ---------------------- Computing foundations --------------------------------------- */

            logger.log(Level.INFO, "Starting Computing foundations for candidates");

            int foundation = 1;  // foundation string is actually an integer value
                                 // and starts with 1

            // create separate lists depending on the type
            // host candidate list
            List<Candidate> hostList = new ArrayList<Candidate>();

            // server reflexive candidate list
            List<Candidate> serverRflxList = new ArrayList<Candidate>();

            // iterate through all the candidates and categorize them into
            // host and server-reflexive lists
            List<Candidate> clist;
            Candidate tempCandidate;
            for(MediaStream mediaStream : mds)
            {
                clist = mediaStream.getLocalCandidateList();
                for(int i = 0; i < clist.size(); i++)
                {
                    tempCandidate = clist.get(i);
                    String candidateType = tempCandidate.getCandidateType();
                    if(candidateType.equals(Candidate.HOST_CANDIDATE))
                    {
                        hostList.add(tempCandidate);
                    }
                    else if(candidateType.equals(Candidate.SERVER_REFLEXIVE_CANDIDATE))
                    {
                        serverRflxList.add(tempCandidate);
                    }
                    else if(candidateType.equals(Candidate.RELAYED_CANDIDATE))
                    {
                        // do nothing at the moment
                    }
                    else
                    {
                        // do nothing at the moment
                    }
                }
            }

            // A hash map of array lists which holds groups of candidates
            // which have different bases
            HashMap<String, List<Candidate>> iplist = new HashMap<String, List<Candidate>>();

            // for host list, categorize the candidates according to their base address
            Candidate base;
            List<Candidate> baseList;
            String key;
            for(int j = 0; j < hostList.size(); j++)
            {
                tempCandidate = hostList.get(j);
                base = tempCandidate.getBase();
                // port no is not considered when comparing bases
                //key = base.toString(); so this is wrong
                key = base.getTransportAddress().getSocketAddress().getAddress().toString();

                if(!iplist.containsKey(key))
                {
                    baseList = new ArrayList<Candidate>();
                    iplist.put(key, baseList);
                }
                else
                {
                    baseList = iplist.get(key);
                }
                baseList.add(tempCandidate);
            }

            // assign foundation for this iplist
            for(List<Candidate> canList : iplist.values())
            {
                // for a list which contains identical base IPs in host candidate list
                for(int k = 0; k < canList.size(); k++)
                {
                    tempCandidate = canList.get(k);
                    tempCandidate.setFoundation(Integer.toString(foundation));

                    logger.log(Level.INFO, "Foundation of candidate " + tempCandidate.getTransportAddress().toString() +
                            "[Component: " + tempCandidate.getParentComponent().getComponentID() + "]" +
                            " of [Mediastream:" + tempCandidate.getParentComponent().getParentMediaStream().getName() + "]" +
                            "= " + foundation);
                }
                foundation++;
            }

            iplist.clear();

            // for the server reflexive types, categorize the candidate accortding to their bases
            for(int i = 0; i < serverRflxList.size(); i++)
            {
                tempCandidate = serverRflxList.get(i);
                base = tempCandidate.getBase();
                // port no is not compared when comparing bases
                //key = base.toString(); so this is wrong
                key = base.getTransportAddress().getSocketAddress().getAddress().toString();

                if(!iplist.containsKey(key))
                {
                    baseList = new ArrayList<Candidate>();
                    iplist.put(key, baseList);
                }
                else
                {
                    baseList = iplist.get(key);
                }
                baseList.add(tempCandidate);
            }

            // assign foundations for the iplist
            for(List<Candidate> canList : iplist.values())
            {
                for(int k = 0; k < canList.size(); k++)
                {
                    tempCandidate = canList.get(k);
                    tempCandidate.setFoundation(Integer.toString(foundation));

                    logger.log(Level.INFO, "Foundation of candidate " + tempCandidate.getTransportAddress().toString() +
                            "[Component: " + tempCandidate.getParentComponent().getComponentID() + "]" +
                            " of [Mediastream:" + tempCandidate.getParentComponent().getParentMediaStream().getName() + "]" +
                            "= " + foundation);
                }
                foundation++;
            }

            iplist.clear();
            iplist = null;
        }
        catch (StunException ex)
        {
            logger.log(Level.SEVERE, "StunException", ex);
        }
        catch (SocketException ex)
        {
            logger.log(Level.SEVERE, "SocketException occurred while retrieving Network Interface" +
                    " information", ex);
        }
        catch (IOException ex)
        {
            logger.log(Level.SEVERE, "IOException occurred.. while gathering public IPs", ex);
        }

    }

    /**
     * Prioritizes the candidates in each and every media-stream
     * and remove redundant candidates
     *
     */
    public void prioritizeCandidates()
    {
        // prioritizing the candidates
        List<Candidate> candidateList;
        Candidate candidate;

        // for each media-stream, compute the priority of every local candidate
        for(MediaStream mediaStream : mediaStreams.values())
        {
            candidateList = mediaStream.getLocalCandidateList();

            for(int i = 0; i < candidateList.size(); i++)
            {
                candidate = candidateList.get(i);
                setPriority(candidate);

                logger.log(Level.INFO, "Setting priority of candidate : " + candidate.getTransportAddress().toString() +
                        " of [Component : " + candidate.getParentComponent().getComponentID() + "]" +
                        " of [MediaStream : " + mediaStream.getName() + "] to " + candidate.getPriority());
            }
        } ///~ end of prioritizing candidates

        // remove redundant candidates
        removeRedundantCandidates();
    }

    public void setPeerReflexivePriority(Candidate candidate)
    {
        if(candidate.getCandidateType() != Candidate.PEER_REFLEXIVE_CANDIDATE)
            return;

        setPriority(candidate);
    }

    /**
     * Computes and sets the priority of the supplied candidate
     *
     * @param candidate the Candidate object to which priority must be
     *                  assigned
     */
    private void setPriority(Candidate candidate)
    {
        candidate.setPriority(Candidate.computePriority(candidate));
    }

    /**
     * Removes redundant candidates from a component
     * A candidate is redundant if its transport address and base is equal to
     * another candidate
     *
     * @param    componentCandidateList  Candidate list for a particular candidate
     * @param    mslocalCandidates        local candidate list for a media-stream
     */
    private void removeRedundantCandidates()
    {
        logger.log(Level.INFO, "Starting of removing redundant candidates...");

        // for each media-stream create a HashMap which stores a list as value and
        // component ID as the key
        for(MediaStream mediaStream : mediaStreams.values())
        {
            HashMap<Integer, List<Candidate>> componentCandidates
                    = new HashMap<Integer, List<Candidate>>();

            // local candidates for this media stream
            List<Candidate> candidateList = mediaStream.getLocalCandidateList();
            Candidate candidate;
            int componentID;

            // categorizing candidates according to their components in one media-stream
            for(int i = 0; i < candidateList.size(); i++)
            {
                candidate = candidateList.get(i);
                componentID = candidate.getParentComponent().getComponentID();

                // if the hash map does not contains an entry corresponding to that component
                if(!componentCandidates.containsKey(new Integer(componentID)))
                {
                    List<Candidate> candidates = new ArrayList<Candidate>();
                    candidates.add(candidate);
                    componentCandidates.put(new Integer(componentID), candidates);
                }
                else
                {
                    List<Candidate> candidates = componentCandidates.get(new Integer(componentID));
                    candidates.add(candidate);
                }
            }
            // ~// end of categorizing candidates according to components for one media stream

            // the key value used to group candidates according to their
            // transport and base addresses
            String key;

            // for each and every list stored in the HashMap
            for(List<Candidate> canList : componentCandidates.values())
            {
                HashMap<String, List<Candidate>> redundantMap =
                                                    new HashMap<String, List<Candidate>>();
                Iterator<Candidate> can = canList.iterator();
                while(can.hasNext())
                {
                    candidate = can.next();
                    key = candidate.getTransportAddress().toString() + " " +
                            candidate.getBase().getTransportAddress().toString();
                    if(!redundantMap.containsKey(key))
                    {
                        List<Candidate> newList = new ArrayList<Candidate>();
                        newList.add(candidate);
                        redundantMap.put(key, newList);
                    }
                    else
                    {
                        List<Candidate> newList = redundantMap.get(key);
                        newList.add(candidate);
                    }
                }
                // ~// end of identifying redundant candidates

                // remove redundant candidates
                for(List<Candidate> redundantList : redundantMap.values())
                {
                    // if there is only one candidates in this list, no redundancy
                    if(redundantList.size() > 1)
                    {
                        // the highest priority discovered in the list so far
                        long highestPriority = -1;

                        // temporary variable to hold the priority of the current candidate
                        long tempPriority = 0;

                        // variable which holds the current candidate
                        Candidate tempCan = null;

                        // variable which holds the reference to the candidate which has the highest priority
                        // so far
                        Candidate highPriorityCan = null;

                        Iterator<Candidate> canit = redundantList.iterator();
                        while(canit.hasNext())
                        {
                            tempCan = canit.next();
                            tempPriority = tempCan.getPriority();
                            if(tempPriority > highestPriority)
                            {
                                    highestPriority = tempPriority;

                                    // this check provides the protection for the 1st iteration
                                    if(highPriorityCan != null)
                                        candidateList.remove(highPriorityCan);
                                    highPriorityCan = tempCan;
                            }
                            else
                            {
                                candidateList.remove(tempCan);

                                logger.log(Level.INFO, "Candidate : " + tempCan.toString() + " of" +
                                        " [Component:" + tempCan.getParentComponent().getComponentID() + "]" +
                                        " of [Mediastream:" + mediaStream.getName() + "] is redundant");
                            }
                        }
                    }
                }
            }

        }
    }

    /**
     * Creates a CHECK-LIST for every media stream
     */
    public void createCheckLists()
    {
        for(MediaStream mediaStream : mediaStreams.values())
        {
            mediaStream.createCheckList();
        }
    }

    /**
     * Performs the connectivity checks for the agent
     */
    public void performConnectivityChecks()
    {

    }

    /**
     * Returns whether the IceAgent is ICE-CONTROLLING or
     * ICE-COTROLLED
     *
     * @return the boolean value representing the role<br/>
     *         If <code>true</code>, agent is the controlling agent
     *         if <code>false</code>, agent is the controlled agent
     */
    public boolean isControlling()
    {
        return isControlling;
    }

    /**
     * Sets the new role of the agent
     * <ul>
     *  <li>ICE-CONROLLING</li>
     *  <li>ICE-CONTROLLED</li>
     * </ul>
     *
     * @param isControlling boolean value
     */
    public void setIsControlling(boolean isControlling)
    {
        this.isControlling = isControlling;
    }
}
