/**
 * Stun4j, the OpenSource Java Solution for NAT and FirewWall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ice4j.*;


/**
 * The class represents a media stream from the ICE perspective, i.e. a 
 * collection of components.
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class MediaStream
{
    private static final Logger logger =
        Logger.getLogger(MediaStream.class.getName());    
    
    /**
     * The list locally gathered candidates for this media stream.
     */
    private List<Candidate> localCandidates = null;

    /**
     * The list of candidates that the peer agent sent for this stream.
     */
    private List<Candidate> remoteCandidates = null;
	
    /**
     * The VALID-LIST as described in ICE specification
     */
	private List<CandidatePair> validList = null;
	
	/**
	 * the CHECK-LIST as described in ICE specification 
	 */
	private List<CandidatePair> checkList = null;

    /**
     * Returns the list of components that this media stream consists of. A
     * component is a piece of a media stream requiring a single transport
     * address; a media stream may require multiple components, each of which
     * has to work for the media stream as a whole to work.
     */
    private LinkedHashMap<Integer, Component> components = new LinkedHashMap<Integer, Component>();

    /**
     * The agent that this media stream belongs to.
     */
    private IceAgent parentAgent = null;

    /**
     * The id that was last assigned to a component. The next id that we give
     * to a component would be lastComponendID + 1;
     */
    private int lastComponentID = 0;
    
    /**
     * The name of this media stream
     * The name is the value specified in the SDP
     */
    private String name;

    /**
     * Creates a new instance of MediaStream.
     *
     * @param parentAgent the agent that created this media stream.
     */
    
    /**
     * Specifies the state of the whole check list
     * Ir true - the check list is frozen
     * if false - the check list is active
     */
    public boolean frozenCheckList = true;    
    
    /**
     * Indicates that the ICE checks are still in progress for this 
     * media stream.
     */
    public static final String CHECK_LIST_RUNNING = "Running";
    
    /**
     * Indicates that the ICE checks have produced nominated pairs
     * for each component of the media stream.  Consequently, ICE has
     * succeeded and media can be sent.
     */
    public static final String CHECK_LIST_COMPLETED = "Completed";
    
    /**
     * Indicates that the ICE checks have not completed
     * successfully for this media stream.
     */
    public static final String CHECK_LIST_FAILED = "Failed";
    
    /**
     * Indicates the current state of the CHECK-LIST
     * The check list itself is associated with a state, which captures the 
     * state of ICE checks for that media stream
     */
    private String checkListState = CHECK_LIST_RUNNING;
    
    /**
     * Initializes a new MediaStream object
     * 
     * @param parentAgent   the IceAgent to which this media-stream belongs
     * @param name          the name of the media stream
     */
    public MediaStream(IceAgent parentAgent, String name)
    {
        this.parentAgent = parentAgent;
        this.name = name;
        
        localCandidates = new ArrayList<Candidate>();
        remoteCandidates = new ArrayList<Candidate>();
        validList = new ArrayList<CandidatePair>();
        checkList = new ArrayList<CandidatePair>();
    }

    /**
     * Returns the agent that created this media stream.
     *
     * @return a reference to the <tt>IceAgent</tt> that created this media
     * stream.
     */
    public IceAgent getParentAgent()
    {
        return parentAgent;
    }
    
    /**
     * Returns the name of the media-stream
     * @return name of the media-stream
     */
    public String getName()
    {
    	return name;
    }
    
    /**
     * Returns the state of an active check-list
     * There are three states
     * <ul>
     *  <li>CHECK_LIST_RUNNING</li>
     *  <li>CHECK_LIST_COMPLETED</li>
     *  <li>CHECK_LIST_FAILED</li>
     * </ul>
     * 
     * @return  the string representing current state of the CHECK-LIST
     * 
     */
    public String getCheckListState()
    {
        return checkListState;
    }
    
    /**
     * Returns the state of the CHECK-LIST
     * 
     * @param state the string representing the state of the CHECK-LIST
     */
    public void setCheckListState(String state)
    {
        this.checkListState = state;
    }

    /**
     * Returns the list of components that this media stream is composed of.
     * A component is a piece of a media stream requiring a single transport
     * address; a media stream may require multiple components, each of which
     * has to work for the media stream as a whole to work).
     */
    public LinkedHashMap<Integer, Component> getComponents()
    {
        return components;
    }
    
    /**
     * Returns a List of the components in the media stream
     * 
     * @return  the List which contains the components of the media-stream
     */
    public List<Component> getComponentsList()
    {
    	Collection<Component> cmps = components.values();
    	Iterator<Component> itcom = cmps.iterator();
    	
    	ArrayList<Component> componentList = new ArrayList<Component>();
    	while(itcom.hasNext())
    	{
    		componentList.add(itcom.next());
    	}
    	
    	return componentList;
    }
    
    /**
     * Creates and adds a component to this media-stream
     * The component ID is incremented to the next integer value
     * when creating the component
     * 
     * @param	transportProtocol	the transport protocol used by the component
     * @param	defaultAddress		address used for default-candidate
     */
    public void createComponent(String transportProtocol,
    							TransportAddress defaultAddress) 
    {
    	lastComponentID += 1;
    	components.put(new Integer(lastComponentID), 
    				   new Component(lastComponentID, transportProtocol,
    						   defaultAddress, this));
    }
    
    /**
     * Add a local candidate to this media-stream
     * 
     * @param candidate the candidate object to be added
     */
    public void addLocalCandidate(Candidate candidate)
    {
    	localCandidates.add(candidate);
    }
    
    /**
     * Adds a remote candidate to this media-stream
     * 
     * @param candidate the candidate object to be added
     */
    public void addRemoteCandidate(Candidate candidate)
    {
    	remoteCandidates.add(candidate);
    }
    
    /**
     * Adds a list of local candidates to this media-stream
     * 
     * @param candidates    a List of candidates to be added
     */
    public void addLocalCandidates(List<Candidate> candidates)
    {
    	localCandidates.addAll(candidates);
    }
    
    /**
     * Adds a List of remote candidate to this media-stream
     * 
     * @param candidates
     */
    public void addRemoteCandidates(List<Candidate> candidates)
    {
    	remoteCandidates.addAll(candidates);
    }
    
    /**
     * Adds a Candidate-pair to the check-list of this media-stream
     * 
     * @param candidatePair the CandidatePair object to be added
     */
    public void addToCheckList(CandidatePair candidatePair)
    {
    	checkList.add(candidatePair);
    }
    
    /**
     * Adds a Candidate-pair to the VALID-LIST of this media-stream
     * This is done when a connectivity check successfully completes
     * for the specified candidate-pair
     * 
     * @param candidatePair the CandidatePair object to be added
     */
    public void addToValidList(CandidatePair candidatePair)
    {
    	validList.add(candidatePair);
    }
    
    /**
     * Returns the list of Local Candidates
     * 
     * @return  the List containing the Candidate objects
     */
    public List<Candidate> getLocalCandidateList()
    {
    	return localCandidates;
    }
    
    /**
     * Returns the status of the CHECK-LIST
     * If the return value is <code>true</code>, the CHECK-LIST is frozen
     * If <code>false</code>, the CHECK-LIST is active
     * 
     * @return true if the CHECK-LIST is frozen, false otherwise
     */
    public boolean isFrozenCheckList()
    {
        return frozenCheckList;
    }
    
    /**
     * Create check list for this media stream
     */
    public void createCheckList()
    {
        Candidate localCandidate;
        Candidate remoteCandidate;
        
        int localComponentID;
        int remoteComponentID;
        
        InetAddress localAddress;
        InetAddress remoteAddress;
        
        CandidatePair candidatePair;
        
        int noOfLocalCandidates = localCandidates.size();
        int noOfRemoteCandidates = remoteCandidates.size();
        
        CandidatePair[] pairs = new CandidatePair[noOfLocalCandidates*noOfRemoteCandidates];
        int noOfPairs = 0;
        
        // creating an array of candidate pairs
        logger.log(Level.INFO, "Creating candidate pairs for [" + name + "]");
        for(int i = 0; i < noOfLocalCandidates; i++)
        {
            localCandidate = localCandidates.get(i);
            localComponentID = localCandidate.getParentComponent().getComponentID();
            localAddress = localCandidate.getTransportAddress().getSocketAddress().getAddress();
            String localCandidateType = localCandidate.getCandidateType();
            for(int j = 0; j < noOfRemoteCandidates; j++)
            {
                remoteCandidate = remoteCandidates.get(j);
                remoteComponentID = remoteCandidate.getParentComponent().getComponentID();
                remoteAddress = remoteCandidate.getTransportAddress().getSocketAddress().getAddress();
                
                // pair candidates only if they belong to the same component and are
                // of the same IP version type
                if(localComponentID == remoteComponentID)
                {
                    
                    if(((localAddress instanceof Inet4Address) && 
                            (remoteAddress instanceof Inet4Address)) || 
                       ((localAddress instanceof Inet6Address) &&
                            (remoteAddress instanceof Inet6Address)))
                    {
                        candidatePair = new CandidatePair(localCandidate, remoteCandidate);
                        candidatePair.setPriority(candidatePair.computePriority());
                        
                        logger.log(Level.INFO, "Candidate-pair created : " + 
                                candidatePair.getLocalCandidate().getTransportAddress() + " : " +
                                candidatePair.getRemoteCandidate().getTransportAddress());
                        
                        // replace the server-reflexive local address with its base
                        // after computing the pair-priority
                        if(localCandidateType == Candidate.SERVER_REFLEXIVE_CANDIDATE)
                        {
                            candidatePair.setLocalCandidate(localCandidate.getBase());
                            
                            logger.log(Level.INFO, "Changed local candidate of candidate-pair " +
                                    "[" + candidatePair.getLocalCandidate().getTransportAddress() + "/" +
                                    candidatePair.getRemoteCandidate().getTransportAddress() + "] to " +
                                    localCandidate.getBase().getTransportAddress());
                        }
                        pairs[noOfPairs++] = candidatePair;
                    }
                }
            }
        }// ~// end of creating the candidate-pair array with priorities

        // sort the candidate-pair array
        Arrays.sort(pairs, 0, noOfPairs, new Comparator<CandidatePair>() {

            public int compare(CandidatePair o1, CandidatePair o2) {
                long o1Priority = o1.getPriority();
                long o2Priority = o2.getPriority();
                if(o1Priority < o2Priority)
                {
                    return -1;
                }
                else if(o1Priority == o2Priority)
                {
                    return 0;
                }
                else
                {
                    return 1;
                }
            }
            
        });     
        
        HashMap<String, CandidatePair> checkMap = 
                                   new HashMap<String, CandidatePair>();
        
        String key;
        
        // going from high priority to low priority
        // pruning the candidate-pairs and adding candidate-pairs to CHECK-LIST
        logger.log(Level.INFO, "Creating the CHECK-LIST for media-stream : [" + name + "]");
        
        for(int k = noOfPairs - 1; k >= 0; k--)
        {
            key = pairs[k].getLocalCandidate().getTransportAddress().toString() + 
                  pairs[k].getRemoteCandidate().getTransportAddress().toString() +
                  " component=" + pairs[k].getRemoteCandidate().getParentComponent().getComponentID();
                         
            if(!checkMap.containsKey(key))
            {
                checkMap.put(key, pairs[k]);
                pairs[k].setState(CandidatePair.STATE_FROZEN);
                checkList.add(pairs[k]);
                
                logger.log(Level.INFO, "Candidate-pair : " + pairs[k].getLocalCandidate().getTransportAddress() +
                        " " + pairs[k].getRemoteCandidate().getTransportAddress() + 
                        " added to CHECK-LIST");
            }
            // else
                // simply ignore it
                // other CandidatePairs which map to the same key, are ignored since they have low
                // priority
        } 
        
        checkListState = CHECK_LIST_RUNNING;
    }
}
