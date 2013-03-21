/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.beans.*;
import java.io.*;
import java.math.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.ice.harvest.*;
import org.ice4j.stack.*;

/**
 * An <tt>Agent</tt> could be described as the main class (i.e. the chef
 * d'orchestre) of an ICE implementation.
 * <p>
 * As defined in RFC 3264, an agent is the protocol implementation involved in
 * the offer/answer exchange. There are two agents involved in an offer/answer
 * exchange.
 * </p>
 * <p>
 * <b>Note</b>: An <tt>Agent</tt> instance should be explicitly prepared for
 * garbage collection by calling {@link #free()} on it if timely freeing of the
 * associated resources is of importance; otherwise, it will wait for the
 * garbage collector to call {@link #finalize()} on it.
 * </p>
 *
 * @author Emil Ivov
 * @author Lyubomir Marinov
 * @author Sebastien Vincent
 */
public class Agent
{
    /**
     * The default maximum size for check lists.
     */
    public static final int DEFAULT_MAX_CHECK_LIST_SIZE = 100;

    /**
     * The default number of milliseconds we should wait before moving from
     * {@link IceProcessingState#COMPLETED} into {@link
     * IceProcessingState#TERMINATED}.
     */
    public static final int DEFAULT_TERMINATION_DELAY = 3000;

    /**
     * The constant which defines an empty array with element type
     * <tt>PropertyChangeListener</tt> and represents the fact that there are no
     * <tt>IceProcessingState</tt> change listeners added to an <tt>Agent</tt>
     * (using {@link #addStateChangeListener(PropertyChangeListener)}.
     */
    private static final PropertyChangeListener[] NO_STATE_CHANGE_LISTENERS
        = new PropertyChangeListener[0];

    /**
     * The <tt>Logger</tt> used by the <tt>Agent</tt> class and its instances
     * for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(Agent.class.getName());

    /**
     * The LinkedHashMap used to store the media streams
     * This map preserves the insertion order of the media streams.
     */
    private final Map<String, IceMediaStream> mediaStreams
        = new LinkedHashMap<String, IceMediaStream>();

    /**
     * The candidate harvester that we use to gather candidate on the local
     * machine.
     */
    private final HostCandidateHarvester hostCandidateHarvester
                                                = new HostCandidateHarvester();

    /**
     * The set of harvesters (i.e. STUN, TURN, and others) that the agent should
     * use when gathering candidates for components.
     */
    private final CandidateHarvesterSet harvesters
        = new CandidateHarvesterSet();

    /**
     * Manages statisics about harvesting time.
     */
    private HarvestingTimeStat harvestingTimeStat = new HarvestingTimeStat();

    /**
     * We use the <tt>FoundationsRegistry</tt> to keep track of the foundations
     * we assign within a session (i.e. the entire life time of an
     * <tt>Agent</tt>)
     */
    private final FoundationsRegistry foundationsRegistry
                                          = new FoundationsRegistry();

    /**
     * Our internal nominator implementing several nomination strategies.
     */
    private final DefaultNominator nominator;

    /**
     * ICE compatibility mode for this agent.
     */
    private CompatibilityMode compatibilityMode = CompatibilityMode.RFC5245;

    /**
     * The name of the {@link PropertyChangeEvent} that we use to deliver
     * events on changes in the state of ICE processing in this agent.
     */
    public static final String PROPERTY_ICE_PROCESSING_STATE
                                            = "IceProcessingState";

    /**
     * the value of <tt>Ta</tt> as specified by the application or <tt>-1</tt>
     * if non was specified and we should calculate one ourselves.
     */
    private long taValue = -1;

    /**
     * The <tt>List</tt> of remote addresses that we have discovered through
     * incoming connectivity checks, before actually receiving a session
     * description from the peer and that may potentially contain peer reflexive
     * addresses. This list is stored and only if and while connectivity checks
     * are not running. Once they start, we are able to determine whether the
     * addresses in here are actually peer-reflexive or not, and schedule
     * the necessary triggered checks.
     */
    private final List<CandidatePair> preDiscoveredPairsQueue
        = new LinkedList<CandidatePair>();

    /**
     * The lock that we use while starting connectivity establishment.
     */
    private final Object startLock = new Object();

    /**
     * The user fragment that we should use for the ice-ufrag attribute.
     */
    private final String ufrag;

    /**
     * The password that we should use for the ice-pwd attribute.
     */
    private final String password;

    /**
     * The tie-breaker number is used in connectivity checks to detect and
     * repair the case where both agents believe to have the controlling or the
     * controlled role.
     */
    private final long tieBreaker;

    /**
     * Determines whether this is the controlling agent in a an ICE interaction.
     */
    private boolean isControlling = true;

    /**
     * The entity that will be taking care of outgoing connectivity checks.
     */
    private final ConnectivityCheckClient connCheckClient;

    /**
     * The entity that will be taking care of incoming connectivity checks.
     */
    private final ConnectivityCheckServer connCheckServer;

    /**
     * Indicates the state of ICE processing in this <tt>Agent</tt>. An
     * <tt>Agent</tt> is in the Waiting state until it has both sent and
     * received candidate lists and started connectivity establishment. The
     * difference between the Waiting and the Running states is important in
     * cases like determining whether a remote address we've just discovered is
     * peer reflexive or not. If iceStarted is true and we don't know about the
     * address then we should add it to the list of candidates. Otherwise
     * we should wait for the remote party to send their media description
     * before being able to determine.
     */
    private IceProcessingState state = IceProcessingState.WAITING;

    /**
     * Contains {@link PropertyChangeListener}s registered with this {@link
     * Agent} and following its changes of state.
     */
    private final List<PropertyChangeListener> stateListeners
        = new LinkedList<PropertyChangeListener>();

    /**
     * The <tt>StunStack</tt> used by this <tt>Agent</tt>.
     */
    private StunStack stunStack;

    /**
     * The thread that we use for moving from COMPLETED into a TERMINATED state.
     */
    private TerminationThread terminationThread;

    /**
     * The thread that we use for STUN keep-alive.
     */
    private StunKeepAliveThread stunKeepAliveThread;

    /**
     * Some protocols, such as XMPP, need to be able to distinguish the separate
     * ICE sessions that occur as a result of ICE restarts, which is why we need
     * to keep track of generations. A generation is an index, starting at 0,
     * that enables the parties to keep track of updates to the candidate
     * throughout the life of the session.
     */
    private int generation = 0;

    /**
     * Indicates that ICE will be shutdown.
     */
    private boolean shutdown = false;

    /**
     * Creates an empty <tt>Agent</tt> with no streams, and no address.
     */
    public Agent()
    {
        this(CompatibilityMode.RFC5245);
    }

    /**
     * Creates an empty <tt>Agent</tt> with no streams, and no address.
     *
     * @param compatibilityMode ICE compatibility mode
     */
    public Agent(CompatibilityMode compatibilityMode)
    {
        SecureRandom random = new SecureRandom();

        this.compatibilityMode = compatibilityMode;

        connCheckServer = new ConnectivityCheckServer(this);
        connCheckClient = new ConnectivityCheckClient(this);

        //add the FINGERPRINT attribute to all messages.
        System.setProperty(StackProperties.ALWAYS_SIGN, "true");

        //add the software attribute to all messages
        if (StackProperties.getString(StackProperties.SOFTWARE) == null)
            System.setProperty(StackProperties.SOFTWARE, "ice4j.org");

        if(compatibilityMode == CompatibilityMode.GTALK)
        {
            /* username is 16 byte in Google Talk dialect but it is set
             * for each candidate and not globally
             */
            ufrag = null;

            /* no password in Google Talk dialect (at least libnice does not use
             * one)
             */
            password = "";
        }
        else
        {
            ufrag = new BigInteger(24, random).toString(32);
            password = new BigInteger(128, random).toString(32);
        }

        tieBreaker = Math.abs(random.nextLong());
        nominator = new DefaultNominator(this);
    }

    /**
     * Creates a new media stream and stores it.
     *
     * @param mediaStreamName the name of the media stream
     *
     * @return the newly created and stored <tt>IceMediaStream</tt>
     */
    public IceMediaStream createMediaStream(String mediaStreamName)
    {
        logger.info("Create media stream for " + mediaStreamName);
        IceMediaStream mediaStream
            = new IceMediaStream(Agent.this, mediaStreamName);

        mediaStreams.put(mediaStreamName, mediaStream);

        // Since we add a new stream, we must wait to add the component and the
        // remote candidates before starting to "RUN" this Agent.
        // This is usefull if this Agent is already in COMPLETED state
        // (isStarted() == true) due to a previous successful ICE preocedure:
        // this way incoming connectivity checks are registered in the
        // preDiscoveredPairsQueue until this Agent is in RUNNING state.
        this.setState(IceProcessingState.WAITING);

        return mediaStream;
    }

    /**
     * Creates a new {@link Component} for the specified <tt>stream</tt> and
     * allocates all local candidates that should belong to it.
     *
     * @param stream the {@link IceMediaStream} that the new {@link Component}
     * should belong to.
     * @param transport the transport protocol used by the component
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwinG an exception.
     *
     * @return the newly created {@link Component} and with a list containing
     * all and only local candidates.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort >
     * maxPort</tt>, or if <tt>transport</tt> is not currently supported.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is using sockets.
     * @throws BindException if we couldn't find a free port between
     * <tt>minPort</tt> and <tt>maxPort</tt> before reaching the maximum allowed
     * number of retries.
     */
    public Component createComponent(  IceMediaStream stream,
                                       Transport      transport,
                                       int            preferredPort,
                                       int            minPort,
                                       int            maxPort)
        throws IllegalArgumentException,
               IOException,
               BindException
    {
        if(transport != Transport.UDP)
        {
            throw new IllegalArgumentException(
                    "This implementation does not currently support transport: "
                        + transport);
        }

        Component component = stream.createComponent(transport);

        logger.info("Create component " + component.toShortString());

        gatherCandidates(component, preferredPort, minPort, maxPort);

        for(Candidate<?> candidate : component.getLocalCandidates())
        {
            logger.info("\t" + candidate.getTransportAddress() + " (" +
                    candidate.getType() + ")");

            if(compatibilityMode == CompatibilityMode.GTALK)
            {
                /* assign a local ufrag of 16 bytes for each candidate */
                LocalCandidate localCand = (LocalCandidate)candidate;

                /* Google relayed candidate should have already set their
                 * ufrag since it must be the same as username present in
                 * HTTP response
                 */
                if(localCand.getUfrag() != null)
                {
                    continue;
                }

                localCand.setUfrag(generateGTalkUfrag());
            }
        }

        /*
         * Lyubomir: After we've gathered the LocalCandidate for a Component and
         * before we've make them available to the caller, we have to make sure
         * that the ConnectivityCheckServer is started. If there's been a
         * previous connectivity establishment which has completed, it has
         * stopped the ConnectivityCheckServer. If the ConnectivtyCheckServer is
         * not started after we've made the gathered LocalCandidates available
         * to the caller, the caller may send them and a connectivity check may
         * arrive from the remote Agent.
         */
        connCheckServer.start();

        return component;
    }

    /**
     * Generates Ufrag for GTalk mode.
     *
     * @return 16 bytes Ufrag
     */
    public String generateGTalkUfrag()
    {
        SecureRandom random = new SecureRandom();
        String s = null;

        while(s == null || s.length() != 16)
        {
            s = new BigInteger(80, random).toString(32);
        }
        return s;
    }

    /**
     * Uses all <tt>CandidateHarvester</tt>s currently registered with this
     * <tt>Agent</tt> to obtain whatever addresses they can discover.
     * <p>
     * Not that the method would only use existing harvesters so make sure
     * you've registered all harvesters that you would want to use before
     * calling it.
     * </p>
     * @param component the <tt>Component</tt> that we'd like to gather
     * candidates for.
     * @param preferredPort the port number that should be tried first when
     * binding local <tt>Candidate</tt> sockets for this <tt>Component</tt>.
     * @param minPort the port number where we should first try to bind before
     * moving to the next one (i.e. <tt>minPort + 1</tt>)
     * @param maxPort the maximum port number where we should try binding
     * before giving up and throwing an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort &gt;
     * maxPort</tt>.
     * @throws IOException if an error occurs while the underlying resolver lib
     * is gathering candidates and we end up without even a single one.
     */
    private void gatherCandidates( Component      component,
                                   int            preferredPort,
                                   int            minPort,
                                   int            maxPort)
        throws IllegalArgumentException,
               IOException
    {
        logger.info("Gather candidates for component " +
                component.toShortString());

        this.startHarvesting();

        hostCandidateHarvester.harvest(
                component,
                preferredPort, minPort, maxPort, Transport.UDP);

        if(compatibilityMode == CompatibilityMode.GTALK)
        {
            hostCandidateHarvester.harvest(
                component,
                preferredPort, minPort, maxPort, Transport.TCP);
        }

        logger.fine("host candidate count: " +
            component.getLocalCandidateCount());

        //apply other harvesters here
        harvesters.harvest(component);

        this.stopHarvesting();
        logger.info(
                "End candidate harvest for all harvesters within "
                + this.getTotalHarvestingTime() + " ms"
                + ", component: " + component.getComponentID());

        logger.fine("host+harvested candidate count: " +
            component.getLocalCandidateCount());

        computeFoundations(component);

        //make sure we compute priorities only after we have all candidates
        component.prioritizeCandidates();

        //eliminate redundant candidates
        component.eliminateRedundantCandidates();

        logger.fine("host+harvested candidate count (after elimination): " +
            component.getLocalCandidateCount());

        //select the candidate to put in the media line.
        component.selectDefaultCandidate();
    }

    /**
     * Initializes all stream check lists and begins the checks.
     */
    public void startConnectivityEstablishment()
    {
        synchronized(startLock)
        {
            logger.info("Start ICE connectivity establishment");
            shutdown = false;
            pruneNonMatchedStreams();

            try
            {
                initCheckLists();
            }
            catch(ArithmeticException e)
            {
                setState(IceProcessingState.FAILED);
                return;
            }

            //change state before we actually send checks so that we don't
            //miss responses and hence the possibility to nominate a pair.
            setState(IceProcessingState.RUNNING);

            //if we have received connectivity checks before RUNNING state,
            //trigger a check for those candidate pairs.
            if(this.preDiscoveredPairsQueue.size() > 0)
            {
                logger.info("Trigger checks for pairs that were received " +
                        "before running state");
                Iterator<CandidatePair> it = preDiscoveredPairsQueue.iterator();

                while(it.hasNext())
                {
                    triggerCheck(it.next());
                }

                this.preDiscoveredPairsQueue.clear();
            }

            connCheckClient.startChecks();
        }
    }

    /**
     * <tt>Free()</tt>s and removes from this agent components or entire streams
     * if they do not contain remote candidates. A possible reason for this
     * could be the fact that the remote party canceled some of the streams.
     */
    private void pruneNonMatchedStreams()
    {
        for (IceMediaStream stream : getStreams())
        {
            for(Component cmp : stream.getComponents())
            {
                if(cmp.getRemoteCandidateCount() == 0)
                    stream.removeComponent(cmp);
            }

            if(stream.getComponentCount() == 0)
                removeStream(stream);
        }
    }

    /**
     * Indicates whether this {@link Agent} is currently in the process of
     * running connectivity checks and establishing connectivity. Connectivity
     * establishment is considered to have started after both {@link Agent}s
     * have exchanged their media descriptions. Determining whether the actual
     * process has started is important, for example, when determining whether
     * a remote address we've just discovered is peer reflexive or not.
     * If ICE has started and we don't know about the address then we should
     * add it to the list of candidates. Otherwise we should hold to it until
     * it does and check later.
     * <p>
     * Note that an {@link Agent} would be ready to and will send responses to
     * connectivity checks as soon as it streams get created, which is well
     * before we actually start the checks.
     *
     * @return <tt>true</tt> after media descriptions have been exchanged both
     * ways and connectivity checks have started (regardless of their current
     * state) and <tt>false</tt> otherwise.
     */
    public boolean isStarted()
    {
        return state != IceProcessingState.WAITING
            && state != IceProcessingState.COMPLETED
            && state != IceProcessingState.TERMINATED;
    }

    /**
     * Indicates whether this {@link Agent} has finished ICE processing.
     *
     * @return <tt>true</tt> if ICE processing is in the {@link
     * IceProcessingState#FAILED}, {@link IceProcessingState#COMPLETED} or
     * {@link IceProcessingState#TERMINATED} and <tt>false</tt> otherwise.
     */
    public boolean isOver()
    {
        return state == IceProcessingState.COMPLETED
            || state == IceProcessingState.TERMINATED
            || state == IceProcessingState.FAILED;
    }

    /**
     * Returns the state of ICE processing for this <tt>Agent</tt>.
     *
     * @return the state of ICE processing for this <tt>Agent</tt>.
     */
    public IceProcessingState getState()
    {
        return state;
    }

    /**
     * Adds <tt>l</tt> to the list of listeners tracking changes of the
     * {@link IceProcessingState} of this <tt>Agent</tt>
     *
     * @param l the listener to register.
     */
    public void addStateChangeListener(PropertyChangeListener l)
    {
        synchronized(stateListeners)
        {
            if(!stateListeners.contains(l))
                this.stateListeners.add(l);
        }
    }

    /**
     * Removes <tt>l</tt> from the list of listeners tracking changes of the
     * {@link IceProcessingState} of this <tt>Agent</tt>
     *
     * @param l the listener to remove.
     */
    public void removeStateChangeListener(PropertyChangeListener l)
    {
        synchronized(stateListeners)
        {
            this.stateListeners.remove(l);
        }
    }

    /**
     * Creates a new {@link PropertyChangeEvent} and delivers it to all
     * currently registered state listeners.
     *
     * @param oldState the {@link IceProcessingState} we had before the change
     * @param newState the {@link IceProcessingState} we had after the change
     */
    private void fireStateChange(IceProcessingState oldState,
                                 IceProcessingState newState)
    {
        PropertyChangeListener[] stateListenersCopy;

        synchronized(stateListeners)
        {
            stateListenersCopy
                = stateListeners.toArray(NO_STATE_CHANGE_LISTENERS);
        }

        if (stateListenersCopy.length != 0)
        {
            PropertyChangeEvent evt
                = new PropertyChangeEvent(
                        this,
                        PROPERTY_ICE_PROCESSING_STATE,
                        oldState, newState);

            for(PropertyChangeListener l : stateListenersCopy)
                l.propertyChange(evt);
        }
    }

    /**
     * Sets the {@link IceProcessingState} of this <tt>Agent</tt> to
     * <tt>newState</tt> and triggers the corresponding change event.
     *
     * @param newState the new state of ICE processing for this <tt>Agent</tt>.
     */
    private void setState(IceProcessingState newState)
    {
        IceProcessingState oldState = state;

        this.state = newState;
        fireStateChange(oldState, newState);
    }

    /**
     * Creates, initializes and orders the list of candidate pairs that would
     * be used for the connectivity checks for all components in this stream.
     */
    protected void initCheckLists()
    {
        //first init the check list.
        List<IceMediaStream> streams
            = getStreamsWithPendingConnectivityEstablishment();

        //init the maximum number of check list entries per stream.
        int maxCheckListSize = Integer.getInteger(
               StackProperties.MAX_CHECK_LIST_SIZE,
               DEFAULT_MAX_CHECK_LIST_SIZE);

        int maxPerStreamSize = maxCheckListSize / streams.size();

        for(IceMediaStream stream : streams)
        {
            logger.info("Init checklist for stream " + stream.getName());
            stream.setMaxCheckListSize(maxPerStreamSize);
            stream.initCheckList();
        }

        //init the states of the first media stream as per 5245
        streams.get(0).getCheckList().computeInitialCheckListPairStates();
    }

    /**
     * Computes and sets the foundations foundation for all <tt>Candidate</tt>s
     * currently found in <tt>component</tt>.
     *
     * @param component the component whose candidate foundations we'd like to
     * compute and assign.
     */
    private void computeFoundations(Component component)
    {
        List<LocalCandidate> candidates = component.getLocalCandidates();

        for (Candidate<?> cand : candidates)
            foundationsRegistry.assignFoundation(cand);
    }

    /**
     * Adds <tt>harvester</tt> to the list of harvesters that this agent will
     * use when gathering <tt>Candidate</tt>s.
     *
     * @param harvester a <tt>CandidateHarvester</tt> that this agent should use
     * when gathering candidates.
     */
    public void addCandidateHarvester(CandidateHarvester harvester)
    {
        harvesters.add(harvester);
    }

    /**
     * Returns that user name that should be advertised in session descriptions
     * containing ICE data from this agent.
     *
     * @return that user name that should be advertised in session descriptions
     * containing ICE data from this agent.
     */
    public String getLocalUfrag()
    {
        return ufrag;
    }

    /**
     * Returns that password that should be advertised in session descriptions
     * containing ICE data from this agent.
     *
     * @return that password that should be advertised in session descriptions
     * containing ICE data from this agent.
     */
    public String getLocalPassword()
    {
        return password;
    }

    /**
     * Returns the user name that this <tt>Agent</tt> should use in connectivity
     * checks for outgoing Binding Requests. According to RFC 5245, a Binding
     * Request serving as a connectivity check MUST utilize the STUN short term
     * credential mechanism. The username for the credential is formed by
     * concatenating the username fragment provided by the peer with the
     * username fragment of the agent sending the request, separated by a
     * colon (":").  The password is equal to the password provided by the peer.
     * For example, consider the case where agent L is the offerer, and agent R
     * is the answerer.  Agent L included a username fragment of LFRAG for its
     * candidates, and a password of LPASS.  Agent R provided a username
     * fragment of RFRAG and a password of RPASS.  A connectivity check from L
     * to R (and its response of course) utilize the username RFRAG:LFRAG and a
     * password of RPASS.  A connectivity check from R to L (and its response)
     * utilize the username LFRAG:RFRAG and a password of LPASS.
     *
     * @param media media name that we want to generate local username for.
     * @return a user name that this <tt>Agent</tt> can use in connectivity
     * check for outgoing Binding Requests.
     */
    public String generateLocalUserName(String media)
    {
        IceMediaStream stream = getStream(media);
        String ret = null;

        if(stream == null || stream.getRemoteUfrag() == null)
        {
            return null;
        }

        ret = stream.getRemoteUfrag() + ":" + getLocalUfrag();
        return ret;
    }

    /**
     * Returns the user name that we should expect a peer <tt>Agent</tt> to use
     * in connectivity checks for Binding Requests its sending our way.
     * According to RFC 5245, a Binding Request serving as a connectivity check
     * MUST utilize the STUN short term credential mechanism. The username for
     * the credential is formed by concatenating the username fragment provided
     * by the peer with the username fragment of the agent sending the request,
     * separated by a colon (":").  The password is equal to the password
     * provided by the peer. For example, consider the case where agent
     * L is the offerer, and agent R is the answerer.  Agent L
     * included a username fragment of LFRAG for its candidates,
     * and a password of LPASS.  Agent R provided a username fragment
     * of RFRAG and a password of RPASS.  A connectivity check from L
     * to R (and its response of course) utilize the username RFRAG:LFRAG and a
     * password of RPASS.  A connectivity check from R to L (and its response)
     * utilize the username LFRAG:RFRAG and a password of LPASS.
     *
     * @param media media name that we want to generate local username for.
     * @return a user name that a peer <tt>Agent</tt> would use in connectivity
     * check for outgoing Binding Requests.
     */
    public String generateRemoteUserName(String media)
    {
        IceMediaStream stream = getStream(media);
        String ret = null;

        if(stream == null)
        {
            return null;
        }

        if(compatibilityMode == CompatibilityMode.RFC5245)
        {
            ret = getLocalUfrag() + ":" + stream.getRemoteUfrag();
        }
        else if(compatibilityMode == CompatibilityMode.GTALK)
        {
            ret = getLocalUfrag() + stream.getRemoteUfrag();
        }

        return ret;
    }

    /**
     * Returns the user name that this <tt>Agent</tt> should use in connectivity
     * checks for outgoing Binding Requests in a Google Talk session.
     *
     * @param remoteCandidate remote candidate
     * @param localCandidate local candidate
     * @return a user name that this <tt>Agent</tt> can use in connectivity
     * check for outgoing Binding Requests.
     */
    public String generateLocalUserName(RemoteCandidate remoteCandidate,
            LocalCandidate localCandidate)
    {
        return generateUserName(remoteCandidate, localCandidate);
    }

    /**
     * Returns the user name that we should expect a peer <tt>Agent</tt> to use
     * in connectivity checks for Binding Requests its sending our way in a
     * Google Talk session.
     *
     * @param remoteCandidate remote candidate
     * @param localCandidate local candidate
     * @return a user name that a peer <tt>Agent</tt> would use in connectivity
     * check for outgoing Binding Requests.
     */
    public String generateRemoteUserName(RemoteCandidate remoteCandidate,
            LocalCandidate localCandidate)
    {
        return generateUserName(localCandidate, remoteCandidate);
    }

    /**
     * Returns the user name that we should expect a peer <tt>Agent</tt> to use
     * in connectivity checks for Binding Requests its sending our way in a
     * Google Talk session.
     *
     * @param candidate1 The first candidate of a candidatePair.
     * @param candidate2 The second candidate of a candidatePair.
     * @return a user name that a peer <tt>Agent</tt> would use in connectivity
     * check for outgoing Binding Requests.
     */
    private String generateUserName(
            Candidate<?> candidate1,
            Candidate<?> candidate2)
    {
        String ret = null;
        String ufrag1 = candidate1.getUfrag();
        String ufrag2 = candidate2.getUfrag();

        /* Google Talk specific
         * each candidate has its own username/password
         */
        if(ufrag1 != null
                && ufrag2 != null
                && compatibilityMode == CompatibilityMode.GTALK)
        {
            ret = ufrag1 + ufrag2;
        }

        return ret;
    }

    /**
     * Returns the <tt>IceMediaStream</tt> with the specified <tt>name</tt> or
     * <tt>null</tt> if no such stream has been registered with this
     * <tt>Agent</tt> yet.
     *
     * @param name the name of the stream that we'd like to obtain a reference
     * to.
     *
     * @return the <tt>IceMediaStream</tt> with the specified <tt>name</tt> or
     * <tt>null</tt> if no such stream has been registered with this
     * <tt>Agent</tt> yet.
     */
    public IceMediaStream getStream(String name)
    {
        synchronized(mediaStreams)
        {
            return mediaStreams.get(name);
        }
    }

    /**
     * Returns a <tt>List</tt> containing the names of all currently registered
     * media streams.
     *
     * @return a <tt>List</tt> containing the names of all currently registered
     * media streams.
     */
    public List<String> getStreamNames()
    {
        synchronized(mediaStreams)
        {
            return new LinkedList<String>(mediaStreams.keySet());
        }
    }

    /**
     * Returns a <tt>List</tt> containing all <tt>IceMediaStream</tt>s currently
     * registered with this agent.
     *
     * @return a <tt>List</tt> containing all <tt>IceMediaStream</tt>s currently
     * registered with this agent.
     */
    public List<IceMediaStream> getStreams()
    {
        synchronized(mediaStreams)
        {
            return new LinkedList<IceMediaStream>(mediaStreams.values());
        }
    }

    /**
     * Returns the number of <tt>IceMediaStream</tt>s currently registered with
     * this agent.
     *
     * @return  the number of <tt>IceMediaStream</tt>s currently registered with
     * this agent.
     *
     */
    public int getStreamCount()
    {
        synchronized(mediaStreams)
        {
            return mediaStreams.size();
        }
    }

    /**
     * Gets the <tt>IceMediaStream</tt>s registered with this <tt>Agent</tt> for
     * which connectivity establishment is pending. For example, after a set of
     * <tt>IceMediaStream</tt>s is registered with this <tt>Agent</tt>,
     * connectivity establishment completes for them and then a new set of
     * <tt>IceMediaStream</tt>s is registered with this <tt>Agent</tt>, the
     * <tt>IceMediaStream</tt>s with pending connectivity establishment are
     * those from the second set.
     *
     * @return a <tt>List</tt> of the <tt>IceMediaStream</tt>s registered with
     * this <tt>Agent</tt> for which connectivity is pending.
     */
    List<IceMediaStream> getStreamsWithPendingConnectivityEstablishment()
    {
        /*
         * Lyubomir: We want to support establishing connectivity for streams
         * which have been created after connectivity has been established for
         * previously created streams. That is why we will remove the streams
         * which have their connectivity checks completed or failed i.e. these
         * streams have been handled by a previous connectivity establishment.
         */
        List<IceMediaStream> streams = getStreams();
        Iterator<IceMediaStream> streamIter = streams.iterator();

        while (streamIter.hasNext())
        {
            IceMediaStream stream = streamIter.next();
            CheckList checkList = stream.getCheckList();
            CheckListState checkListState = checkList.getState();

            if (CheckListState.COMPLETED.equals(checkListState)
                    || CheckListState.FAILED.equals(checkListState))
                streamIter.remove();
        }
        return streams;
    }

    /**
     * Gets the <tt>StunStack</tt> used by this <tt>Agent</tt>.
     *
     * @return the <tt>StunStack</tt> used by this <tt>Agent</tt>
     */
    public synchronized StunStack getStunStack()
    {
        if (stunStack == null)
            stunStack = new StunStack(compatibilityMode);
        return stunStack;
    }

    /**
     * Returns the number of {@link CheckList}s that are currently active.
     *
     * @return the number of {@link CheckList}s that are currently active.
     *
     */
    protected int getActiveCheckListCount()
    {
        synchronized(mediaStreams)
        {
            int i=0;
            Collection<IceMediaStream> streams = mediaStreams.values();

            for (IceMediaStream stream : streams)
            {
                if (stream.getCheckList().isActive())
                    i++;
            }

            return i;
        }
    }

    /**
     * Returns a <tt>String</tt> representation of this agent.
     *
     * @return a <tt>String</tt> representation of this agent.
     */
    @Override
    public String toString()
    {
        StringBuilder buff = new StringBuilder("ICE Agent (stream-count=");

        buff.append(getStreamCount()).append(" ice-pwd:")
            .append(getLocalPassword());
        buff.append(getStreamCount()).append(" ice-ufrag:")
            .append(getLocalUfrag());
        buff.append(getStreamCount()).append(" tie-breaker:")
            .append(getTieBreaker());
        buff.append("):\n");

        for(IceMediaStream stream : getStreams())
            buff.append(stream.toString()).append("\n");

        return buff.toString();
    }

    /**
     * Returns this agent's tie-breaker number. The tie-breaker number is used
     * in connectivity checks to detect and repair the case where both agents
     * believe to have the controlling or the controlled role.
     *
     * @return  this agent's tie-breaker number
     */
    public long getTieBreaker()
    {
        return tieBreaker;
    }

    /**
     * Specifies whether this agent has the controlling role in an ICE exchange.
     *
     * @param isControlling <tt>true</tt> if this is to be the controlling
     * <tt>Agent</tt> and <tt>false</tt> otherwise.
     */
    public void setControlling(boolean isControlling)
    {
        this.isControlling = isControlling;

        //in case we have already initialized our check lists we'd need to
        //recompute pair priorities.
        List<IceMediaStream> streams = getStreams();
        for(IceMediaStream stream : streams)
        {
            CheckList list = stream.getCheckList();

            if (list != null)
                list.recomputePairPriorities();
        }
    }

    /**
     * Removes <tt>stream</tt> and all its child <tt>Component</tt>s and
     * <tt>Candidate</tt>s from the this agent and releases all resources that
     * they had allocated (like sockets for example)
     *
     * @param stream the <tt>Component</tt> we'd like to remove and free.
     */
    public void removeStream(IceMediaStream stream)
    {
        synchronized (mediaStreams)
        {
            mediaStreams.remove(stream.getName());
            stream.free();
        }
    }

    /**
     * Determines whether this agent has the controlling role in an ICE
     * exchange.
     *
     * @return <tt>true</tt> if this is to be the controlling <tt>Agent</tt>
     * and <tt>false</tt> otherwise.
     */
    public boolean isControlling()
    {
        return isControlling;
    }

    /**
     * Returns the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@link Agent}'s
     * streams or <tt>null</tt> if it doesn't.
     *
     * @param localAddress the {@link TransportAddress} we are looking for.
     *
     * @return the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@link Agent}'s
     * streams or <tt>null</tt> if it doesn't.
     */
    public LocalCandidate findLocalCandidate(TransportAddress localAddress)
    {
        Collection<IceMediaStream> streamsCollection = mediaStreams.values();

        for( IceMediaStream stream : streamsCollection)
        {
            LocalCandidate cnd = stream.findLocalCandidate(localAddress);

            if(cnd != null)
                return cnd;
        }

        return null;
    }

    /**
     * Returns the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@link Agent}'s
     * streams or <tt>null</tt> if it doesn't.
     *
     * @param localAddress the {@link TransportAddress} we are looking for.
     * @param ufrag local ufrag
     * @return the local <tt>LocalCandidate</tt> with the specified
     * <tt>localAddress</tt> if it belongs to any of this {@link Agent}'s
     * streams or <tt>null</tt> if it doesn't.
     */
    public LocalCandidate findLocalCandidate(TransportAddress localAddress,
        String ufrag)
    {
        Collection<IceMediaStream> streamsCollection = mediaStreams.values();

        for(IceMediaStream stream : streamsCollection)
        {
            for(Component c : stream.getComponents())
            {
                for(LocalCandidate cnd : c.getLocalCandidates())
                {
                    if(cnd != null && cnd.getUfrag() != null &&
                        cnd.getUfrag().equals(ufrag))
                        return cnd;
                }
            }
        }

        return null;
    }

    /**
     * Returns the remote <tt>Candidate</tt> with the specified
     * <tt>remoteAddress</tt> if it belongs to any of this {@link Agent}'s
     * streams or <tt>null</tt> if it doesn't.
     *
     * @param remoteAddress the {@link TransportAddress} we are looking for.
     *
     * @return the remote <tt>Candidate</tt> with the specified
     * <tt>remoteAddress</tt> if it belongs to any of this {@link Agent}'s
     * streams or <tt>null</tt> if it doesn't.
     */
    public RemoteCandidate findRemoteCandidate(TransportAddress remoteAddress)
    {
        Collection<IceMediaStream> streamsCollection = mediaStreams.values();

        for( IceMediaStream stream : streamsCollection)
        {
            RemoteCandidate cnd = stream.findRemoteCandidate(remoteAddress);

            if(cnd != null)
                return cnd;
        }

        return null;
    }

    /**
     * Returns the {@link CandidatePair} with the specified remote and local
     * addresses or <tt>null</tt> if neither of the {@link CheckList}s in this
     * {@link Agent}'s streams contain such a pair.
     *
     * @param localAddress the local {@link TransportAddress} of the pair we
     * are looking for.
     * @param remoteAddress the remote {@link TransportAddress} of the pair we
     * are looking for.
     *
     * @return the {@link CandidatePair} with the specified remote and local
     * addresses or <tt>null</tt> if neither of the {@link CheckList}s in this
     * {@link Agent}'s streams contain such a pair.
     */
    public CandidatePair findCandidatePair(TransportAddress localAddress,
                                           TransportAddress remoteAddress)
    {
        synchronized(mediaStreams)
        {
            Collection<IceMediaStream> streamsCollection
                = mediaStreams.values();

            for (IceMediaStream stream : streamsCollection)
            {
                CandidatePair pair
                    = stream.findCandidatePair(localAddress, remoteAddress);

                if( pair != null )
                    return pair;
            }
        }

        return null;
    }

    /**
     * Returns the {@link CandidatePair} with the specified remote and local
     * addresses or <tt>null</tt> if neither of the {@link CheckList}s in this
     * {@link Agent}'s streams contain such a pair.
     *
     * @param localUFrag local user fragment
     * @param remoteUFrag remote user fragment
     * @return the {@link CandidatePair} with the specified remote and local
     * addresses or <tt>null</tt> if neither of the {@link CheckList}s in this
     * {@link Agent}'s streams contain such a pair.
     */
    public CandidatePair findCandidatePair(String localUFrag,
                                           String remoteUFrag)
    {
        synchronized(mediaStreams)
        {
            Collection<IceMediaStream> streamsCollection
                = mediaStreams.values();

            for (IceMediaStream stream : streamsCollection)
            {
                CandidatePair pair
                    = stream.findCandidatePair(localUFrag, remoteUFrag);

                if( pair != null )
                    return pair;
            }
        }

        return null;
    }

    /**
     * Notifies the implementation that the {@link ConnectivityCheckServer} has
     * just received a message on <tt>localAddress</tt> originating at
     * <tt>remoteAddress</tt> carrying the specified <tt>priority</tt>. This
     * will cause us to schedule a triggered check for the corresponding
     * remote candidate and potentially to the discovery of a PEER-REFLEXIVE
     * candidate.
     *
     * @param remoteAddress the address that we've just seen, and that is
     * potentially a peer-reflexive address.
     * @param localAddress the address that we were contacted on.
     * @param priority the priority that the remote party assigned to
     * @param remoteUFrag the user fragment that we should be using when and if
     * we decide to send a check to <tt>remoteAddress</tt>.
     * @param localUFrag local user fragment
     * @param useCandidate indicates whether the incoming check
     * {@link org.ice4j.message.Request} contained the USE-CANDIDATE ICE
     * attribute.
     */
    protected void incomingCheckReceived(
                                         TransportAddress remoteAddress,
                                         TransportAddress localAddress,
                                         long             priority,
                                         String           remoteUFrag,
                                         String           localUFrag,
                                         boolean          useCandidate)
    {
        if (isOver())
        {
            //means we already completed ICE and are happily running media
            //the only reason we are called is most probably because the remote
            //party is still sending Binding Requests our way and making sure we
            //are still alive.
            return;
        }

        String ufrag = null;
        LocalCandidate localCandidate = null;

        if(compatibilityMode == CompatibilityMode.GTALK
                && localAddress.getTransport() != Transport.TCP)
        {
            localCandidate = findLocalCandidate(localAddress, remoteUFrag);
        }
        else
        {
            localCandidate = findLocalCandidate(localAddress);
        }

        if(localCandidate == null)
        {
            logger.info("No localAddress for this incoming checks: " +
                    localAddress);
            return;
        }

        Component parentComponent = localCandidate.getParentComponent();
        RemoteCandidate remoteCandidate = null;

        // we need to find the username for the couple
        if(compatibilityMode == CompatibilityMode.GTALK)
        {
            CandidatePair pair = findCandidatePair(localUFrag, remoteUFrag);
            if(pair == null)
            {
                logger.info("No GTalk CandidatePair that match Lufrag/Rufrag" +
                    " " + localUFrag + " " + remoteUFrag);
                return;
            }

            CandidatePair pair2 = findCandidatePair(
                localCandidate.getTransportAddress(),
                remoteAddress);
            if(pair2 == null)
            {
                useCandidate = false;
            }
            else
            {
                useCandidate = pair2.useCandidateReceived();
            }

            ufrag = pair.getRemoteCandidate().getUfrag();
        }
        remoteCandidate = new RemoteCandidate(
                remoteAddress,
                parentComponent,
                CandidateType.PEER_REFLEXIVE_CANDIDATE,
                foundationsRegistry.obtainFoundationForPeerReflexiveCandidate(),
                priority,
                // We can not know the related candidate of a remote peer
                // reflexive candidate. We must set it to "null".
                null,
                ufrag);

        CandidatePair triggeredPair
            = new CandidatePair(localCandidate, remoteCandidate);

        logger.fine("set use-candidate " + useCandidate + " for pair " +
            triggeredPair.toShortString());
        if(useCandidate)
        {
            triggeredPair.setUseCandidateReceived();
        }

        synchronized(startLock)
        {
            if(isStarted())
            {
                //we are started, which means we have the remote candidates
                //so it's now safe to go and see whether this is a new PR cand.
                if(triggeredPair.getParentComponent().getSelectedPair() == null)
                {
                    logger.info("Receive check from " +
                        triggeredPair.toShortString() + "triggered a check");
                }
                triggerCheck(triggeredPair);
            }
            else
            {
                logger.fine("Receive STUN checks before our ICE has started");
                //we are not started yet so we'd better wait until we get the
                //remote candidates in case we are holding to a new PR one.
                this.preDiscoveredPairsQueue.add(triggeredPair);
            }
        }
    }

    /**
     * Either queues a triggered check for <tt>triggeredPair</tt> or, in case
     * there's already a pair with the specified remote and local addresses,
     * puts it in the queue instead.
     *
     * @param triggerPair the pair containing the local and remote candidate
     * that we'd need to trigger a check for.
     */
    private void triggerCheck(CandidatePair triggerPair)
    {
        //first check whether we already know about the remote address in case
        //we've just discovered a peer-reflexive candidate.
        CandidatePair knownPair = null;

        knownPair = this.findCandidatePair(
                triggerPair.getLocalCandidate().getTransportAddress(),
                triggerPair.getRemoteCandidate().getTransportAddress());

        IceMediaStream parentStream = triggerPair.getLocalCandidate()
            .getParentComponent().getParentStream();

        if (knownPair != null)
        {
            boolean useCand = false;

            useCand = triggerPair.useCandidateReceived();

            //if the incoming request contained a USE-CANDIDATE attribute then
            //make sure we don't lose this piece of info.
            if (triggerPair.useCandidateReceived())
                knownPair.setUseCandidateReceived();

            triggerPair = knownPair;

            //we already know about the remote address so we only need to
            //trigger a check for the existing pair

            if(compatibilityMode != CompatibilityMode.RFC5245 &&
                !isControlling())
            {
                logger.fine("set useCandidateReceived for " +
                    triggerPair.toShortString());

                // we synchronize here because the same pair object can be
                // processed (in another thread) in ConnectivityCheckClient's
                // processSuccessResponse. A controlled agent select its
                // pair here if the pair state is succeeded (set in
                // processSuccessResponse) or in processSuccessResponse if
                // the pair has useCandidateReceived as true (set here). So be
                // sure that if a binding response and a binding request (for
                // the same check) from other peer come at the very same time,
                // that we will trigger the nominationConfirmed (that will
                // pass the pair as selected if it is the first time).
                synchronized(triggerPair)
                {
                    //next time we will see a request it will be considered as
                    //having USE-CANDIDATE
                    triggerPair.setUseCandidateReceived();
                }
            }

            if (knownPair.getState() == CandidatePairState.SUCCEEDED )
            {
                //7.2.1.5. Updating the Nominated Flag
                if (!isControlling() && useCand)
                {
                    logger.fine("update nominated flag");
                    // If the Binding request received by the agent had the
                    // USE-CANDIDATE attribute set, and the agent is in the
                    // controlled role, the agent looks at the state of the
                    // pair ....
                    // If the state of this pair is Succeeded, it means that a
                    // previous check generated by this pair produced a
                    // successful response. This would have caused the agent to
                    // construct a valid pair when that success response was
                    // received. The agent now sets the nominated flag in the
                    // valid pair to true.
                    nominationConfirmed( triggerPair );

                    //the above may have caused us to exit, and so we need to
                    //make the call below in order to make sure that we update
                    //ICE processing state.
                    checkListStatesUpdated();
                }

                return;
            }

            // RFC 5245: If the state of that pair is In-Progress, the agent
            // cancels the in-progress transaction.
            if (knownPair.getState() == CandidatePairState.IN_PROGRESS )
            {
                TransactionID checkTransaction
                    = knownPair.getConnectivityCheckTransaction();

                getStunStack().cancelTransaction(checkTransaction);
            }
        }
        else
        {
            //it appears that we've just discovered a peer-reflexive address.
            // RFC 5245: If the pair is not already on the check list:
            // The pair is inserted into the check list based on its priority
            // Its state is set to Waiting [and it] is enqueued into the
            // triggered check queue.
            //
            if(triggerPair.getParentComponent().getSelectedPair() == null)
                logger.info("Add peer CandidatePair with new reflexive " +
                        "address to checkList");
            triggerPair.setUseCandidateReceived();
            parentStream.addToCheckList(triggerPair);
        }

        // RFC 5245: The agent MUST create a new connectivity check for that
        // pair (representing a new STUN Binding request transaction) by
        // enqueueing the pair in the triggered check queue.  The state of
        // the pair is then changed to Waiting.
        // Emil: This actually applies for all cases.
        /*
         * Lyubomir: The connectivity checks for a CheckList are started
         * elsewhere as soon as and only if the CheckList changes from frozen
         * to unfrozen. Since CheckList#scheduleTriggeredCheck will change
         * triggerPair to Waiting and will thus unfreeze its CheckList, make
         * sure that the connectivity checks for the CheckList are started.
         * Otherwise, the connectivity checks for the CheckList may never be
         * started (which may make the Agent remain running forever).
         */
        CheckList checkList = parentStream.getCheckList();
        boolean wasFrozen = checkList.isFrozen();

        checkList.scheduleTriggeredCheck(triggerPair);
        if (wasFrozen && !checkList.isFrozen())
            connCheckClient.startChecks(checkList);
    }

    /**
     * Adds <tt>pair</tt> to that list of valid candidates for its parent
     * stream.
     *
     * @param validPair the {@link CandidatePair} we'd like to validate.
     */
    protected void validatePair(CandidatePair validPair)
    {
        Component parentComponent = validPair.getParentComponent();
        IceMediaStream parentStream = parentComponent.getParentStream();

        parentStream.addToValidList(validPair);
    }

    /**
     * Raises <tt>pair</tt>'s nomination flag and schedules a triggered check.
     * Applications only need to use this method if they disable this
     * <tt>Agent</tt>'s internal nomination and implement their own nominator
     * and turn off nominations in this agent.
     *
     * @param pair the {@link CandidatePair} that we'd like to nominate and that
     * we'd like to schedule a triggered check for.
     *
     * @throws IllegalStateException if this <tt>Agent</tt> is not a controlling
     * agent and can therefore not nominate pairs.
     *
     * @see Agent#setNominationStrategy(NominationStrategy)
     */
    public synchronized void nominate(CandidatePair pair)
        throws IllegalStateException
    {
        if(! isControlling() )
            throw new IllegalStateException("Only controlling agents can "
                            +"nominate pairs");

        Component parentComponent = pair.getParentComponent();
        IceMediaStream parentStream = parentComponent.getParentStream();

        //If the pair is not already nominated and if its parent component
        //does not already contain a nominated pair - nominate it.
        if(!pair.isNominated()
              && !parentStream.validListContainsNomineeForComponent(
                      parentComponent))
        {
            logger.info("verify if nominated pair answer again");
            pair.nominate();
            pair.getParentComponent().getParentStream()
                .getCheckList().scheduleTriggeredCheck(pair);
        }
    }

    /**
     * Specifies the {@link NominationStrategy} that we should use in order to
     * decide if and when we should nominate valid pairs.
     *
     * @param strategy the strategy that we'd like to use for nominating
     * valid {@link CandidatePair}s.
     */
    public void setNominationStrategy(NominationStrategy strategy)
    {
        this.nominator.setStrategy(strategy);
    }

    /**
     * Indicates that we have received a response to a request that either
     * contained the <tt>USE-CANDIDATE</tt> attribute or was triggered by an
     * incoming request that did.
     *
     * @param nominatedPair the {@link CandidatePair} whose nomination has
     * just been confirmed.
     */
    protected void nominationConfirmed(CandidatePair nominatedPair)
    {
        nominatedPair.nominate();

        Component parentComponent = nominatedPair.getParentComponent();
        IceMediaStream parentStream = parentComponent.getParentStream();
        CheckList checkList = parentStream.getCheckList();

        if( checkList.getState() == CheckListState.RUNNING )
            checkList.handleNominationConfirmed(nominatedPair);

        //Once there is at least one nominated pair in the valid list for
        //every component of the media stream and the state of the
        //check list is Running
        if(parentStream.allComponentsHaveSelected()
           && checkList.getState() == CheckListState.RUNNING)
        {
            //The agent MUST change the state of processing for its check
            //list for that media stream to Completed.
            checkList.setState(CheckListState.COMPLETED);
        }
    }

    /**
     * After updating check list states as a result of an incoming response
     * or a timeout event the method goes through all check lists and tries
     * to assess the state of ICE processing.
     */
    protected void checkListStatesUpdated()
    {
        boolean allListsEnded = true;
        boolean atLeastOneListSucceeded = false;

        if(getState() == IceProcessingState.COMPLETED)
            return;

        List<IceMediaStream> streams = getStreams();

        for(IceMediaStream stream : streams)
        {
            CheckListState checkListState = stream.getCheckList().getState();

            if(checkListState == CheckListState.RUNNING)
            {
                allListsEnded = false;
                break;
            }
            else if(checkListState == CheckListState.COMPLETED)
            {
                logger.info("CheckList of stream " + stream.getName() +
                        " is COMPLETED");
                atLeastOneListSucceeded = true;
            }
        }


        if(!allListsEnded)
            return;

        if(!atLeastOneListSucceeded)
        {
            //all lists ended but none succeeded. No love today ;(
            logger.info("ICE state is FAILED");
            terminate(IceProcessingState.FAILED);
            return;
        }

        //Once the state of each check list is Completed:
        //The agent sets the state of ICE processing overall to Completed.
        if(getState() != IceProcessingState.RUNNING)
        {
            //Oh, seems like we already did this.
            return;
        }

        logger.info("ICE state is COMPLETED");

        setState(IceProcessingState.COMPLETED);

        // keep ICE running (answer binding request)
        if(stunKeepAliveThread == null)
        {
            // schedule STUN checks for selected candidates
            scheduleSTUNKeepAlive();
        }

        if(compatibilityMode == CompatibilityMode.RFC5245)
        {
            scheduleTermination();
        }

        //print logs for the types of addresses we chose.
        logCandTypes();

    }

    /**
     * Goes through all streams and components and prints into the logs the type
     * of local candidates that were selected as well as the server that
     * were used (if any) to obtain them.
     */
    private void logCandTypes()
    {
        List<IceMediaStream> strms = getStreams();

        for(IceMediaStream stream : strms)
        {
            for(Component component : stream.getComponents())
            {
                CandidatePair selectedPair = component.getSelectedPair();

                StringBuffer buf = new StringBuffer( "Harvester selected for ");
                buf.append(component.toShortString());
                buf.append(" ");

                if(selectedPair == null)
                {
                    buf.append("none (conn checks failed)");
                    logger.info(buf.toString());
                    continue;
                }

                Candidate localCnd = selectedPair.getLocalCandidate();

                TransportAddress serverAddr = localCnd.getStunServerAddress();
                TransportAddress relayAddr = localCnd.getRelayServerAddress();

                buf.append(localCnd.getType());

                if(serverAddr != null)
                {
                    buf.append(" (STUN server = ");
                    buf.append(localCnd.getStunServerAddress());
                    buf.append(")");
                }
                else if(relayAddr != null)
                {
                    buf.append(" (relay = ");
                    buf.append(localCnd.getRelayServerAddress());
                    buf.append(")");
                }
                logger.info(buf.toString());
            }
        }
    }

    /**
     * Returns the number of host {@link Candidate}s in this {@link Agent}.
     *
     * @return the number of host {@link Candidate}s in this {@link Agent}.
     */
    protected int countHostCandidates()
    {
        int num = 0;

        synchronized (mediaStreams)
        {
            Collection<IceMediaStream> streamsCol = mediaStreams.values();

            for( IceMediaStream stream : streamsCol)
                num += stream.countHostCandidates();
        }

        return num;
    }

    /**
     * Lets the application specify a custom value for the <tt>Ta</tt> timer
     * so that we don't calculate one.
     *
     * @param taValue the value of the <tt>Ta</tt> timer that the application
     * would like us to use rather than calculate one.
     */
    public void setTa(long taValue)
    {
        this.taValue = taValue;
    }

    /**
     * Calculates the value of the <tt>Ta</tt> pace timer according to the
     * number and type of {@link IceMediaStream}s this agent will be using.
     * <p>
     * During the gathering phase of ICE (Section 4.1.1) and while ICE is
     * performing connectivity checks (Section 7), an agent sends STUN and
     * TURN transactions.  These transactions are paced at a rate of one
     * every <tt>Ta</tt> milliseconds.
     * <p>
     * As per RFC 5245, the value of <tt>Ta</tt> should be configurable so if
     * someone has set a value of their own, we return that value rather than
     * calculating a new one.
     *
     * @return the value of the <tt>Ta</tt> pace timer according to the
     * number and type of {@link IceMediaStream}s this agent will be using or
     * a pre-configured value if the application has set one.
     * <p>
     */
    protected long calculateTa()
    {
        //if application specified a value - use it. other wise return ....
        // eeeer ... a "dynamically" calculated one ;)
        if (taValue != -1)
            return taValue;

        /* RFC 5245 says that Ta is:
         *
         *     Ta_i = (stun_packet_size / rtp_packet_size) * rtp_ptime
         *
         *                               1
         *         Ta = MAX (20ms, ------------------- )
         *                               k
         *                             ----
         *                             \        1
         *                              >    ------
         *                             /       Ta_i
         *                             ----
         *                              i=1
         *
         * In this implementation we assume equal values of
         * stun_packet_size and rtp_packet_size. rtp_ptime is also assumed to be
         * 20ms. One day we should probably let the application modify them.
         * Until then however the above formula would always be equal to.
         *                            1
         *         Ta = MAX (20ms, ------- )
         *                            k
         *                           ---
         *                            20
         * which gives us Ta = MAX (20ms, 20/k) which is always 20.
         */
        return 20;
    }

    /**
     * Calculates the value of the retransmission timer to use in STUN
     * transactions, while harvesting addresses (not to confuse with the RTO
     * for the STUN transactions used in connectivity checks).
     *
     * @return the value of the retransmission timer to use in STUN
     * transactions, while harvesting addresses.
     */
    protected long calculateStunHarvestRTO()
    {
        /* RFC 5245 says:
         * RTO = MAX (100ms, Ta * (number of pairs))
         * where the number of pairs refers to the number of pairs of candidates
         * with STUN or TURN servers.
         *
         * Go figure what "pairs of candidates with STUN or TURN servers" means.
         * Let's assume they meant the number stun transactions we'll start
         * while harvesting.
         */

        return Math.max(100, calculateTa() * 2 * countHostCandidates());
    }

    /**
     * Calculates the value of the retransmission timer to use in STUN
     * transactions, used in connectivity checks (not to confused with the RTO
     * for the STUN address harvesting).
     *
     * @return the value of the retransmission timer to use in STUN connectivity
     * check transactions..
     */
    protected long calculateStunConnCheckRTO()
    {
        /* RFC 5245 says:
         * For connectivity checks, RTO SHOULD be configurable and SHOULD have
         * a default of:
         *
         * RTO = MAX (100ms, Ta*N * (Num-Waiting + Num-In-Progress))
         *
         * where Num-Waiting is the number of checks in the check list in the
         * Waiting state, Num-In-Progress is the number of checks in the
         * In-Progress state, and N is the number of checks to be performed.
         *
         * Emil: I am not sure I like the formula so we'll simply be returning
         * 100 for the time being.
         */
        return 100;
    }

    /**
     * Initializes and starts the {@link TerminationThread}
     */
    private void scheduleTermination()
    {
        if (terminationThread == null)
        {
            terminationThread = new TerminationThread();
            terminationThread.start();
        }
    }

    /**
     * Initializes and starts the {@link StunKeepAliveThread}
     */
    private void scheduleSTUNKeepAlive()
    {
        if (stunKeepAliveThread == null)
        {
            stunKeepAliveThread = new StunKeepAliveThread();
            stunKeepAliveThread.start();
        }
    }

    /**
     * RFC 5245 says: Once ICE processing has reached the Completed state for
     * all peers for media streams using those candidates, the agent SHOULD
     * wait an additional three seconds, and then it MAY cease responding to
     * checks or generating triggered checks on that candidate.  It MAY free
     * the candidate at that time.
     * <p>
     * This <tt>TerminationThread</tt> is scheduling such a termination and
     * garbage collection in three seconds.
     */
    private class TerminationThread
        extends Thread
    {

        /**
         * Creates a new termination timer.
         */
        private TerminationThread()
        {
            super("TerminationThread");
        }

        /**
         * Waits for a period of three seconds (or whatever termination
         * interval the user has specified) and then moves this <tt>Agent</tt>
         * into the terminated state and frees all non-nominated candidates.
         */
        @Override
        public synchronized void run()
        {
            long terminationDelay
                = Integer.getInteger(
                        StackProperties.TERMINATION_DELAY,
                        DEFAULT_TERMINATION_DELAY);

            if (terminationDelay >= 0)
            {
                try
                {
                    wait(terminationDelay);
                }
                catch (InterruptedException ie)
                {
                    logger.log(
                            Level.FINEST, "Interrupted while waiting. Will "
                                    +"speed up termination",
                            ie);
                }
            }

            logger.info("ICE state is TERMINATED");
            terminate(IceProcessingState.TERMINATED);

            terminationThread = null;
        }
    }

    /**
     * Terminates this <tt>Agent</tt> by stopping the handling of connectivity
     * checks and setting a specific termination state on it.
     *
     * @param terminationState the state that we'd like processing to terminate
     * with i.e. either {@link IceProcessingState#TERMINATED} or
     * {@link IceProcessingState#FAILED}
     */
    private void terminate(IceProcessingState terminationState)
    {
        if (!IceProcessingState.FAILED.equals(terminationState)
                && !IceProcessingState.TERMINATED.equals(terminationState))
            throw new IllegalArgumentException("terminationState");

        // stop making any checks.
        connCheckClient.stop();

        //do not stop the conn check server here because it may still need to
        //process STUN Binding Requests that remote agents may send our way.
        //we'll do this in "free()" instead.
        //connCheckServer.stop();

        setState(terminationState);
    }

    /**
     * Called by the garbage collector when garbage collection determines that
     * there are no more references to this instance. Calls {@link #free()} on
     * this instance.
     *
     * @throws Throwable if anything goes wrong and the finalization of this
     * instance is to be halted
     * @see #free()
     */
    @Override
    protected void finalize()
        throws Throwable
    {
        free();

        super.finalize();
    }

    /**
     * Prepares this <tt>Agent</tt> for garbage collection by ending all related
     * processes and  freeing its <tt>IceMediaStream</tt>s, <tt>Component</tt>s
     * and <tt>Candidate</tt>s. This method will also place the agent in the
     * terminated state in case it wasn't already there.
     */
    public void free()
    {
        logger.info("Free ICE agent");

        shutdown = true;

        //stop sending keep alives (STUN Binding Indications).
        if(stunKeepAliveThread != null)
            stunKeepAliveThread.interrupt();

        //stop responding to STUN Binding Requests.
        connCheckServer.stop();

        /*
         * Set the IceProcessingState#TERMINATED state on this Agent unless it
         * is in a termination state already.
         */
        IceProcessingState state = getState();

        if (    !IceProcessingState.FAILED.equals(state)
             && !IceProcessingState.TERMINATED.equals(state))
        {
            terminate(IceProcessingState.TERMINATED);
        }

        logger.info("remove streams");
        // Free its IceMediaStreams, Components and Candidates.
        for(IceMediaStream stream : getStreams())
        {
            try
            {
                removeStream(stream);
            }
            catch(Throwable t)
            {
                logger.info("remove stream failed: " + t);
            }
            logger.info("remove stream " + stream.getName());
        }

        getStunStack().shutDown();

        logger.info("ICE agent freed");
    }

    /**
     * Returns the current generation of this ICE Agent. A generation is an
     * index, starting at 0, that enables the parties to keep track of updates
     * to the candidate throughout the life of the session.
     *
     * @return the current generation of this ICE Agent
     */
    public int getGeneration()
    {
        return generation;
    }

    /**
     * Specifies the current generation of this ICE Agent. A generation is an
     * index, starting at 0, that enables the parties to keep track of updates
     * to the candidate throughout the life of the session.
     *
     * @param generation the current generation of this ICE Agent
     */
    public void setGeneration(int generation)
    {
        this.generation = generation;
    }

    /**
     * Returns the compatibility mode used by this agent.
     *
     * @return compatibility mode
     */
    public CompatibilityMode getCompatibilityMode()
    {
        return compatibilityMode;
    }

    /**
     * Thread that performs STUN keep-alive once ICE has COMPLETED.
     */
    private class StunKeepAliveThread
        extends Thread
    {
        /**
         * Creates a new termination timer.
         */
        private StunKeepAliveThread()
        {
            super("StunKeepAliveThread");
        }

        /**
         * Thread entry to point.
         */
        @Override
        public synchronized void run()
        {
            runInStunKeepAliveThread();
        }
    }

    /**
     * Schedule STUN checks for selected pair.
     */
    public void runInStunKeepAliveThread()
    {
        while(state == IceProcessingState.COMPLETED || state ==
            IceProcessingState.TERMINATED)
        {
            if(shutdown)
                break;

            List<IceMediaStream> streams = getStreams();

            for(IceMediaStream stream : streams)
            {
                List<Component> cmps = stream.getComponents();

                for(Component cmp : cmps)
                {
                    CandidatePair pair = cmp.getSelectedPair();

                    if(pair != null)
                    {
                        if(compatibilityMode == CompatibilityMode.GTALK)
                        {
                            //apparently GTalk insists on seeing binding
                            //requests or else it believes we are dead
                            //Emil: I am not sure this is true. I think it would
                            //be enough for us to respond to their binding
                            //requests. At least that's how it seems to work for
                            //Chrome and WebRTC.
                            //TODO: check and maybe remove
                            connCheckClient.startCheckForPair(pair);
                        }
                        else if(compatibilityMode == CompatibilityMode.RFC5245)
                        {
                            connCheckClient.sendBindingIndicationForPair(pair);
                        }
                    }
                }
            }

            if(shutdown)
                break;

            try
            {
                Thread.sleep(3000);
                Thread.yield();
            }
            catch(InterruptedException e)
            {
            }
        }
        logger.info("KeepAliveThread ends");
    }

    /**
     * Returns the selected pair for this Agent.
     *
     * @param streamName The stream name (AUDIO, VIDEO);
     *
     * @return The selected pair for this Agent. Null if no pair is selected.
     */
    private CandidatePair getSelectedPair(String streamName)
    {
        List<IceMediaStream> iceMediaStreams = this.getStreams();
        for(int i = 0; i < iceMediaStreams.size(); ++i)
        {
            if(iceMediaStreams.get(i).getName().equals(streamName))
            {
                List<org.ice4j.ice.Component> components =
                    iceMediaStreams.get(i).getComponents();
                for(int j = 0; j < components.size(); ++j)
                {
                    Component component = components.get(i);
                    if(component.getComponentID()
                            == org.ice4j.ice.Component.RTP)
                    {
                        return component.getSelectedPair();
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns the selected local candidate for this Agent.
     *
     * @param streamName The stream name (AUDIO, VIDEO);
     *
     * @return The selected local candidate for this Agent. Null if no pair is
     * selected.
     */
    public LocalCandidate getSelectedLocalCandidate(String streamName)
    {
        CandidatePair candidatePair = this.getSelectedPair(streamName);
        if(candidatePair != null)
        {
            return candidatePair.getLocalCandidate();
        }
        return null;
    }

    /**
     * Returns the selected remote candidate for this Agent.
     *
     * @param streamName The stream name (AUDIO, VIDEO);
     *
     * @return The selected remote candidate for this Agent. Null if no pair is
     * selected.
     */
    public RemoteCandidate getSelectedRemoteCandidate(String streamName)
    {
        CandidatePair candidatePair = this.getSelectedPair(streamName);
        if(candidatePair != null)
        {
            return candidatePair.getRemoteCandidate();
        }
        return null;
    }


    /**
     * Returns the harvesting time (in ms) for the harvester given in parameter.
     *
     * @param harvesterName The class name if the harvester.
     *
     * @return The harvesting time (in ms) for the harvester given in parameter.
     * 0 if this harvester does not exists, or if the agent has not yet
     * harvested with this harvester.
     */     
    public long getHarvestingTime(String harvesterName)
    {
        if(this.hostCandidateHarvester.getClass().getName().endsWith(
                    harvesterName))
        {
            return this.hostCandidateHarvester.getHarvestingTime();
        }

        long harvestingTime = 0;
        CandidateHarvester tmpHarvester;
        Iterator<CandidateHarvester> itHarvesters = this.harvesters.iterator();
        while(itHarvesters.hasNext())
        {
            tmpHarvester = itHarvesters.next();
            if(tmpHarvester.getClass().getName().endsWith(harvesterName))
            {
                harvestingTime = tmpHarvester.getHarvestingTime();
                // There may be several harvester with the same class name.
                // Thus, returns only an active one (if any).
                if(harvestingTime != 0)
                {
                    return harvestingTime;
                }
            }
        }

        return 0;
    }

    /**
     * Returns the number of harvesting time for the harvester given in
     * parameter.
     *
     * @param harvesterName The class name if the harvester.
     *
     * @return The number of harvesting time for the harvester given in
     * parameter.
     */     
    public int getNbHarvesting(String harvesterName)
    {
        if(this.hostCandidateHarvester.getClass().getName().endsWith(
                    harvesterName))
        {
            return this.hostCandidateHarvester.getNbHarvesting();
        }

        int nbHarvesting = 0;
        CandidateHarvester tmpHarvester;
        Iterator<CandidateHarvester> itHarvesters = this.harvesters.iterator();
        while(itHarvesters.hasNext())
        {
            tmpHarvester = itHarvesters.next();
            if(tmpHarvester.getClass().getName().endsWith(harvesterName))
            {
                nbHarvesting = tmpHarvester.getNbHarvesting();
                // There may be several harvester with the same class name.
                // Thus, returns only an active one (if any).
                if(nbHarvesting != 0)
                {
                    return nbHarvesting;
                }
            }
        }

        return 0;
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
     * Returns the current harvesting time in ms. If this agent is not currently
     * harvesting, then returns the value of the last total harvesting time for
     * all the harvesters.  0 if this agent has nerver harvested.
     *
     * @return The current harvesting time in ms. If this agent is not currently
     * harvesting, then returns the value of the last total harvesting time for
     * all the harvesters.  0 if this agent has nerver harvested.
     */
    public long getTotalHarvestingTime()
    {
        return this.harvestingTimeStat.getHarvestingTime();
    }

    /**
     * Returns the number of harvesting for this agent.
     *
     * @return The number of harvesting for this agent.
     */
    public int getNbHarvesting()
    {
        return this.harvestingTimeStat.getNbHarvesting();
    }
}
