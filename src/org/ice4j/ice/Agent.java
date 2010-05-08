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
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * An <tt>Agent</tt> could be described as the main class (i.e. the chef d'orchestre)
 * of an ICE implementation.
 * <p>
 * As defined in RFC 3264, an agent is the protocol implementation involved in
 * the offer/answer exchange. There are two agents involved in an offer/answer
 * exchange.
 * <p>
 *
 * @author Emil Ivov
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
     * The <tt>Logger</tt> used by the <tt>Agent</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(Agent.class.getName());

    /**
     * The LinkedHashMap used to store the media streams
     * This map preserves the insertion order of the media streams.
     */
    private Map<String, IceMediaStream> mediaStreams
                                = new LinkedHashMap<String, IceMediaStream>();

    /**
     * The candidate harvester that we use to gather candidate on the local
     * machine.
     */
    private final HostCandidateHarvester hostCandidateHarvester
                                                = new HostCandidateHarvester();

    /**
     * The list of harvesters (i.e. STUN, TURN, and others) that the agent
     * should use when gathering candidates for components.
     */
    private final List<CandidateHarvester> harvesters
                                        = new ArrayList<CandidateHarvester>();

    /**
     * We use the <tt>FoundationsRegistry</tt> to keep track of the foundations
     * we assign within a session (i.e. the entire life time of an
     * <tt>Agent</tt>)
     */
    private final FoundationsRegistry foundationsRegistry
                                          = new FoundationsRegistry();

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
        = new Vector<CandidatePair>();

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
     * The user fragment that we received from the remote party.
     */
    private String remoteUfrag;

    /**
     * The password that we received from the remote party.
     */
    private String remotePassword;

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
    private final ConnectivityCheckClient connCheckClient
                                = new ConnectivityCheckClient(this);

    /**
     * The entity that will be taking care of incoming connectivity checks.
     */
    private final ConnectivityCheckServer connCheckServer
                                = new ConnectivityCheckServer(this);

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
    private List<PropertyChangeListener> stateListeners
                                = new LinkedList<PropertyChangeListener>();

    /**
     * The thread that we use for moving from COMPLETED into a TERMINATED state.
     */
    private TerminationThread terminationThread;

    /**
     * Creates an empty <tt>Agent</tt> with no streams, and no address
     */
    public Agent()
    {
        SecureRandom random = new SecureRandom();

        ufrag = new BigInteger(24, random).toString(32);
        password = new BigInteger(128, random).toString(32);

        tieBreaker = Math.abs(random.nextLong());

        //add the software attribute to all messages
        String sware = StackProperties.getString(StackProperties.SOFTWARE);
        if( sware == null)
            System.setProperty(StackProperties.SOFTWARE, "ice4j.org");

        //add the FINGERPRINT attribute to all messages.
        System.setProperty(StackProperties.ALWAYS_SIGN, "true");
    }

    /**
     * Creates a new media stream and stores it
     *
     * @param mediaStreamName    the name of the media stream
     *
     * @return a reference to the newly created <tt>IceMediaStream</tt>.
     */
    public IceMediaStream createMediaStream(String mediaStreamName)
    {
        IceMediaStream mediaStream
            = new IceMediaStream(Agent.this, mediaStreamName);
        mediaStreams.put(mediaStreamName, mediaStream);

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
            throw new IllegalArgumentException("This implementation does not "
                            +" currently support transport: " + transport);
        Component component = stream.createComponent(transport);

        gatherCandidates(component, preferredPort, minPort, maxPort );
        return component;
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
     * before giving up and throwinG an exception.
     *
     * @throws IllegalArgumentException if either <tt>minPort</tt> or
     * <tt>maxPort</tt> is not a valid port number or if <tt>minPort >
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
        hostCandidateHarvester.harvest(
                        component, preferredPort, minPort, maxPort);

        //apply other harvesters here:
        //todo: run harvesters in a parallel manner
        synchronized(harvesters)
        {
            for (CandidateHarvester h : harvesters )
            {
                h.harvest(component);
            }
        }

        computeFoundations(component);

        //make sure we compute priorities only after we have all candidates
        component.prioritizeCandidates();

        //eliminate redundant candidates
        component.eliminateRedundantCandidates();

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
            initCheckLists();
            setState(IceProcessingState.RUNNING);
            connCheckClient.startChecks();
        }
    }

    /**
     * Indicates whether this {@link Agent} is currently in the process of
     * running connectivity checks and establishing connectivity. Connectivity
     * establishment is considered to have started after both {@link Agent}s
     * have exchanged their media descriptions. Determining whether the actual
     * process has started is important, for example, when determining whether
     * a remote address we've just discovered is peer reflexive or not.
     * If CE has started and we don't know about the address then we should
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
        return state != IceProcessingState.WAITING;
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
        List<PropertyChangeListener> listenersCopy;

        synchronized(stateListeners)
        {
            listenersCopy
                = new LinkedList<PropertyChangeListener>(stateListeners);
        }

        PropertyChangeEvent evt = new PropertyChangeEvent(
                        this, "IceProcessingState", oldState, newState);

        for(PropertyChangeListener l : listenersCopy)
        {
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
        List<IceMediaStream> streams = getStreams();

        //init the maximum number of check list entries per stream.
        int maxCheckListSize = Integer.getInteger(
               StackProperties.MAX_CHECK_LIST_SIZE,
               DEFAULT_MAX_CHECK_LIST_SIZE);

        int maxPerStreamSize = maxCheckListSize / streams.size();

        for(IceMediaStream stream : streams)
        {
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

        for (Candidate cand : candidates)
        {
            foundationsRegistry.assignFoundation(cand);
        }
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
        synchronized(harvesters)
        {
            harvesters.add(harvester);
        }
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
     * Returns the user name that we received from the remote peer or
     * <tt>null</tt> if we haven't received a user name from them yet.
     *
     * @return the user name that we received from the remote peer or
     * <tt>null</tt> if we haven't received a user name from them yet.
     */
    public String getRemoteUfrag()
    {
        return remoteUfrag;
    }

    /**
     * Returns the password that we received from the remote peer or
     * <tt>null</tt> if we haven't received a password from them yet.
     *
     * @return the password that we received from the remote peer or
     * <tt>null</tt> if we haven't received a password from them yet.
     */
    public String getRemotePassword()
    {
        return remotePassword;
    }

    /**
     * Specifies the user name that we received from the remote peer.
     *
     * @param remoteUfrag the user name that we received from the remote peer.
     */
    public void setRemoteUfrag(String remoteUfrag)
    {
        this.remoteUfrag = remoteUfrag;
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
     * @return a user name that this <tt>Agent</tt> can use in connectivity
     * check for outgoing Binding Requests.
     */
    public String generateLocalUserName()
    {
        return getRemoteUfrag() + ":" + getLocalUfrag();
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
     * @return a user name that a peer <tt>Agent</tt> would use in connectivity
     * check for outgoing Binding Requests.
     */
    public String generateRemoteUserName()
    {
        return getLocalUfrag() + ":" + getRemoteUfrag();
    }

    /**
     * Specifies the password that we received from the remote peer.
     *
     * @param remotePassword the user name that we received from the remote
     * peer.
     */
    public void setRemotePassword(String remotePassword)
    {
        this.remotePassword = remotePassword;
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
     * Returns the number of {@link CheckList}s that are currently active.
     *
     * @return the number of {@link CheckList}s that are currently active.
     *
     */
    public int getActiveCheckListCount()
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
        StringBuffer buff = new StringBuffer("ICE Agent (stream-count=");

        buff.append(getStreamCount()).append(" ice-pwd:")
            .append(getLocalPassword());
        buff.append(getStreamCount()).append(" ice-ufrag:")
            .append(getLocalUfrag());
        buff.append(getStreamCount()).append(" tie-breaker:")
            .append(getTieBreaker());
        buff.append("):\n");

        List<IceMediaStream> streams = getStreams();
        for(IceMediaStream stream : streams)
        {
            buff.append(stream.toString()).append("\n");
        }

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
    public Candidate findRemoteCandidate(TransportAddress remoteAddress)
    {
        Collection<IceMediaStream> streamsCollection = mediaStreams.values();

        for( IceMediaStream stream : streamsCollection)
        {
            Candidate cnd = stream.findRemoteCandidate(remoteAddress);

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

            for( IceMediaStream stream : streamsCollection)
            {
                CandidatePair pair = stream.findCandidatePair(
                                localAddress, remoteAddress);
                if( pair != null )
                {
                    return pair;
                }
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
     * @param useCandidate indicates whether the incoming check {@link Request}
     * contained the USE-CANDIDATE ICE attribute.
     */
    public void incomingCheckReceived(TransportAddress remoteAddress,
                                      TransportAddress localAddress,
                                      long             priority,
                                      String           remoteUFrag,
                                      boolean          useCandidate)
    {
        LocalCandidate localCandidate = findLocalCandidate(localAddress);
        Component parentComponent = localCandidate.getParentComponent();

        RemoteCandidate remoteCandidate = new RemoteCandidate(
            remoteAddress, parentComponent,
            CandidateType.PEER_REFLEXIVE_CANDIDATE,
            foundationsRegistry.obtainFoundationForPeerReflexiveCandidate(),
            priority);

        CandidatePair triggeredPair
            = new CandidatePair(localCandidate, remoteCandidate);

        if(useCandidate)
            triggeredPair.setUseCandidateReceived();

        synchronized(startLock)
        {
            if(isStarted())
            {
                //we are started, which means we have the remote candidates
                //so it's now safe to go and see whether this is a new PR cand.
                triggerCheck(triggeredPair);
            }
            else
            {
                //we are not started yet so we'd better wait until we get the
                //remote candidates incase we are holding to a new PR one.
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
        CandidatePair knownPair =  this.findCandidatePair(
                    triggerPair.getLocalCandidate().getTransportAddress(),
                    triggerPair.getRemoteCandidate().getTransportAddress());

        IceMediaStream parentStream = triggerPair.getLocalCandidate()
            .getParentComponent().getParentStream();

        if (knownPair != null)
        {
            //if the incoming request contained a USE-CANDIDATE attribute then
            //make sure we don't lose this piece of info.
            if (triggerPair.useCandidateReceived())
                knownPair.setUseCandidateReceived();

            triggerPair = knownPair;

            //we already know about the remote address so we only need to
            //trigger a check for the existing pair

            if (knownPair.getState() == CandidatePairState.SUCCEEDED )
            {
                //7.2.1.5. Updating the Nominated Flag
                if (!isControlling() && triggerPair.useCandidateReceived())
                {
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
                }

                return;
            }

            // RFC 5245: If the state of that pair is In-Progress, the agent
            // cancels the in-progress transaction.
            if (knownPair.getState() == CandidatePairState.IN_PROGRESS )
            {
                TransactionID checkTransaction
                    = knownPair.getConnectivityCheckTransaction();

                StunStack.getInstance().cancelTransaction(checkTransaction);

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
            parentStream.addToCheckList(triggerPair);
        }

        // RFC 5245: The agent MUST create a new connectivity check for that
        // pair (representing a new STUN Binding request transaction) by
        // enqueueing the pair in the triggered check queue.  The state of
        // the pair is then changed to Waiting.
        // Emil: This actually applies for all cases.
        parentStream.getCheckList().scheduleTriggeredCheck(triggerPair);
    }

    /**
     * Adds <tt>pair</tt> to that list of valid candidates for its parent
     * stream.
     *
     * @param validPair the {@link CandidatePair} we'd like to validate.
     */
    public void validatePair(CandidatePair validPair)
    {
        IceMediaStream parentStream
            = validPair.getParentComponent().getParentStream();

        parentStream.addValidPair(validPair);

System.out.println("valid pair was nominated " + validPair);
        validPair.nominate();
        validPair.getParentComponent().getParentStream()
                .getCheckList().scheduleTriggeredCheck(validPair);
    }

    /**
     * Indicates that we have received a response to a request that either
     * contained the <tt>USE-CANDIDATE</tt> attribute or was triggered by an
     * incoming request that did.
     *
     * @param pairToNominate the {@link CandidatePair} whose nomination has
     * just been confirmed.
     */
    public void nominationConfirmed(CandidatePair pairToNominate)
    {
        pairToNominate.nominate();
System.out.println("pair nomination confirmed");
        Component parentComponent = pairToNominate.getParentComponent();
        IceMediaStream parentStream = parentComponent.getParentStream();
        CheckList checkList = parentStream.getCheckList();

        if( checkList.getState() == CheckListState.RUNNING )
            checkList.handleNomination(pairToNominate);

        //Once there is at least one nominated pair in the valid list for
        //every component of the media stream and the state of the
        //check list is Running
        if(parentStream.allComponentsAreNominated()
           && checkList.getState() == CheckListState.RUNNING)
        {
            //The agent MUST change the state of processing for its check
            //list for that media stream to Completed.
            checkList.setState(CheckListState.COMPLETED);
System.out.println("checklist " + checkList.getName() + " became " + checkList.getState());
        }
    }

    /**
     * After updating check list states as a result of an incoming response
     * or a timeout event the method goes through all check lists and tries
     * to assess the state of ICE processing.
     */
    public void checkListStatesUpdated()
    {
        boolean allListsEnded = true;
        boolean atLeastOneListSucceeded = false;

        List<IceMediaStream> streams = getStreams();

        for(IceMediaStream stream : streams)
        {
            CheckList checkList = stream.getCheckList();
            if(checkList.getState() == CheckListState.RUNNING)
            {
                allListsEnded = false;
                break;
            }
            else if(stream.getCheckList().getState() == CheckListState.COMPLETED)
            {
                atLeastOneListSucceeded = true;
            }
        }

        //Once the state of each check list is Completed:
        //The agent sets the state of ICE processing overall to Completed.
        if(allListsEnded)
        {
            if(atLeastOneListSucceeded)
            {
                setState(IceProcessingState.COMPLETED);
                scheduleTermination();
            }
            else
            {
                setState(IceProcessingState.FAILED);

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
            {
                num += stream.countHostCandidates();
            }
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
    public long calculateTa()
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
    public long calculateStunHarvestRTO()
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
    public long calculateStunConnCheckRTO()
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
            terminationThread = new TerminationThread(this);

        terminationThread.start();
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
    private static class TerminationThread
        extends Thread
    {
        /**
         * The parent agent that created us.
         */
        private final Agent parentAgent;

        /**
         * Creates a new termination timer.
         *
         * @param parentAgent the <tt>Agent</tt> that created us.
         */
        private TerminationThread(Agent parentAgent)
        {
            super("TerminationThread");
            this.parentAgent = parentAgent;
        }

        /**
         * Waits for a period of three seconds (or whatever termination
         * interval the user has specified) and then moves this <tt>Agent</tt>
         * into the terminated state and frees all non-nominated candidates.
         */
        public void run()
        {
            long waitFor = Integer.getInteger(
                            StackProperties.TERMINATION_DELAY,
                            DEFAULT_TERMINATION_DELAY);

            try
            {
                wait(waitFor);
            }
            catch (Exception e)
            {
                logger.log(Level.FINEST,
                    "Interrupted while waiting. Will speed up termination", e);
            }

            parentAgent.terminate();
        }
    }

    /**
     * Prepares everything associated with this {@link Agent} for garbage
     * collection and moves it into the terminated state.
     */
    private void terminate()
    {
        // free candidates
        // stop listening for checks

        setState(IceProcessingState.TERMINATED);
    }
}
