/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.util.*;
import java.util.logging.*;

import org.ice4j.*;

/**
 * The class represents a media stream from the ICE perspective, i.e. a
 * collection of components.
 *
 * @author Emil Ivov
 * @author Namal Senarathne
 */
public class IceMediaStream
{
    /**
     * Our class logger.
     */
    private static final Logger logger =
        Logger.getLogger(IceMediaStream.class.getName());

    /**
     * The name of this media stream. The name is equal to the value specified
     * in the SDP description.
     */
    private final String name;

    /**
     * Returns the list of components that this media stream consists of. A
     * component is a piece of a media stream requiring a single transport
     * address; a media stream may require multiple components, each of which
     * has to work for the media stream as a whole to work.
     */
    private final LinkedHashMap<Integer, Component> components
                                    = new LinkedHashMap<Integer, Component>();

    /**
     * The id that was last assigned to a component. The next id that we give
     * to a component would be lastComponendID + 1;
     */
    private int lastComponentID = 0;

    /**
     * The CHECK-LIST for this stream as described in the ICE specification.
     */
    private final List<CandidatePair> checkList
                                        = new LinkedList<CandidatePair>();

    /**
     * The name of the System property that allows us to set a custom maximum
     * for check list sizes.
     */
    public static final String PNAME_MAX_CHECK_LIST_SIZE
                                        = "org.ice4j.MAX_CHECK_LIST_SIZE";

    /**
     * The default maximum size for check lists.
     */
    public static final int DEFAULT_MAX_CHECK_LIST_SIZE = 100;

    /**
     * The agent that this media stream belongs to.
     */
    private final Agent parentAgent;

    /**
     * Initializes a new <tt>IceMediaStream</tt> object.
     *
     * @param name the name of the media stream
     * @param parentAgent the agent that is handling the session that this
     * media stream is a part of
     */
    protected IceMediaStream(Agent parentAgent, String name)
    {
        this.name = name;
        this.parentAgent = parentAgent;
    }

    /**
     * Creates and adds a component to this media-stream
     * The component ID is incremented to the next integer value
     * when creating the component so make sure you keep that in mind in case
     * assigning a specific component ID is important to you.
     *
     * @param transport the transport protocol used by the component
     *
     * @return the newly created stream <tt>Component</tt> after adding it to
     * the stream first.
     */
    protected Component createComponent(Transport transport)
    {
        lastComponentID ++;

        Component component;
        synchronized( components )
        {
            component = new Component(lastComponentID, transport, this);
            components.put(new Integer(lastComponentID), component);
        }

        return component;
    }

    /**
     * Returns the name of this <tt>IceMediaStream</tt>.
     *
     * @return the name of this <tt>IceMediaStream</tt>.
     */
    public String getName()
    {
        return name;
    }

    /**
     * Returns a <tt>String</tt> representation of this media stream.
     *
     * @return a <tt>String</tt> representation of this media stream.
     */
    public String toString()
    {
        StringBuffer buff = new StringBuffer( "media stream:")
            .append(getName());
        buff.append(" (component count=").append(getComponentCount())
            .append(")");

        List<Component> components = getComponents();
        for (Component cmp : components)
        {
            buff.append("\n").append(cmp);
        }

        return buff.toString();
    }

    /**
     * Returns the <tt>Component</tt> with the specified <tt>id</tt> or
     * <tt>null</tt> if no such component exists in this stream.
     *
     * @param id the identifier of the component we are looking for.
     *
     * @return  the <tt>Component</tt> with the specified <tt>id</tt> or
     * <tt>null</tt> if no such component exists in this stream.
     */
    public Component getComponnet(int id)
    {
        synchronized(components)
        {
            return components.get(id);
        }
    }

    /**
     * Returns the list of <tt>Component</tt>s currently registered with this
     * stream.
     *
     * @return a non-null list of <tt>Component</tt>s currently registered with
     * this stream.
     */
    public List<Component> getComponents()
    {
        synchronized(components)
        {
            return new LinkedList<Component>(components.values());
        }
    }

    /**
     * Returns the number of <tt>Component</tt>s currently registered with this
     * stream.
     *
     * @return the number of <tt>Component</tt>s currently registered with this
     * stream.
     */
    public int getComponentCount()
    {
        synchronized(components)
        {
            return components.size();
        }
    }

    /**
     * Returns the IDs of all <tt>Component</tt>s currently registered with this
     * stream.
     *
     * @return a non-null list of IDs corresponding to the <tt>Component</tt>s
     * currently registered with this stream.
     */
    public List<Integer> getComponentIDs()
    {
        synchronized(components)
        {
            return new LinkedList<Integer>(components.keySet());
        }
    }

    /**
     * Returns the number of <tt>Component</tt>s currently registered with this
     * stream.
     *
     * @return the number of <tt>Component</tt>s currently registered with this
     * stream.
     */
    public int getStreamCount()
    {
        synchronized(components)
        {
            return components.size();
        }
    }

    /**
     * Returns a reference to the <tt>Agent</tt> that this stream belongs to.
     *
     * @return a reference to the <tt>Agent</tt> that this stream belongs to.
     */
    public Agent getParentAgent()
    {
        return parentAgent;
    }

    /**
     * Removes this stream and all <tt>Candidate</tt>s associated with its child
     * <tt>Component</tt>s.
     */
    protected void free()
    {
        synchronized (components)
        {
            Iterator<Map.Entry<Integer, Component>> cmpEntries
                            = components.entrySet().iterator();
            while (cmpEntries.hasNext())
            {
                Component component = cmpEntries.next().getValue();
                component.free();
                cmpEntries.remove();
            }
        }
    }

    /**
     * Removes <tt>component</tt> and all its <tt>Candidate</tt>s from the
     * this stream and releases all associated resources that they had
     * allocated (like sockets for example)
     *
     * @param component the <tt>Component</tt> we'd like to remove and free.
     */
    public void removeComponent(Component component)
    {
        synchronized (components)
        {
            components.remove(component.getComponentID());
            component.free();
        }
    }

    /**
     * Creates, initializes and orders the list of candidate pairs that would
     * be used for the connectivity checks for all components in this stream.
     */
    protected void initCheckList()
    {
        synchronized(checkList)
        {
            checkList.clear();
            List<Component> componentsList = getComponents();

            for(Component cmp : componentsList)
            {
                createCheckList(cmp, checkList);
            }
        }
    }

    /**
     * Creates and adds to <tt>checkList</tt> all the <tt>CandidatePair</tt>s
     * in <tt>component</tt>.
     *
     * @param component the <tt>Component</tt> whose candidates we need to
     * pair and extract.
     * @param checkList the list that we need to update with the new pairs.
     */
    private void createCheckList(Component           component,
                                 List<CandidatePair> checkList)
    {
        List<LocalCandidate> localCnds = component.getLocalCandidates();
        List<Candidate> remoteCnds = component.getRemoteCandidates();

        for(LocalCandidate localCnd : localCnds)
        {
            for(Candidate remoteCnd : remoteCnds)
            {
                if(!localCnd.canReach(remoteCnd))
                    continue;

                CandidatePair pair = new CandidatePair(localCnd, remoteCnd);

                checkList.add(pair);
            }
        }

        orderCheckList();
        pruneCheckList();
    }

    /**
     * Orders this stream's pair check list in decreasing order of pair
     * priority. If two pairs have identical priority, the ordering amongst
     * them is arbitrary.
     */
    private void orderCheckList()
    {
        synchronized(checkList)
        {
            Collections.sort(checkList, CandidatePair.comparator);
        }
    }


    /**
     *  Removes or, as per the ICE spec, "prunes" pairs that we don't need to
     *  run checks for. For example, since we cannot send requests directly
     *  from a reflexive candidate, but only from its base, we go through the
     *  sorted list of candidate pairs and in every pair where the local
     *  candidate is server reflexive, we replace the local server reflexive
     *  candidate with its base. Once this has been done, we remove each pair
     *  where the local and remote candidates are identical to the local and
     *  remote candidates of a pair higher up on the priority list.
     *  <p/>
     *  In addition, in order to limit the attacks described in Section 18.5.2
     *  of the ICE spec, we limit the total number of pairs and hence
     *  (connectivity checks) to a specific value, (100 by default).
     */
    private void pruneCheckList()
    {
        synchronized(checkList)
        {
            //a list that we only use for storing pairs that we've already gone
            //through. The list is destroyed at the end of this method.
            List<CandidatePair> tmpCheckList
                = new ArrayList<CandidatePair>(checkList.size());

            Iterator<CandidatePair> ckListIter = checkList.iterator();

            int maxCheckListSize = Integer.getInteger(
                PNAME_MAX_CHECK_LIST_SIZE, DEFAULT_MAX_CHECK_LIST_SIZE);

            while(ckListIter.hasNext())
            {
                CandidatePair pair = ckListIter.next();

                //drop all pairs above MAX_CHECK_LIST_SIZE.
                if(tmpCheckList.size() > maxCheckListSize)
                {
                    ckListIter.remove();
                    continue;
                }

                //replace local server reflexive candidates with their base.
                LocalCandidate localCnd = pair.getLocalCandidate();
                if( localCnd.getType()
                                == CandidateType.SERVER_REFLEXIVE_CANDIDATE)
                {
                    pair.setLocalCandidate(localCnd.getBase());

                    //if the new pair corresponds to another one with a higher
                    //priority, then remove it.
                    if(tmpCheckList.contains(pair))
                    {
                        ckListIter.remove();
                        continue;
                    }
                }

                tmpCheckList.add(pair);
            }
        }
    }

    /**
     * Returns the list of <tt>CandidatePair</tt>s for this stream.
     *
     * @return the list of <tt>CandidatePair</tt>s for this stream.
     */
    public List<CandidatePair> getCheckList()
    {
        return checkList;
    }
}
