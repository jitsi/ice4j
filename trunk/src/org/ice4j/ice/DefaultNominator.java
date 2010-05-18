/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.beans.*;
import java.util.*;

/**
 * Implements ice4j internal nomination strategies.
 *
 * @author Emil Ivov
 */
public class DefaultNominator
    implements PropertyChangeListener
{
    /**
     * The Agent that created us.
     */
    private final Agent parentAgent;

    /**
     * The strategy that this nominator should use to nominate valid pairs.
     */
    private NominationStrategy strategy
        = NominationStrategy.NOMINATE_FIRST_VALID;

    /**
     * Creates a new instance of this nominator using <tt>parentAgent</tt> as
     * a reference to the <tt>Agent</tt> instance that we should use to
     * nominate pairs.
     *
     * @param parentAgent the {@link Agent} that created us.
     */
    public DefaultNominator(Agent parentAgent)
    {
        this.parentAgent = parentAgent;
        parentAgent.addStateChangeListener(this);
    }

    /**
     * Tracks changes of state in {@link IceMediaStream}s and {@link
     * CheckList}s.
     *
     * @param evt the event that we should use in case it means we should
     * nominate someone.
     */
    public void propertyChange(PropertyChangeEvent evt)
    {
        if(Agent.PROPERTY_ICE_PROCESSING_STATE.equals(evt.getPropertyName()))
        {
            IceProcessingState newState = (IceProcessingState)evt.getNewValue();

            if(newState != IceProcessingState.RUNNING)
                return;

            List<IceMediaStream> streams = parentAgent.getStreams();

            for(IceMediaStream stream : streams)
            {
                stream.addPairChangeListener(this);
                stream.getCheckList().addStateChangeListener(this);
            }
        }

        if (!parentAgent.isControlling() //CONTROLLED agents cannot nominate
            || strategy == NominationStrategy.NONE)
        {
            return;
        }

        if(strategy == NominationStrategy.NOMINATE_FIRST_VALID)
            strategyNominateFirstValid(evt);
        else if (strategy == NominationStrategy.NOMINATE_HIGHEST_PRIO)
            strategyNominateHighestPrio(evt);

    }

    /**
     * Implements a basic nomination strategy that consists in nominating the
     * first pair that has become valid for a check list.
     *
     * @param evt the {@link PropertyChangeEvent} containing the pair which
     * has been validated.
     */
    private void strategyNominateFirstValid(PropertyChangeEvent evt)
    {
        if(IceMediaStream.PROPERTY_PAIR_VALIDATED.equals(evt.getPropertyName()))
        {
            CandidatePair validPair = (CandidatePair)evt.getSource();
            parentAgent.nominate(validPair);
        }
    }

    /**
     * Implements a nomination strategy that allows checks for several (or all)
     * pairs in a check list to conclude before nominating the one with the
     * highest priority.
     *
     * @param evt the {@link PropertyChangeEvent} containing the new state and
     * the source {@link CheckList}.
     */
    private void strategyNominateHighestPrio(PropertyChangeEvent evt)
    {
        String propName = evt.getPropertyName();
        if(IceMediaStream.PROPERTY_PAIR_VALIDATED.equals(propName)
           || (IceMediaStream.PROPERTY_PAIR_STATE_CHANGED.equals(propName)
                && ((CandidatePairState)evt.getNewValue())
                                == CandidatePairState.FAILED))
        {
            CandidatePair validPair = (CandidatePair)evt.getSource();
            Component parentComponent = validPair.getParentComponent();
            IceMediaStream parentStream = parentComponent.getParentStream();
            CheckList parentCheckList = parentStream.getCheckList();

            if(!parentCheckList.allChecksCompleted())
                return;

            List<Component> components = parentStream.getComponents();

            for(Component component : components)
            {
                CandidatePair pair = parentStream.getValidPair(component);
                if(pair != null)
                    parentAgent.nominate(pair);
            }
        }
    }

    /**
     * The {@link NominationStrategy} that this nominator should use when
     * deciding whether or not a valid {@link CandidatePair} is suitable for
     * nomination.
     *
     * @param strategy the {@link NominationStrategy} we should be using.
     */
    public void setStrategy(NominationStrategy strategy)
    {
        this.strategy = strategy;
    }
}
