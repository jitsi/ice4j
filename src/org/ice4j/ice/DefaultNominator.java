/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.beans.*;
import java.util.*;
import java.util.logging.*;

/**
 * Implements ice4j internal nomination strategies.
 *
 * @author Emil Ivov
 */
public class DefaultNominator
    implements PropertyChangeListener
{
    /**
     * The logger.
     */
    private static Logger logger =
        Logger.getLogger(DefaultNominator.class.getName());

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
     * Map that will remember association between validated relayed candidate
     * and a timer. It is use with the NOMINATE_FIRST_HIGHEST_VALID strategy.
     */
    private Map<String, TimerTask> validatedCandidates =
        new HashMap<String, TimerTask>();

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

        if(evt.getSource() instanceof CandidatePair)
        {
            CandidatePair validPair = (CandidatePair)evt.getSource();


            // do not nominate pair if there is currently a selected pair for
            // the component
            if(validPair.getParentComponent().getSelectedPair() != null)
            {
                logger.fine("Keep-alive for pair: " +
                    validPair.toShortString());
                return;
            }
        }

        if(strategy == NominationStrategy.NOMINATE_FIRST_VALID)
            strategyNominateFirstValid(evt);
        else if (strategy == NominationStrategy.NOMINATE_HIGHEST_PRIO)
            strategyNominateHighestPrio(evt);
        else if (strategy ==
            NominationStrategy.NOMINATE_FIRST_HOST_OR_REFLEXIVE_VALID)
            strategyNominateFirstHostOrReflexiveValid(evt);
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

            logger.info("Nominate (first valid): " + validPair.toShortString());
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
                {
                    logger.info("Nominate (highest priority): " +
                            validPair.toShortString());
                    parentAgent.nominate(pair);
                }
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

    /**
     * Implements a nomination strategy that consists in nominating directly
     * host or server reflexive pair that has become valid for a
     * check list. For relayed pair, a timer is armed to see if no other host or
     * server reflexive pair gets validated prior to timeout, the relayed ones
     * gets nominated.
     *
     * @param evt the {@link PropertyChangeEvent} containing the pair which
     * has been validated.
     */
    private void strategyNominateFirstHostOrReflexiveValid(
            PropertyChangeEvent evt)
    {
        if(IceMediaStream.PROPERTY_PAIR_VALIDATED.equals(evt.getPropertyName()))
        {
            CandidatePair validPair = (CandidatePair)evt.getSource();

            TimerTask task = null;
            boolean isRelayed =
                (validPair.getLocalCandidate() instanceof RelayedCandidate) ||
                validPair.getLocalCandidate().getType().equals(
                    CandidateType.RELAYED_CANDIDATE) ||
                validPair.getRemoteCandidate().getType().equals(
                    CandidateType.RELAYED_CANDIDATE);
            boolean nominate = false;

            synchronized(validatedCandidates)
            {
                task = validatedCandidates.get(
                    validPair.getParentComponent().toShortString());

                if(isRelayed && task == null)
                {
                    /* armed a timer and see if a host or server reflexive pair
                     * gets nominated. Otherwise nominate the relayed candidate
                     * pair
                     */
                    Timer timer = new Timer();
                    task = new RelayedCandidateTask(validPair);

                    logger.info("Wait timeout to nominate relayed candidate");
                    timer.schedule(task, 0);
                    validatedCandidates.put(
                             validPair.getParentComponent().toShortString(),
                            task);
                }
                else if(!isRelayed)
                {
                    // host or server reflexive candidate pair
                    if(task != null)
                    {
                        task.cancel();
                        logger.info(
                            "Found a better candidate pair to nominate for "
                                    + validPair.getParentComponent().
                                        toShortString());
                    }

                    logger.info("Nominate (first highest valid): " +
                            validPair.toShortString());
                    nominate = true;
                }
            }

            if(nominate)
                parentAgent.nominate(validPair);
        }
    }

    /**
     * TimerTask that will wait a certain amount of time to let other candidate
     * pair to be validated and possibly be better than the relayed candidate.
     *
     * @author Sebastien Vincent
     */
    private class RelayedCandidateTask
        extends TimerTask
        implements PropertyChangeListener
    {
        /**
         * Wait time in milliseconds.
         */
        private static final int WAIT_TIME = 800;

        /**
         * The relayed candidate pair.
         */
        private final CandidatePair pair;

        /**
         * If the task has been canceled.
         */
        private boolean canceled = false;

        /**
         * Constructor.
         *
         * @param pair relayed candidate pair
         */
        public RelayedCandidateTask(CandidatePair pair)
        {
            this.pair = pair;
            pair.getParentComponent().getParentStream().getCheckList().
                addChecksListener(this);
        }

        /**
         * Tracks end of checks of the {@link CheckList}.
         *
         * @param evt the event
         */
        public void propertyChange(PropertyChangeEvent evt)
        {
            /* check list has running out of ordinary checks, see if all other
             * candidates are FAILED, in which case we nominate immediately
             * the relayed candidate
             */
            CheckList checkList = (CheckList)evt.getSource();
            boolean allFailed = true;

            synchronized(checkList)
            {
                for(CandidatePair c : checkList)
                {
                    if(c != pair && c.getState() != CandidatePairState.FAILED)
                    {
                        allFailed = false;
                    }
                }
            }

            if(allFailed)
            {
                // all other pairs are failed to do not waste time, cancel
                // timer and nominate ourself (the relayed candidate).
                this.cancel();

                logger.info("Nominate (first highest valid): " +
                        pair.toShortString());
                parentAgent.nominate(pair);
            }
        }

        /**
         * Cancel task.
         */
        @Override
        public boolean cancel()
        {
            canceled = true;
            return super.cancel();
        }

        /**
         * Task entry point.
         */
        public void run()
        {
            try
            {
                Thread.sleep(WAIT_TIME);
            }
            catch(InterruptedException e)
            {
                canceled = true;
            }

            pair.getParentComponent().getParentStream().getCheckList().
                removeChecksListener(this);
            validatedCandidates.remove(
                    pair.getParentComponent().toShortString());

            if(canceled)
            {
                return;
            }

            logger.info("Nominate (first highest valid): " +
                    pair.toShortString());

            // task has not been canceled after WAIT_TIME milliseconds so
            // nominate the pair
            parentAgent.nominate(pair);
        }
    }
}
