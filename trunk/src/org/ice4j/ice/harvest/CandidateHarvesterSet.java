/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.ice.harvest;

import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

import org.ice4j.ice.*;

/**
 * Implements {@link Set} of <tt>CandidateHarvester</tt>s which runs the
 * gathering of candidate addresses performed by its elements in parallel.
 *
 * @author Lyubomir Marinov
 */
public class CandidateHarvesterSet
    extends AbstractSet<CandidateHarvester>
{
    /**
     * The <tt>Logger</tt> used by the <tt>Agent</tt> class and its instances
     * for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(CandidateHarvesterSet.class.getName());

    /**
     * The <tt>CandidateHarvester</tt>s which are the elements of this
     * <tt>Set</tt>.
     */
    private final Collection<CandidateHarvesterSetElement> elements
        = new LinkedList<CandidateHarvesterSetElement>();

    /**
     * A pool of thread used for gathering process.
     */
    private static ExecutorService threadPool = Executors.newCachedThreadPool();

    /**
     * Initializes a new <tt>CandidateHarvesterSet</tt> instance.
     */
    public CandidateHarvesterSet()
    {
    }

    /**
     * Adds a specific <tt>CandidateHarvester</tt> to this
     * <tt>CandidateHarvesterSet</tt> and returns <tt>true</tt> if it is not
     * already present. Otherwise, leaves this set unchanged and returns
     * <tt>false</tt>.
     *
     * @param harvester the <tt>CandidateHarvester</tt> to be added to this
     * <tt>CandidateHarvesterSet</tt>
     * @return <tt>true</tt> if this <tt>CandidateHarvesterSet</tt> did not
     * already contain the specified <tt>harvester</tt>; otherwise,
     * <tt>false</tt>
     * @see Set#add(Object)
     */
    @Override
    public boolean add(CandidateHarvester harvester)
    {
        synchronized (elements)
        {
            for (CandidateHarvesterSetElement element : elements)
                if (element.harvesterEquals(harvester))
                    return false;

            elements.add(new CandidateHarvesterSetElement(harvester));
            return true;
        }
    }

    /**
     * Gathers candidate addresses for a specific <tt>Component</tt>.
     * <tt>CandidateHarvesterSet</tt> delegates to the
     * <tt>CandidateHarvester</tt>s which are its <tt>Set</tt> elements.
     *
     * @param component the <tt>Component</tt> to gather candidate addresses for
     * @see CandidateHarvester#harvest(Component)
     */
    public void harvest(Component component)
    {
        synchronized (elements)
        {
            harvest(elements.iterator(), component, threadPool);
        }
    }

    /**
     * Gathers candidate addresses for a specific <tt>Component</tt> using
     * specific <tt>CandidateHarvester</tt>s.
     *
     * @param harvesters the <tt>CandidateHarvester</tt>s to gather candidate
     * addresses for the specified <tt>Component</tt>
     * @param component the <tt>Component</tt> to gather candidate addresses for
     * @param executorService the <tt>ExecutorService</tt> to schedule the
     * execution of the gathering of candidate addresses performed by the
     * specified <tt>harvesters</tt>
     */
    private void harvest(
            final Iterator<CandidateHarvesterSetElement> harvesters,
            final Component component,
            ExecutorService executorService)
    {
        /**
         * Represents a task to be executed by the specified executorService and
         * to call {@link CandidateHarvester#harvestComponent} on the specified
         * harvesters.
         */
        class CandidateHarvesterSetTask
            implements Runnable
        {
            /**
             * The <tt>CandidateHarvester</tt> on which
             * {@link CandidateHarvester#harvest(Component)} is to be or is
             * being called.
             */
            private CandidateHarvesterSetElement harvester;

            /**
             * Initializes a new <tt>CandidateHarvesterSetTask</tt> which is to
             * call {@link CandidateHarvester#harvest(Component)} on a specific
             * harvester and then as many harvesters as possible.
             *
             * @param harvester the <tt>CandidateHarvester</tt> on which the
             * new instance is to call
             * <tt>CandidateHarvester#harvest(Component)</tt> first
             */
            public CandidateHarvesterSetTask(
                    CandidateHarvesterSetElement harvester)
            {
                this.harvester = harvester;
            }

            /**
             * Gets the <tt>CandidateHarvester</tt> on which
             * {@link CandidateHarvester#harvest(Component)} is being called.
             *
             * @return the <tt>CandidateHarvester</tt> on which
             * <tt>CandidateHarvester#harvest(Component)</tt> is being called
             */
            public CandidateHarvesterSetElement getHarvester()
            {
                return harvester;
            }

            public void run()
            {
                while (true)
                {
                    if (harvester.isEnabled())
                    {
                        try
                        {
                            harvester.harvest(component);
                        }
                        catch (Throwable t)
                        {
                            logger.info(
                                "disabling harvester due to exception: " +
                                    t.getLocalizedMessage());
                            harvester.setEnabled(false);

                            if (t instanceof ThreadDeath)
                                throw (ThreadDeath) t;
                        }
                    }

                    /*
                     * CandidateHarvester#harvest(Component) has been called on
                     * the harvester and its success or failure has been noted.
                     * Now forget the harvester because any failure to continue
                     * execution is surely not its fault.
                     */
                    harvester = null;

                    synchronized (harvesters)
                    {
                        if (harvesters.hasNext())
                            harvester = harvesters.next();
                        else
                            break;
                    }
                }
            }
        }

        /*
         * Start asynchronously executing the
         * CandidateHarvester#harvest(Component) method of the harvesters.
         */
        Map<CandidateHarvesterSetTask, Future<?>> tasks
            = new HashMap<CandidateHarvesterSetTask, Future<?>>();

        while (true)
        {
            /*
             * Find the next CandidateHarvester which is to start gathering
             * candidates.
             */
            CandidateHarvesterSetElement harvester;

            synchronized (harvesters)
            {
                if (harvesters.hasNext())
                    harvester = harvesters.next();
                else
                    break;
            }
            if (!harvester.isEnabled())
                continue;

            // Asynchronously start gathering candidates using the harvester.
            CandidateHarvesterSetTask task
                = new CandidateHarvesterSetTask(harvester);

            tasks.put(task, executorService.submit(task));
        }

        /*
         * Wait for all harvesters to be given a chance to execute their
         * CandidateHarvester#harvest(Component) method.
         */
        Iterator<Map.Entry<CandidateHarvesterSetTask, Future<?>>> taskIter
            = tasks.entrySet().iterator();

        while (taskIter.hasNext())
        {
            Map.Entry<CandidateHarvesterSetTask, Future<?>> task
                = taskIter.next();
            Future<?> future = task.getValue();

            while (true)
            {
                try
                {
                    future.get();
                    break;
                }
                catch (CancellationException ce)
                {
                    logger.info("harvester cancelled");
                    /*
                     * It got cancelled so we cannot say that the fault is with
                     * its current harvester.
                     */
                    break;
                }
                catch (ExecutionException ee)
                {
                    /*
                     * A problem appeared during the execution of the task.
                     * CandidateHarvesterSetTask clears its harvester property
                     * for the purpose of determining whether the problem has
                     * appeared while working with a harvester.
                     */
                    logger.info(
                        "disabling harvester due to ExecutionException: " +
                            ee.getLocalizedMessage());

                    CandidateHarvesterSetElement harvester
                        = task.getKey().getHarvester();

                    if (harvester != null)
                        harvester.setEnabled(false);
                    break;
                }
                catch (InterruptedException ie)
                {
                    continue;
                }
            }
            taskIter.remove();
        }
    }

    /**
     * Returns an <tt>Iterator</tt> over the <tt>CandidateHarvester</tt>s which
     * are elements in this <tt>CandidateHarvesterSet</tt>. The elements are
     * returned in no particular order.
     *
     * @return an <tt>Iterator</tt> over the <tt>CandidateHarvester</tt>s which
     * are elements in this <tt>CandidateHarvesterSet</tt>
     * @see Set#iterator()
     */
    public Iterator<CandidateHarvester> iterator()
    {
        final Iterator<CandidateHarvesterSetElement> elementIter
            = elements.iterator();

        return
            new Iterator<CandidateHarvester>()
            {
                /**
                 * Determines whether this iteration has more elements.
                 *
                 * @return <tt>true</tt> if this iteration has more elements;
                 * otherwise, <tt>false</tt>
                 * @see Iterator#hasNext()
                 */
                public boolean hasNext()
                {
                    return elementIter.hasNext();
                }

                /**
                 * Returns the next element in this iteration.
                 *
                 * @return the next element in this iteration
                 * @throws NoSuchElementException if this iteration has no more
                 * elements
                 * @see Iterator#next()
                 */
                public CandidateHarvester next()
                    throws NoSuchElementException
                {
                    return elementIter.next().harvester;
                }

                /**
                 * Removes from the underlying <tt>CandidateHarvesterSet</tt>
                 * the last <tt>CandidateHarvester</tt> (element) returned by
                 * this <tt>Iterator</tt>. <tt>CandidateHarvestSet</tt> does not
                 * implement the <tt>remove</tt> operation at the time of this
                 * writing i.e. it always throws
                 * <tt>UnsupportedOperationException</tt>.
                 *
                 * @throws IllegalStateException if the <tt>next</tt> method has
                 * not yet been called, or the <tt>remove</tt> method has
                 * already been called after the last call to the <tt>next</tt>
                 * method
                 * @throws UnsupportedOperationException if the <tt>remove</tt>
                 * operation is not supported by this <tt>Iterator</tt>
                 * @see Iterator#remove()
                 */
                public void remove()
                    throws IllegalStateException,
                           UnsupportedOperationException
                {
                    throw new UnsupportedOperationException("remove");
                }
            };
    }

    /**
     * Returns the number of <tt>CandidateHarvester</tt>s which are elements in
     * this <tt>CandidateHarvesterSet</tt>.
     *
     * @return the number of <tt>CandidateHarvester</tt>s which are elements in
     * this <tt>CandidateHarvesterSet</tt>
     * @see Set#size()
     */
    public int size()
    {
        synchronized (elements)
        {
            return elements.size();
        }
    }

    /**
     * Represents a <tt>CandidateHarvester</tt> as an element in a
     * <tt>CandidateHarvesterSet</tt>.
     */
    private static class CandidateHarvesterSetElement
    {
        /**
         * The indicator which determines whether
         * {@link CandidateHarvester#harvest(Component)} is to be called on
         * {@link #harvester}.
         */
        private boolean enabled = true;

        /**
         * The <tt>CandidateHarvester</tt> which is an element in a
         * <tt>CandidateHarvesterSet</tt>.
         */
        private final CandidateHarvester harvester;

        /**
         * Initializes a new <tt>CandidateHarvesterSetElement</tt> instance
         * which is to represent a specific <tt>CandidateHarvester</tt> as an
         * element in a <tt>CandidateHarvesterSet</tt>.
         *
         * @param harvester the <tt>CandidateHarvester</tt> which is to be
         * represented as an element in a <tt>CandidateHarvesterSet</tt> by the
         * new instance
         */
        public CandidateHarvesterSetElement(CandidateHarvester harvester)
        {
            this.harvester = harvester;
        }

        /**
         * Calls {@link CandidateHarvester#harvest(Component)} on the associated
         * <tt>CandidateHarvester</tt> if <tt>enabled</tt>.
         *
         * @param component the <tt>Component</tt> to gather candidates for
         */
        public void harvest(Component component)
        {
            if (isEnabled())
            {
                harvester.startHarvesting();
                Collection<LocalCandidate> candidates
                    = harvester.harvest(component);
                harvester.stopHarvesting();

                logger.info(
                        "End candidate harvest within "
                        + harvester.getHarvestingTime()
                        + " ms, for "
                        + harvester.getClass().getName()
                        + ", component: " + component.getComponentID());

                /*
                 * If the CandidateHarvester has not gathered any candidates, it
                 * is considered failed and will not be used again in order to
                 * not risk it slowing down the overall harvesting.
                 */
                if ((candidates == null) || candidates.isEmpty())
                    setEnabled(false);
            }
        }

        /**
         * Determines whether the associated <tt>CandidateHarvester</tt> is
         * considered to be the same as a specific <tt>CandidateHarvester</tt>.
         *
         * @param harvester the <tt>CandidateHarvester</tt> to be compared to
         * the associated <tt>CandidateHarvester</tt>
         * @return <tt>true</tt> if the associated <tt>CandidateHarvester</tt>
         * is considered to be the same as the specified <tt>harvester</tt>;
         * otherwise, <tt>false</tt>
         */
        public boolean harvesterEquals(CandidateHarvester harvester)
        {
            return this.harvester.equals(harvester);
        }

        /**
         * Gets the indicator which determines whether
         * {@link CandidateHarvester#harvest(Component)} is to be called on the
         * associated <tt>CandidateHarvester</tt>.
         *
         * @return <tt>true</tt> if
         * <tt>CandidateHarvester#harvest(Component)</tt> is to be called on the
         * associated <tt>CandidateHarvester</tt>; otherwise, <tt>false</tt>
         */
        public boolean isEnabled()
        {
            return enabled;
        }

        /**
         * Sets the indicator which determines whether
         * {@link CandidateHarvester#harvest(Component)} is to be called on the
         * associated <tt>CandidateHarvester</tt>.
         *
         * @param enabled <tt>true</tt> if
         * <tt>CandidateHarvester#harvest(Component)</tt> is to be called on the
         * associated <tt>CandidateHarvester</tt>; otherwise, <tt>false</tt>
         */
        public void setEnabled(boolean enabled)
        {
            logger.info("disabling harvester: " + harvester);
            this.enabled = enabled;
        }
    }
}
