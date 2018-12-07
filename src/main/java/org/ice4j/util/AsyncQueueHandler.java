/*
 * Copyright @ 2018 Jitsi.org
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

package org.ice4j.util;

import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.Logger; // Disambiguation

/**
 * Asynchronously reads items from provided {@link #queue} on separate thread
 * borrowed from {@link #executor} and process items with specified handler.
 * Thread is not blocked when queue is empty and returned back to
 * {@link #executor} pool. New or existing thread is borrowed from
 * {@link #executor} when queue is non empty and {@link #reader} is not
 * running
 *
 * @author Yura Yaroshevich
 */
public final class AsyncQueueHandler<T>
{
    /**
     * The {@link java.util.logging.Logger} used by the
     * {@link AsyncQueueHandler} class and its instances for logging output.
     */
    private static final java.util.logging.Logger logger
        = Logger.getLogger(AsyncQueueHandler.class.getName());

    /**
     * ScheduledExecutorService to implement delay during throttling in
     * <tt>AsyncQueueHandler</tt>
     */
    private final static ScheduledExecutorService delayTimer
        = Executors.newSingleThreadScheduledExecutor(
            new CustomizableThreadFactory(
                AsyncQueueHandler.class.getName() + "-timer-", true));

    /**
     * The default <tt>ExecutorService</tt> to run <tt>AsyncQueueHandler</tt>
     * when there is no executor injected in constructor.
     */
    private final static ExecutorService sharedExecutor
        = Executors.newCachedThreadPool(
            new CustomizableThreadFactory(
                AsyncQueueHandler.class.getName() + "-executor-", true));

    /**
     * Number of nanoseconds to consider queue is empty to exit reading loop in
     * borrowed thread.
     */
    private final static long emptyQueueTimeoutNanoseconds = 50;

    /**
     * Executor service to run <tt>AsyncQueueHandler</tt>, which asynchronously
     * invokes specified {@link #handler} on queued items.
     */
    private final ExecutorService executor;

    /**
     * An {@link BlockingQueue <T>} which will be read on separate thread.
     */
    private final BlockingQueue<T> queue;

    /**
     * The {@link Handler<T>} used to handle items read from
     * {@link #queue} by {@link #reader}.
     */
    private final Handler<T> handler;

    /**
     * An identifier of current reader which is used for debugging purpose.
     */
    private final String id;

    /**
     * A flag which indicates if reading of {@link #queue} should be
     * cancelled.
     */
    private final AtomicBoolean cancelled = new AtomicBoolean();

    /**
     * Synchronization object of current instance state, in particular
     * used to resolve races between {@link #handleQueueItemsUntilEmpty()}
     * and {@link #reader} exit. In particular synchronization object used to
     * access to field {@link #readerFuture} and {@link #delayedFuture}.
     */
    private final Object syncRoot = new Object();

    /**
     * Throttle calculator which is used for counting handled items and
     * computing necessary delay before processing next item when
     * throttling is enabled.
     */
    private final ThrottleCalculator<T> throttler;

    /**
     * Stores <tt>Future</tt> of currently executing {@link #reader}
     */
    private Future<?> readerFuture;

    /**
     * Stores <tt>ScheduledFuture</tt> of currently delayed
     * execution {@link #reader}
     */
    private ScheduledFuture<?> delayedFuture;

    /**
     * Perpetually reads item from {@link #queue} and uses
     * {@link #handler} on each of them.
     */
    private final Runnable reader = new Runnable()
    {
        @Override
        public void run()
        {
            final long maxSequentiallyHandledItems =
                handler.maxSequentiallyHandledItems();

            int sequentiallyHandledItems = 0;

            while (!cancelled.get())
            {
                T pkt;

                synchronized (syncRoot)
                {
                    long delay = throttler.getDelayNanos();
                    if (delay > 0)
                    {
                        onDelay(delay, TimeUnit.NANOSECONDS);
                        return;
                    }

                    if (maxSequentiallyHandledItems > 0 &&
                        sequentiallyHandledItems >= maxSequentiallyHandledItems)
                    {
                        /*
                        All instances of AsyncQueueHandler executed on
                        single shared instance of ExecutorService to better
                        use existing threads and to reduce number of idle
                        threads when reader's queue is empty.

                        Having limited number of threads to execute might
                        lead to other problem, when queue is always
                        non-empty reader will keep running, while other
                        readers might suffer from execution starvation. One
                        way to solve this, is to to artificially interrupt
                        current reader execution and pump it via internal
                        executor's queue.
                        */
                        onYield();
                        return;
                    }

                    try
                    {
                        // It is observed that giving very small poll timeout,
                        // up to hundred nanoseconds, compared to not
                        // timeout at all has about 5-10% better
                        // performance in micro-benchmark scenarios.
                        pkt = queue.poll(
                            emptyQueueTimeoutNanoseconds, TimeUnit.NANOSECONDS);
                    }
                    catch (InterruptedException e)
                    {
                        pkt = null;
                    }

                    if (pkt == null)
                    {
                        cancel(false);
                        return;
                    }
                }

                sequentiallyHandledItems++;
                throttler.notifyItemHandled();

                try
                {
                    handler.handleItem(pkt);
                }
                catch (Throwable e)
                {
                    logger.warning("Failed to handle item: " + e);
                }
            }
        }
    };

    /**
     * Runnable which is scheduled with delay to perform actual
     * scheduling of {@link #reader} execution.
     */
    private final Runnable delayedSchedule = new Runnable()
    {
        @Override
        public void run()
        {
            synchronized (syncRoot)
            {
                delayedFuture = null;
            }
            handleQueueItemsUntilEmpty();
        }
    };

    /**
     * Constucts instance of {@link AsyncQueueHandler<T>} which is capable of
     * asyncronous reading provided queue from thread borrowed from executor to
     * process items with provided handler.
     * @param queue host queue which holds items to process
     * @param handler an implementation of handler routine which will be
     *                invoked per each item placed in the queue.
     * @param id optional identifier of current handler for debug purpose
     * @param executor optional executor service to borrow threads from
     */
    public AsyncQueueHandler(
        BlockingQueue<T> queue,
        Handler<T> handler,
        String id,
        ExecutorService executor)
    {
        this.executor = executor != null ? executor : sharedExecutor;
        this.queue = queue;
        this.handler = handler;
        this.id = id;
        this.throttler = new ThrottleCalculator<>(handler);
    }

    /**
     * Attempts to stop execution of {@link #reader} if running
     */
    public void cancel()
    {
        cancelled.set(true);

        synchronized (syncRoot)
        {
            cancel(true);
        }
    }

    /**
     * Checks if {@link #reader} is running on one of {@link #executor}
     * thread and if no submits execution of {@link #reader} on executor.
     */
    public void handleQueueItemsUntilEmpty()
    {
        if (cancelled.get())
        {
            return;
        }

        if (handler == null)
        {
            logger.warning("No handler set, the reading will not start.");
            return;
        }

        synchronized (syncRoot)
        {
            if ((readerFuture == null || readerFuture.isDone())
                && (delayedFuture == null || delayedFuture.isDone()))
            {
                readerFuture = executor.submit(reader);
            }
        }
    }

    /**
     * Invoked when execution of {@link #reader} is about to temporary
     * cancel and further execution need to be re-scheduled.
     * Assuming called when lock on {@link #syncRoot} is already taken.
     */
    private void onYield()
    {
        logger.fine("Yielding AsyncQueueHandler associated with "
            + "AsyncQueueHandler with ID = " + id);
        cancel(false);
        readerFuture = executor.submit(reader);
    }

    /**
     * Invoked when next execution of {@link #reader} should be delayed.
     * Assuming called when lock on {@link #syncRoot} is already taken.
     * @param delay the time from now to delay execution
     * @param unit the time unit of the delay parameter
     */
    private void onDelay(long delay, TimeUnit unit)
    {
        logger.fine("Delaying AsyncQueueHandler associated with "
            + "AsyncQueueHandler with ID = " + id + " for "
            + unit.toNanos(delay) + "us");
        cancel(false);
        delayedFuture = delayTimer.schedule(delayedSchedule, delay, unit);
    }

    /**
     * Attempts to cancel currently running reader. Assuming called when
     * lock on {@link #syncRoot} is already taken
     * @param mayInterruptIfRunning indicates if {@link #reader} allowed
     * to be interrupted if running
     */
    private void cancel(boolean mayInterruptIfRunning)
    {
        if (delayedFuture != null)
        {
            delayedFuture.cancel(mayInterruptIfRunning);
            delayedFuture = null;
        }

        if (readerFuture != null)
        {
            readerFuture.cancel(mayInterruptIfRunning);
            readerFuture = null;
        }
    }

    /**
     * A simple interface to handle enqueued {@link T} items.
     * @param <T> the type of the item.
     */
    public interface Handler<T>
    {
        /**
         * Does something with an item.
         * @param item the item to do something with.
         */
        void handleItem(T item);

        /**
         * Specifies max number {@link #handleItem(T)} invocation
         * per {@link #perNanos()}
         * @return positive number of allowed handled items in case of
         * throttling must be enabled.
         */
        default long maxHandledItems() {
            return -1;
        }

        /**
         * Specifies time interval in nanoseconds for {@link #maxHandledItems()}
         * @return positive nanoseconds count in case of throttling must be
         * enabled.
         */
        default long perNanos() {
            return -1;
        }

        /**
         * Specifies the number of items allowed to be handled sequentially
         * without yielding control to executor's thread. Specifying positive
         * number will allow other possible queues sharing same
         * {@link ExecutorService} to process their items.
         * @return positive value to specify max number of sequentially handled
         * items which allows implementation of cooperative multi-tasking
         * between different {@link AsyncQueueHandler<T>} sharing
         * same {@link ExecutorService}.
         */
        default long maxSequentiallyHandledItems()
        {
            return -1;
        }
    }

    /**
     * Helper class to calculate throttle delay when throttling is enabled.
     */
    private static final class ThrottleCalculator<T>
    {
        /**
         * The number of {@link T}s already processed during the current
         * <tt>perNanos</tt> interval.
         */
        private long itemsHandledWithinInterval = 0;

        /**
         * The time stamp in nanoseconds of the start of the current
         * <tt>perNanos</tt> interval.
         */
        private long intervalStartTimeNanos = 0;

        /**
         * {@link Handler <T>} instance which provide throttling
         * configuration
         */
        private final Handler<T> handler;

        ThrottleCalculator(Handler<T> handler)
        {
            if (handler == null)
            {
                throw new IllegalArgumentException("handler must not be null");
            }
            this.handler = handler;
        }

        /**
         * Calculate necessary delay based current time and number of items
         * processed during current time interval
         * @return 0 in case delay is not necessary or delay value in nanos
         */
        long getDelayNanos()
        {
            final long perNanos = handler.perNanos();
            final long maxHandledItems = handler.maxHandledItems();

            if (perNanos > 0 && maxHandledItems > 0)
            {
                final long now = System.nanoTime();
                final long nanosRemainingTime = now - intervalStartTimeNanos;

                if (nanosRemainingTime >= perNanos)
                {
                    intervalStartTimeNanos = now;
                    itemsHandledWithinInterval = 0;
                }
                else if (itemsHandledWithinInterval >= maxHandledItems)
                {
                    return nanosRemainingTime;
                }
            }
            return 0;
        }

        /**
         * Count number of handled items
         */
        void notifyItemHandled()
        {
            itemsHandledWithinInterval++;
        }
    }
}
