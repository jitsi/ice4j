/*
 * Copyright @ 2018 8x8, Inc.
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
     * The default <tt>ExecutorService</tt> to run <tt>AsyncQueueHandler</tt>
     * when there is no executor injected in constructor.
     */
    private final static ExecutorService sharedExecutor
        = Executors.newCachedThreadPool(
            new CustomizableThreadFactory(
                AsyncQueueHandler.class.getName() + "-executor-", true));

    /**
     * Executor service to run {@link #reader}, which asynchronously
     * invokes specified {@link #handler} on queued items.
     */
    private final ExecutorService executor;

    /**
     * An {@link BlockingQueue <T>} whose items read on separate thread and
     * processed by provided {@link #handler}.
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
     * Specifies the number of items allowed to be handled sequentially
     * without yielding control to executor's thread. Specifying positive
     * number allows implementation of cooperative multi-tasking
     * between different {@link AsyncQueueHandler<T>} sharing
     * same {@link ExecutorService}.
     */
    private final long maxSequentiallyHandledItems;

    /**
     * A flag which indicates if reading of {@link #queue} is allowed
     * to continue.
     */
    private final AtomicBoolean running = new AtomicBoolean();

    /**
     * Synchronization object of current instance state, in particular
     * used to resolve races between {@link #handleQueueItemsUntilEmpty()}
     * and {@link #reader} exit. In particular synchronization object used to
     * access to field {@link #readerFuture}.
     */
    private final Object syncRoot = new Object();

    /**
     * Stores <tt>Future</tt> of currently executing {@link #reader}
     */
    private Future<?> readerFuture;

    /**
     * Perpetually reads item from {@link #queue} and uses
     * {@link #handler} on each of them.
     */
    private final Runnable reader = new Runnable()
    {
        @Override
        public void run()
        {
            long sequentiallyHandledItems = 0;

            while (running.get())
            {
                if (maxSequentiallyHandledItems > 0 &&
                    sequentiallyHandledItems >= maxSequentiallyHandledItems)
                {
                    onYield();
                    return;
                }

                T item;

                synchronized (syncRoot)
                {
                    item = queue.poll();

                    if (item == null)
                    {
                        cancel(false);
                        return;
                    }
                }

                sequentiallyHandledItems++;

                try
                {
                    handler.handleItem(item);
                }
                catch (Throwable e)
                {
                    logger.warning("Failed to handle item: " + e);
                }
            }
        }
    };

    /**
     * Constructs instance of {@link AsyncQueueHandler<T>} which is capable of
     * asynchronous reading provided queue from thread borrowed from executor to
     * process items with provided handler.
     * @param queue thread-safe queue which holds items to process
     * @param handler an implementation of handler routine which will be
     * invoked per each item placed in the queue.
     * @param id optional identifier of current handler for debug purpose
     * @param executor optional executor service to borrow threads from
     */
    public AsyncQueueHandler(
        BlockingQueue<T> queue,
        Handler<T> handler,
        String id,
        ExecutorService executor)
    {
        this(queue, handler, id, executor, -1);
    }

    /**
     * Constructs instance of {@link AsyncQueueHandler<T>} which is capable of
     * asynchronous reading provided queue from thread borrowed from executor to
     * process items with provided handler.
     * @param queue thread-safe queue which holds items to process
     * @param handler an implementation of handler routine which will be
     * invoked per each item placed in the queue.
     * @param id optional identifier of current handler for debug purpose
     * @param executor optional executor service to borrow threads from
     * @param maxSequentiallyHandledItems maximum number of items sequentially
     * handled on thread borrowed from {@link #executor} before temporary
     * releasing thread and re-acquiring it from {@link #executor}.
     */
    public AsyncQueueHandler(
        BlockingQueue<T> queue,
        Handler<T> handler,
        String id,
        ExecutorService executor,
        long maxSequentiallyHandledItems)
    {
        if (queue == null)
        {
            throw new IllegalArgumentException("queue is null");
        }

        if (handler == null)
        {
            throw new IllegalArgumentException("handler is null");
        }

        this.executor = executor != null ? executor : sharedExecutor;
        this.queue = queue;
        this.handler = handler;
        this.id = id;
        this.maxSequentiallyHandledItems = maxSequentiallyHandledItems;
    }

    /**
     * Attempts to stop execution of {@link #reader} if running
     */
    public void cancel()
    {
        cancel(true);
    }

    /**
     * Checks if {@link #reader} is running on one of {@link #executor}
     * thread and if no submits execution of {@link #reader} on executor.
     */
    public void handleQueueItemsUntilEmpty()
    {
        synchronized (syncRoot)
        {
            if (readerFuture == null || readerFuture.isDone())
            {
                rescheduleReader();
            }
        }
    }

    /**
     * Invoked when execution of {@link #reader} is about to temporary
     * cancel and further execution need to be re-scheduled.
     */
    private void onYield()
    {
        if (logger.isLoggable(java.util.logging.Level.FINE))
        {
            logger.fine("Yielding AsyncQueueHandler with ID = " + id);
        }

        rescheduleReader();
    }

    /**
     * Attempts to cancel currently running reader.
     * @param mayInterruptIfRunning indicates if {@link #reader} allowed
     * to be interrupted if running
     */
    private void cancel(boolean mayInterruptIfRunning)
    {
        synchronized (syncRoot)
        {
            running.set(false);

            if (readerFuture != null)
            {
                readerFuture.cancel(mayInterruptIfRunning);
                readerFuture = null;
            }
        }
    }

    /**
     * Reschedules execution of {@link #reader} on {@link #executor}'s thread.
     */
    private void rescheduleReader()
    {
        synchronized (syncRoot)
        {
            running.set(true);
            readerFuture = executor.submit(reader);
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
    }
}
