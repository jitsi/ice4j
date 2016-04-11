/*
 * Copyright @ 2016 Atlassian Pty Ltd
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

/*
 * Based on:
 * http://gee.cs.oswego.edu/cgi-bin/viewcvs.cgi/jsr166/src/jdk7/java/util/concurrent/ArrayBlockingQueue.java?revision=1.7
 * http://gee.cs.oswego.edu/dl/concurrency-interest/index.html
 *
 * Original comment:
 *
 * Written by Doug Lea with assistance from members of JCP JSR-166
 * Expert Group and released to the public domain, as explained at
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

package org.ice4j.util.concurrent;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded queue, closable, optionally evicting, backed by an
 * array.  This queue orders elements FIFO (first-in-first-out).  The
 * <em>head</em> of the queue is that element that has been on the
 * queue the longest time.  The <em>tail</em> of the queue is that
 * element that has been on the queue the shortest time. New elements
 * are inserted at the tail of the queue, and the queue retrieval
 * operations obtain elements at the head of the queue.
 *
 * <p>This is a classic &quot;bounded buffer&quot;, in which a
 * fixed-sized array holds elements inserted by producers and
 * extracted by consumers.  Once created, the capacity cannot be
 * changed.
 *
 * <p>This class supports an optional fairness policy for ordering
 * waiting producer and consumer threads.  By default, this ordering
 * is not guaranteed. However, a queue constructed with fairness set
 * to {@code true} grants threads access in FIFO order. Fairness
 * generally decreases throughput but reduces variability and avoids
 * starvation.
 *
 * <p>This class supports evicting with {@link insert} function.
 * Instead of blocking (with {@link put}) or failing (with {@link offer})
 * to insert when this queue is full, we can drop the head ({@link insert}).
 *
 * <p>This class support closing with {@link close} function. When this queue
 * is closed read and write operations throw {@link QueueClosedException}
 *
 * @author Doug Lea
 * @author Etienne Champetier
 * @param <E> the type of elements held in this queue
 */
public class ClosableEvictingQueue<E> {

    /** The queued items */
    final Object[] items;

    /** items index for next take, poll, peek or remove */
    int takeIndex;

    /** items index for next put, offer, or add */
    int putIndex;

    /** Number of elements in the queue */
    int count;

    /** is this queue closed */
    boolean closed = false;

    /*
     * Concurrency control uses the classic two-condition algorithm
     * found in any textbook.
     */

    /** Main lock guarding all access */
    final ReentrantLock lock;

    /** Condition for waiting takes */
    private final Condition notEmpty;

    /** Condition for waiting puts */
    private final Condition notFull;

    // Internal helper methods

    /**
     * Returns item at index i.
     */
    @SuppressWarnings("unchecked")
    final E itemAt(int i) {
        return (E) items[i];
    }

    /**
     * Inserts element at current put position, advances, and signals.
     * Call only when holding lock.
     */
    private void enqueue(E x) {
        // assert lock.getHoldCount() == 1;
        // assert items[putIndex] == null;
        final Object[] items = this.items;
        items[putIndex] = x;
        if (++putIndex == items.length) putIndex = 0;
        count++;
        notEmpty.signal();
    }

    /**
     * Extracts element at current take position, advances, and signals.
     * Call only when holding lock.
     */
    private E dequeue() {
        // assert lock.getHoldCount() == 1;
        // assert items[takeIndex] != null;
        final Object[] items = this.items;
        @SuppressWarnings("unchecked")
        E x = (E) items[takeIndex];
        items[takeIndex] = null;
        if (++takeIndex == items.length) takeIndex = 0;
        count--;
        notFull.signal();
        return x;
    }

    /**
     * Creates an {@code ClosableEvictingQueue} with the given (fixed)
     * capacity and default access policy.
     *
     * @param capacity the capacity of this queue
     * @throws IllegalArgumentException if {@code capacity < 1}
     */
    public ClosableEvictingQueue(int capacity) {
        this(capacity, false);
    }

    /**
     * Creates an {@code ClosableEvictingQueue} with the given (fixed)
     * capacity and the specified access policy.
     *
     * @param capacity the capacity of this queue
     * @param fair if {@code true} then queue accesses for threads blocked
     *        on insertion or removal, are processed in FIFO order;
     *        if {@code false} the access order is unspecified.
     * @throws IllegalArgumentException if {@code capacity < 1}
     */
    public ClosableEvictingQueue(int capacity, boolean fair) {
        if (capacity <= 0)
            throw new IllegalArgumentException();
        this.items = new Object[capacity];
        lock = new ReentrantLock(fair);
        notEmpty = lock.newCondition();
        notFull =  lock.newCondition();
    }

    /**
     * Inserts the specified element at the tail of this queue if it is
     * possible to do so immediately without exceeding the queue's capacity,
     * returning {@code true} upon success and {@code false} if this queue
     * is full.
     *
     * @throws NullPointerException {@inheritDoc}
     * @throws QueueClosedException - if queue is closed
     */
    public boolean offer(E e) {
        if (e == null) throw new NullPointerException();
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            if (closed)
                throw new QueueClosedException();
            if (count == items.length)
                return false;
            else {
                enqueue(e);
                return true;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Inserts the specified element at the tail of this queue. If this queue is
     * full we will return the element at the head of this queue, else null.
     *
     * @see offer for non evicting/dropping version
     * @return null if this queue was not full, else head
     * @throws NullPointerException {@inheritDoc}
     * @throws QueueClosedException - if queue is closed
     */
    public E insert(E e) {
        if (e == null) throw new NullPointerException();
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            if (closed)
                throw new QueueClosedException();
            if (count == items.length) {
                /*
                 * we could call dequeue & enqueue here but that would
                 * unecesserally signal (notEmpty, notFull)
                 */
                final Object[] items = this.items;
                /*
                 * dequeue without signaling
                 */
                @SuppressWarnings("unchecked")
                E drop = (E) items[takeIndex];
                if (++takeIndex == items.length) takeIndex = 0;
                /*
                 * enqueue without signaling
                 */
                items[putIndex] = e;
                if (++putIndex == items.length) putIndex = 0;

                return drop;
            } else {
                enqueue(e);
                return null;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Inserts the specified element at the tail of this queue, waiting
     * for space to become available if the queue is full.
     *
     * @throws InterruptedException {@inheritDoc}
     * @throws NullPointerException {@inheritDoc}
     * @throws QueueClosedException - if queue is closed
     */
    public void put(E e) throws InterruptedException, QueueClosedException {
        if (e == null) throw new NullPointerException();
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            while (true) {
                if (closed)
                    throw new QueueClosedException();
                if (count != items.length)
                    break;
                notFull.await();
            }
            enqueue(e);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Inserts the specified element at the tail of this queue, waiting
     * up to the specified wait time for space to become available if
     * the queue is full.
     *
     * @throws InterruptedException {@inheritDoc}
     * @throws NullPointerException {@inheritDoc}
     * @throws QueueClosedException - if queue is closed
     */
    public boolean offer(E e, long timeout, TimeUnit unit)
        throws InterruptedException, QueueClosedException {

        if (e == null) throw new NullPointerException();
        long nanos = unit.toNanos(timeout);
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            while (true) {
                if (closed)
                    throw new QueueClosedException();
                if (count != items.length)
                    break;
                if (nanos <= 0)
                    return false;
                nanos = notFull.awaitNanos(nanos);
            }
            enqueue(e);
            return true;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Retrieves and removes the head of this queue, or returns null if this
     * queue is empty.
     *
     * @return the head of this queue, or null if this queue is empty
     * @throws QueueClosedException - if queue is closed
     */
    public E poll() throws QueueClosedException {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            if (closed)
                throw new QueueClosedException();
            return (count == 0) ? null : dequeue();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Retrieves and removes the head of this queue, waiting if necessary until
     * an element becomes available.
     *
     * @return the head of this queue
     * @throws InterruptedException - {@inheritDoc}
     * @throws QueueClosedException - if queue is closed
     */
    public E take() throws InterruptedException, QueueClosedException {
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            while (true) {
                if (closed)
                    throw new QueueClosedException();
                if (count != 0)
                    break;
                notEmpty.await();
            }
            return dequeue();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Retrieves and removes the head of this queue, waiting up to the specified
     * wait time if necessary for an element to become available.
     *
     * @param timeout - how long to wait before giving up, in units of unit
     * @param unit - a TimeUnit determining how to interpret the timeout
     *            parameter
     * @return the head of this queue, or null if the specified waiting time
     *         elapses before an element is available
     * @throws InterruptedException - {@inheritDoc}
     * @throws QueueClosedException - if queue is closed
     */
    public E poll(long timeout, TimeUnit unit)
        throws InterruptedException, QueueClosedException {

        long nanos = unit.toNanos(timeout);
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            while (true) {
                if (closed)
                    throw new QueueClosedException();
                if (count != 0)
                    break;
                if (nanos <= 0)
                    return null;
                nanos = notEmpty.awaitNanos(nanos);
            }
            return dequeue();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Retrieves, but does not remove, the head of this queue, or returns null
     * if this queue is empty.
     *
     * @return the head of this queue, or null if this queue is empty
     * @throws QueueClosedException - if queue is closed
     */
    public E peek() throws QueueClosedException {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            if (closed)
                throw new QueueClosedException();
            return itemAt(takeIndex); // null when queue is empty
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the number of elements in this queue.
     *
     * @return the number of elements in this queue
     */
    public int size() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            return count;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the number of additional elements that this queue can ideally (in
     * the absence of memory or resource constraints) accept without blocking or
     * evicting. This is always equal to the initial capacity of this queue less
     * the current {@code size} of this queue.
     */
    public int remainingCapacity() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            return items.length - count;
        } finally {
            lock.unlock();
        }
    }

    public String toString() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            int k = count;
            if (k == 0)
                return "[]";

            final Object[] items = this.items;
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            for (int i = takeIndex; ; ) {
                Object e = items[i];
                sb.append(e == this ? "(this Collection)" : e);
                if (--k == 0)
                    return sb.append(']').toString();
                sb.append(',').append(' ');
                if (++i == items.length) i = 0;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically removes all of the elements from this queue.
     * The queue will be empty after this call returns.
     */
    public void clear() {
        final Object[] items = this.items;
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            int k = count;
            if (k > 0) {
                final int putIndex = this.putIndex;
                int i = takeIndex;
                do {
                    items[i] = null;
                    if (++i == items.length) i = 0;
                } while (i != putIndex);
                takeIndex = putIndex;
                count = 0;
                for (; k > 0 && lock.hasWaiters(notFull); k--)
                    notFull.signal();
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Atomically close the queue and drop remaining items.
     * This also wake up all waiting thread.
     */
    public void close() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            if (closed)
                return;
            //Close the queue
            closed = true;
            //Drop current items
            final Object[] items = this.items;
            for (int i=0; i < items.length; i++)
                items[i] = null;
            takeIndex = putIndex = count = 0;

            //Wake up every waiting thread
            notFull.signalAll();
            notEmpty.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Return whether this queue is closed or not
     */
    public boolean isClosed() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            return closed;
        } finally {
            lock.unlock();
        }
    }

}
