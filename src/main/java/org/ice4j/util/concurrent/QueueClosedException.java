package org.ice4j.util.concurrent;

/**
 * Exception thrown when calling some function on a closed
 * {@link ClosableEvictingQueue}
 */
public class QueueClosedException
    extends IllegalStateException
{
    private static final long serialVersionUID = 1L;
}
