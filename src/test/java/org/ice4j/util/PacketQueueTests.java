package org.ice4j.util;

import org.junit.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.*;
import java.util.logging.Logger; // Disambiguation

/**
 * Test various aspects of {@link PacketQueue} implementation.
 */
public class PacketQueueTests
{
    /**
     * The <tt>Logger</tt> used by the <tt>PacketQueueTests</tt> class and
     * its instances for logging output.
     */
    private static final java.util.logging.Logger logger
        = Logger.getLogger(PacketQueueTests.class.getName());

    @Test
    public void testThrottlingHandlePacket() throws InterruptedException
    {
        final long minIntervalBetweenPacketsNanos =
            TimeUnit.MILLISECONDS.toNanos(10);

        final int itemsCount = 100;

        final CountDownLatch itemsProcessed = new CountDownLatch(itemsCount);

        final AtomicBoolean allItemsWereThrottled = new AtomicBoolean(true);

        final DummyQueue queue = new DummyQueue(
            itemsCount,
            false,
            false,
            "dummy",
            new PacketQueue.PacketHandler<DummyQueue.Dummy>()
            {
                private long lastPacketHandledTimestampNanos = -1;

                @Override
                public boolean handlePacket(DummyQueue.Dummy pkt)
                {
                    final long now = System.nanoTime();

                    if (lastPacketHandledTimestampNanos != -1)
                    {
                        final long durationSinceLastPacketNanos
                            = now - lastPacketHandledTimestampNanos;

                        final boolean isThrottled
                            = durationSinceLastPacketNanos
                                >= minIntervalBetweenPacketsNanos;

                        allItemsWereThrottled.set(
                            allItemsWereThrottled.get() && isThrottled);

                        if (!isThrottled)
                        {
                            logger.log(Level.SEVERE,
                                "Throttling was not properly applied "
                            + "between packets processing. Current packet "
                            + "timestamp is " + now + "us, previous packet "
                            + "timestamp is " + lastPacketHandledTimestampNanos
                            + "us, time interval between is "
                            + durationSinceLastPacketNanos
                            + "us, expected at least " + perNanos() + "us "
                            + "between " + maxPackets() + " items");
                        }
                    }

                    itemsProcessed.countDown();

                    lastPacketHandledTimestampNanos = now;
                    return true;
                }

                @Override
                public long maxPackets()
                {
                    // for easier computation and error message use 1
                    return 1;
                }

                @Override
                public long perNanos()
                {
                    // no more than 1 packet per 100 ms
                    return minIntervalBetweenPacketsNanos;
                }
            }, null);

        for (int i = 0; i < itemsCount; i++)
        {
            queue.add(new DummyQueue.Dummy());
            Thread.sleep(TimeUnit.NANOSECONDS.toMillis(
                minIntervalBetweenPacketsNanos / 10));
        }

        itemsProcessed.await(
            minIntervalBetweenPacketsNanos * itemsCount,
            TimeUnit.NANOSECONDS);

        Assert.assertTrue("Expect throttling was done by PacketQueue "
            + " when maxPackets() and perNanos() specified ",
            allItemsWereThrottled.get());
    }

    @Test
    public void testAddingItemToQueueNotifiesBlockedThreadsImmediately()
        throws Exception
    {
        final DummyQueue dummyQueue = new DummyQueue(10);
        final CompletableFuture<DummyQueue.Dummy> dummyItem =
            CompletableFuture.supplyAsync(dummyQueue::get);

        try
        {
            // This block surrounded with try/catch necessary to ensure that
            // thread calling PacketQueue::get blocked before items is added
            // to queue. Giving 50ms for CompletableFuture to stuck on get.
            final DummyQueue.Dummy nullDummy
                = dummyItem.get(50, TimeUnit.MILLISECONDS);
            Assert.fail("There is no items in queue, must not be here");
        }
        catch (TimeoutException e)
        {
            // no item is added during 50 ms into queue.
        }

        final DummyQueue.Dummy pushedItem = new DummyQueue.Dummy();

        dummyQueue.add(pushedItem);

        try
        {
            // checks that thread stuck in PacketQueue::get notified
            // "immediately" when item added to queue. Giving 1 ms for
            // CompletableFuture to transit to completed state.
            final DummyQueue.Dummy poppedItem = dummyItem.get(
                1, TimeUnit.MILLISECONDS);
            Assert.assertEquals(pushedItem, poppedItem);
        }
        catch (TimeoutException e)
        {
            Assert.fail("Expected that blocked thread notified immediately "
                + "about item added to queue");
        }
    }

    @Test
    public void testClosingQueueImmediatelyNotifiesAllThreadsBlockedOnGet()
        throws Exception
    {
        final DummyQueue dummyQueue = new DummyQueue(10);
        final ArrayList<CompletableFuture<DummyQueue.Dummy>>
            dummyItems = new ArrayList<>();
        for (int i = 0; i < ForkJoinPool.getCommonPoolParallelism(); i++)
        {
            dummyItems.add(CompletableFuture.supplyAsync(dummyQueue::get));
        }

        for (CompletableFuture<DummyQueue.Dummy> dummyItem : dummyItems)
        {
            try
            {
                // This block surrounded with try/catch necessary to ensure that
                // thread calling PacketQueue::get blocked before items is added
                // to queue. Giving 50ms for CompletableFuture to stuck on get.
                final DummyQueue.Dummy nullDummy
                    = dummyItem.get(50, TimeUnit.MILLISECONDS);
                Assert.fail("There is no items in queue, must not be here");
            }
            catch (TimeoutException e)
            {
                // no item is added during 50 ms into queue.
            }
        }

        dummyQueue.close();

        for (CompletableFuture<DummyQueue.Dummy> dummyItem : dummyItems)
        {
            try
            {
                // checks that thread stuck in PacketQueue::get notified
                // "immediately" when PacketQueue is stopped. Giving 1 ms for
                // CompletableFuture to transit to completed state.
                final DummyQueue.Dummy poppedItem = dummyItem.get(
                    1, TimeUnit.MILLISECONDS);
                Assert.assertNull("When PacketQueue is closed "
                    + "null must be returned", poppedItem);
            }
            catch (TimeoutException e)
            {
                Assert.fail("Expected that blocked thread notified immediately "
                    + "when queue is stopped");
            }
        }
    }
}