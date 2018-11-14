package org.ice4j.util;

import junit.framework.TestCase;
import org.ice4j.stunclient.ResponseSequenceServer;
import org.junit.Assert;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Test various aspects of {@link PacketQueue} implementation.
 */
public class PacketQueueTests
    extends TestCase
{
    /**
     * The <tt>Logger</tt> used by the <tt>PacketQueueTests</tt> class and
     * its instances for logging output.
     */
    private static final java.util.logging.Logger logger
        = Logger.getLogger(ResponseSequenceServer.class.getName());

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
            new PacketQueue.PacketHandler<Dummy>()
            {

                private long lastPacketHandledTimestampNanos = -1;

                @Override
                public boolean handlePacket(Dummy pkt)
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
            queue.add(new Dummy());
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

    private class Dummy {
    }

    private class DummyQueue extends PacketQueue<Dummy>
    {
        DummyQueue(int capacity, boolean copy, boolean enableStatistics,
            String id,
            PacketHandler<Dummy> packetHandler,
            ExecutorService executor)
        {
            super(capacity, copy, enableStatistics, id, packetHandler,
                executor);
        }

        @Override
        public byte[] getBuffer(Dummy pkt)
        {
            return null;
        }

        @Override
        public int getOffset(Dummy pkt)
        {
            return 0;
        }

        @Override
        public int getLength(Dummy pkt)
        {
            return 0;
        }

        @Override
        public Object getContext(Dummy pkt)
        {
            return null;
        }

        @Override
        protected Dummy createPacket(byte[] buf, int off, int len,
            Object context)
        {
            return new Dummy();
        }
    }
}