package org.ice4j.util;

import org.junit.*;

import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;  // Disambiguation

/**
 * Contains test for checking performance aspects of various
 * PacketQueue configuration
 *
 * @author Yura Yaroshevich
 */
@Ignore("Check only performance aspect of PacketQueue")
public class PacketQueueBenchmarkTests
{
    /**
     * The <tt>Logger</tt> used by the <tt>PacketQueueBenchmarkTests</tt> class
     * and its instances for logging output.
     */
    private static final java.util.logging.Logger logger
        = Logger.getLogger(PacketQueueBenchmarkTests.class.getName());

    /**
     * Number of iteration to run benchmark and compute
     * average execution time.
     */
    private final int numberOfBenchmarkIterations = 100;

    /**
     * Simulates number of concurrent existing PacketQueue instances inside
     * application. In case of JVB it is linear to number of connected peers
     * to JVB instance.
     */
    private final int numberOfQueues = 800;

    /**
     * Simulates number of messages processed via single PacketQueue
     */
    private final int numberOfItemsInQueue = 1000;

    /**
     * Simulates the computation "weight" of single item processed by
     * PacketQueue
     */
    private final int singleQueueItemProcessingWeight = 300;

    @Test
    public void testMultiplePacketQueueThroughputWithThreadPerQueue()
        throws Exception
    {
        /*
         * This test roughly simulates initial implementation of PacketQueue
         * when each PacketQueue instance has it's own processing thread
         */
        measureBenchmark("ThreadPerQueuePool", () -> {
            final ExecutorService executorService
                = Executors.newFixedThreadPool(numberOfQueues);
            Duration duration = runBenchmark(
                executorService,
                -1 /* Disable cooperative multi-tasking mode,
                 which is not relevant when each queue has it's own processing
                 thread*/);
            executorService.shutdownNow();
            return duration;
        });
    }

    @Test
    public void testMultiplePacketQueueThroughputWithCachedThreadPerQueue()
        throws Exception
    {
        /*
         * This test is slight modification of previous test, but now threads
         * are re-used between PacketQueues when possible.
         */
        measureBenchmark("CachedThreadPerQueuePool", () -> {
            final ExecutorService executorService
                = Executors.newCachedThreadPool();
            Duration duration = runBenchmark(
                executorService,
                -1 /* Disable cooperative multi-tasking mode,
                 which is not relevant when each queue has it's own processing
                 thread*/);
            executorService.shutdownNow();
            return duration;
        });
    }

    @Test
    public void testMultiplePacketQueueThroughputWithFixedSizePool()
        throws Exception
    {
        /*
         * This test creates pool with limited number of threads, all
         * PacketQueues share threads in cooperative multi-tasking mode.
         */
        measureBenchmark("FixedSizeCPUBoundPool", () -> {
            final ExecutorService executorService
                = Executors.newFixedThreadPool(
                    Runtime.getRuntime().availableProcessors());
            Duration duration = runBenchmark(
                executorService,
                50 /* Because queues will share executor
                with limited number of threads, so configure cooperative
                multi-tasking mode*/);
            executorService.shutdownNow();
            return duration;
        });
    }

    @Test
    public void testMultiplePacketQueueThroughputWithForkJoinPool()
        throws Exception
    {
        /*
         * This test check proposed change to PacketQueue implementation when
         * all created PacketQueues share single ExecutorService with limited
         * number of threads. Execution starvation is resolved by implementing
         * cooperative multi-tasking when each PacketQueue release it's thread
         * borrowed for ExecutorService so other PacketQueue instances can
         * proceed with execution.
         * This modification has noticeable better performance when executed
         * on system which is already loaded by other concurrent tasks.
         */
        measureBenchmark("ForkJoinCPUBoundPool", () -> {
            final ExecutorService executorService
                = Executors.newWorkStealingPool(
                    Runtime.getRuntime().availableProcessors());
            Duration duration = runBenchmark(
                executorService,
                50 /* Because queues will share executor
                with limited number of threads, so configure cooperative
                multi-tasking mode*/);
            executorService.shutdownNow();
            return duration;
        });
    }

    private Duration runBenchmark(
        final ExecutorService executor,
        final long maxSequentiallyPackets)
        throws InterruptedException
    {
        final CountDownLatch completionGuard
            = new CountDownLatch(numberOfItemsInQueue * numberOfQueues);

        final ArrayList<DummyQueue> queues = new ArrayList<>();
        for (int i = 0; i < numberOfQueues; i++) {
            queues.add(new DummyQueue(
                numberOfItemsInQueue,
                new PacketQueue.PacketHandler<DummyQueue.Dummy>()
                {
                    @Override
                    public boolean handlePacket(DummyQueue.Dummy pkt)
                    {
                        double result = 0;
                        // some dummy computationally exp
                        final int end
                            = pkt.id + singleQueueItemProcessingWeight;

                        for (int i = pkt.id; i < end; i++)
                        {
                            result += Math.log(Math.sqrt(i));
                        }
                        completionGuard.countDown();
                        return result > 0;
                    }

                    @Override
                    public long maxSequentiallyProcessedPackets()
                    {
                        return maxSequentiallyPackets;
                    }
                },
                executor));
        }

        long startTime = System.nanoTime();

        for (DummyQueue queue : queues)
        {
            for (int i = 0; i < numberOfItemsInQueue; i++)
            {
                queue.add(new DummyQueue.Dummy());
            }
        }

        completionGuard.await();
        long endTime = System.nanoTime();

        for (DummyQueue queue : queues) {
            queue.close();
        }

        return Duration.ofNanos(endTime - startTime);
    }

    private void measureBenchmark(String name, Callable<Duration> runWithDuration) throws Exception
    {
        final ArrayList<Duration> experimentDuration = new ArrayList<>();
        for (int i = 0; i < 1 + numberOfBenchmarkIterations; i++)
        {
            System.gc();
            final Duration duration = runWithDuration.call();
            if (i != 0)
            {
                experimentDuration.add(duration);
            }
        }

        long totalNanos = 0;
        for (Duration duration : experimentDuration)
        {
            totalNanos += duration.toNanos();
        }
        long averageNanos = totalNanos / experimentDuration.size();

        long sumSquares = 0;

        for (Duration duration : experimentDuration)
        {
            long diff = Math.abs(duration.toNanos() - averageNanos);
            sumSquares = diff * diff;
        }

        double stdDev
            = Math.sqrt((1.0 / (experimentDuration.size() - 1)) * sumSquares);

        System.out.println(name
            + " : avg = " + TimeUnit.NANOSECONDS.toMillis(averageNanos) + " ms"
            + ", std_dev = " + TimeUnit.NANOSECONDS.toMillis((long)stdDev) + " ms");
    }
}
