package org.ice4j.util;

import org.junit.*;

import java.time.*;
import java.util.concurrent.*;

/**
 * Test various aspects of {@link PeriodicRunnable} implementation.
 *
 * @author Yura Yaroshevich
 */
public class PeriodicRunnableTests
{
    @Test
    public void scheduleExecutesSpecifiedRunnableMultipleTimes()
        throws InterruptedException
    {
        final ScheduledExecutorService timer
            = Executors.newSingleThreadScheduledExecutor();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final CountDownLatch latch = new CountDownLatch(10);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(100),
            latch::countDown);

        scheduledRunnable.schedule();

        // Give 20 extra milliseconds to avoid possible failures due to
        // slight timer inaccuracy
        latch.await(1020, TimeUnit.MILLISECONDS);
        Assert.assertEquals(0, latch.getCount());

        scheduledRunnable.cancel();
        executor.shutdownNow();
        timer.shutdownNow();
    }

    @Test
    public void scheduleWithNegativeDelayDoesNotExecuteRunnable()
        throws InterruptedException
    {
        final ScheduledExecutorService timer
            = Executors.newSingleThreadScheduledExecutor();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final CountDownLatch latch = new CountDownLatch(1);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(-1),
            latch::countDown);

        scheduledRunnable.schedule();

        latch.await(1000, TimeUnit.MILLISECONDS);
        Assert.assertEquals(1, latch.getCount());

        scheduledRunnable.cancel();
        executor.shutdownNow();
        timer.shutdownNow();
    }

    @Test
    public void negativeDelayStopsFurtherExecution()
        throws InterruptedException
    {
        final ScheduledExecutorService timer
            = Executors.newSingleThreadScheduledExecutor();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final CountDownLatch latch = new CountDownLatch(5);
        final PeriodicRunnable scheduledRunnable =
            new PeriodicRunnable(timer, executor)
            {
                @Override
                protected Duration getDelayUntilNextRun()
                {
                    return Duration.ofMillis(latch.getCount() > 1 ? 100 : -1);
                }

                @Override
                protected void run()
                {
                    latch.countDown();
                }
            };

        scheduledRunnable.schedule();

        latch.await(1000, TimeUnit.MILLISECONDS);
        Assert.assertEquals(1, latch.getCount());

        scheduledRunnable.cancel();
        executor.shutdownNow();
        timer.shutdownNow();
    }

    @Test
    public void cancelStopFurtherExecution()
        throws InterruptedException
    {
        final ScheduledExecutorService timer
            = Executors.newSingleThreadScheduledExecutor();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final CountDownLatch latch = new CountDownLatch(2);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(500),
            latch::countDown);

        scheduledRunnable.schedule();
        latch.await(520, TimeUnit.MILLISECONDS);

        // Check runnable executed once
        Assert.assertEquals(1, latch.getCount());

        scheduledRunnable.cancel();

        latch.await(1000, TimeUnit.MILLISECONDS);
        // Check runnable was not executed after cancel.
        Assert.assertEquals(1, latch.getCount());

        scheduledRunnable.cancel();
        executor.shutdownNow();
        timer.shutdownNow();
    }

    @Test
    public void scheduleExecuteRunnableIfPreviouslyCancelled()
        throws InterruptedException
    {
        final ScheduledExecutorService timer
            = Executors.newSingleThreadScheduledExecutor();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final CountDownLatch latch = new CountDownLatch(5);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(200),
            latch::countDown);

        scheduledRunnable.schedule();
        latch.await(220, TimeUnit.MILLISECONDS);

        // Check runnable executed once
        Assert.assertEquals(4, latch.getCount());

        scheduledRunnable.cancel();

        latch.await(1000, TimeUnit.MILLISECONDS);
        // Check runnable was not executed after cancel.
        Assert.assertEquals(4, latch.getCount());

        // Schedule again
        scheduledRunnable.schedule();
        latch.await(1000, TimeUnit.MILLISECONDS);
        Assert.assertEquals(0, latch.getCount());

        scheduledRunnable.cancel();
        executor.shutdownNow();
        timer.shutdownNow();
    }
}
