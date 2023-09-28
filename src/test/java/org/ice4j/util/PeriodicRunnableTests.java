package org.ice4j.util;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.*;
import java.util.concurrent.*;
import org.jitsi.utils.concurrent.*;
import org.junit.jupiter.api.*;

/**
 * Test various aspects of {@link PeriodicRunnable} implementation.
 *
 * @author Yura Yaroshevich
 */
public class PeriodicRunnableTests
{
    private FakeScheduledExecutorService timer;
    private ExecutorService executor;

    @BeforeEach
    void beforeEach()
    {
        timer = new FakeScheduledExecutorService();
        executor = mock(ExecutorService.class);
        when(executor.submit(any(Runnable.class))).thenAnswer(a ->
        {
            ((Runnable)a.getArgument(0)).run();
            return CompletableFuture.completedFuture(null);
        });
    }

    @Test
    public void scheduleExecutesSpecifiedRunnableMultipleTimes()
    {
        int scheduleCount = 10;
        Duration period = Duration.ofMillis(100);
        final CountDownLatch latch = new CountDownLatch(scheduleCount);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            period,
            latch::countDown);

        scheduledRunnable.schedule();

        for (int i = 0; i < scheduleCount; i++)
        {
            timer.getClock().elapse(period.plusMillis(10));
            timer.run();
        }

        assertEquals(0, latch.getCount());
    }

    @Test
    public void scheduleWithNegativeDelayDoesNotExecuteRunnable()
    {
        final CountDownLatch latch = new CountDownLatch(1);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(-1),
            latch::countDown);

        scheduledRunnable.schedule();

        timer.getClock().elapse(Duration.ofSeconds(1));
        timer.run();
        assertEquals(1, latch.getCount());
    }

    @Test
    public void negativeDelayStopsFurtherExecution()
    {
        int scheduleCount = 5;
        final CountDownLatch latch = new CountDownLatch(scheduleCount);
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

        for (int i = 0; i < scheduleCount; i++)
        {
            timer.getClock().elapse(Duration.ofMillis(100));
            timer.run();
        }

        assertEquals(1, latch.getCount());
    }

    @Test
    public void cancelStopFurtherExecution()
    {
        final CountDownLatch latch = new CountDownLatch(2);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(500),
            latch::countDown);

        scheduledRunnable.schedule();
        timer.getClock().elapse(Duration.ofMillis(520));
        timer.run();

        // Check runnable executed once
        assertEquals(1, latch.getCount());

        scheduledRunnable.cancel();

        timer.getClock().elapse(Duration.ofSeconds(1));
        timer.run();
        // Check runnable was not executed after cancel.
        assertEquals(1, latch.getCount());
    }

    @Test
    public void scheduleExecuteRunnableIfPreviouslyCancelled()
    {
        final CountDownLatch latch = new CountDownLatch(10);
        final PeriodicRunnable scheduledRunnable = PeriodicRunnable.create(
            timer,
            executor,
            Duration.ofMillis(200),
            latch::countDown);

        scheduledRunnable.schedule();
        timer.getClock().elapse(Duration.ofMillis(220));
        timer.run();

        // Check runnable executed once
        assertEquals(9, latch.getCount());

        scheduledRunnable.cancel();

        timer.getClock().elapse(Duration.ofSeconds(1));
        timer.run();
        // Check runnable was not executed after cancel.
        assertEquals(9, latch.getCount());

        // Schedule again
        scheduledRunnable.schedule();
        for (int i = 0; i < 5; i++)
        {
            timer.getClock().elapse(Duration.ofMillis(200));
            timer.run();
        }
        assertEquals(4, latch.getCount());
    }
}
