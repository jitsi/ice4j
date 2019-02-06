package org.ice4j.util;

import java.util.concurrent.*;

/**
 * A base class for runnables which should be periodically executed on
 * specified executor service.
 *
 * @author Yura Yaroshevich
 */
public abstract class PeriodicRunnable
{
    /**
     * A timer to perform periodic scheduling of {@link #run()} execution
     * on {@link #executor}'s thread.
     */
    private final ScheduledExecutorService timer;

    /**
     * An executor service to perform actual execution of {@link #run()}.
     */
    private final ExecutorService executor;

    /**
     * A synchronization object to synchronize scheduling, execution and
     * cancellation of {@link #run()}.
     */
    private final Object syncRoot = new Object();

    /**
     * Indicates if execution of {@link #run()} scheduled and should
     * be further continued.
     */
    private volatile boolean running = false;

    /**
     * Store a reference to last runnable submitted to {@link #timer}
     */
    private ScheduledFuture<?> scheduledSubmit;

    /**
     * Store a reference to last runnable submitted to {@link #executor}
     */
    private Future<?> submittedExecute;

    /**
     * Create instance of {@link PeriodicRunnable} with specified timer and
     * executor.
     * @param timer an {@link ScheduledExecutorService} which is used to
     *              periodic triggering of {@link #run()} execution.
     * @param executor an {@link ExecutorService} to perform actual execution
     *                 of {@link #run()}.
     */
    protected PeriodicRunnable(
        ScheduledExecutorService timer,
        ExecutorService executor)
    {
        if (timer == null)
        {
            throw new IllegalArgumentException("timer is null");
        }
        if (executor == null)
        {
            throw new IllegalArgumentException("executor is null");
        }
        this.timer = timer;
        this.executor = executor;
    }

    /**
     * Get delay before next execution of {@link #run()}.
     * @return non-negative value if execution of {@link #run()} should be
     * performed with specified delay, negative value if execution should not
     * be done.
     */
    protected abstract long getMillisecondsDelayUntilNextRun();

    /**
     * Periodically executed method on {@link #executor}'s thread.
     */
    protected abstract void run();

    /**
     * Schedules periodic execution of {@link #run()} on {@link #executor}'s
     * thread.
     */
    public void schedule()
    {
        if (running)
        {
            return;
        }

        final long delayMillis =
            getMillisecondsDelayUntilNextRun();

        synchronized (syncRoot)
        {
            if (running)
            {
                return;
            }
            scheduleNextRun(delayMillis);
        }
    }

    /**
     * Cancels periodic execution of {@link #run()} on {@link #executor}'s
     * thread.
     */
    public void cancel()
    {
        if (!running)
        {
            return;
        }

        synchronized (syncRoot)
        {
            if (running)
            {
                running = false;

                if (scheduledSubmit != null)
                {
                    scheduledSubmit.cancel(true);
                    scheduledSubmit = null;
                }

                if (submittedExecute != null)
                {
                    submittedExecute.cancel(true);
                    submittedExecute = null;
                }
            }
        }
    }

    /**
     * Perform either cancellation or actual scheduling based on delay until
     * next run.
     * @param delayMillis delay in milliseconds before next
     *                    execution of {@link #run()}.
     */
    private void scheduleNextRun(long delayMillis)
    {
        if (delayMillis < 0)
        {
            running = false;
            return;
        }

        running = true;

        if (delayMillis == 0)
        {
            submitExecuteRun();
        }
        else
        {
            scheduledSubmit = timer.schedule(
                this::submitExecuteRun,
                delayMillis,
                TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Submit execution of {@link #run()} into {@link #executor}'s thread
     * if not cancelled.
     */
    private void submitExecuteRun()
    {
        if (!running)
        {
            return;
        }
        submittedExecute = this.executor.submit(this::executeRun);
    }

    /**
     * Perform execution of {@link #run()} with further re-schedule of
     * execution if not cancelled
     */
    private void executeRun()
    {
        if (!running)
        {
            return;
        }

        try
        {
            this.run();
        }
        finally
        {
            if (running)
            {
                final long delayMillis =
                    getMillisecondsDelayUntilNextRun();

                synchronized (syncRoot)
                {
                    if (running)
                    {
                        scheduleNextRun(delayMillis);
                    }
                }
            }
        }
    }

    /**
     * Constructs {@link PeriodicRunnable} for {@link Runnable} with provided
     * timer, executor and fixed delay.
     * fixed delay.
     * @param timer {@link ScheduledExecutorService} to be used as timer
     * @param executor {@link ExecutorService} to execute provided runnable
     * @param delay delay between subsequent execution of runnable
     * @param unit time units of delay
     * @param r {@link Runnable} to for periodic execution.
     * @return {@link PeriodicRunnable} instance constructed with provided
     * arguments
     */
    static PeriodicRunnable create(
        ScheduledExecutorService timer,
        ExecutorService executor,
        long delay,
        TimeUnit unit,
        Runnable r)
    {
        return new PeriodicRunnable(timer, executor)
        {
            @Override
            protected long getMillisecondsDelayUntilNextRun()
            {
                return unit.toMillis(delay);
            }

            @Override
            protected void run()
            {
                r.run();
            }
        };
    }
}
