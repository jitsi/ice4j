/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
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

/**
 * Helper class which contains functions to work with executors
 */
public class ExecutorUtils
{
    /**
     * Creates pre-configured {@link ScheduledExecutorService} instance with
     * defaults suitable for ice4j
     * @param threadNamePrefix - name prefix for threads created by pool
     * @param threadKeepAliveTime - keep alive thread even when no more work
     * @param timeUnit - time unit of <tt>threadKeepAliveTime</tt>
     * @return pre-configured {@link ScheduledExecutorService}
     */
    public static ScheduledExecutorService createdScheduledExecutor(
        String threadNamePrefix,
        int threadKeepAliveTime,
        TimeUnit timeUnit)
    {
        CustomizableThreadFactory threadFactory
            = new CustomizableThreadFactory(threadNamePrefix, true);

        // Motivation:
        // The desired behaviour from pool is that it creates limited number
        // of threads based on current load, as well as releasing threads when
        // there is no work to execute.
        // Based on these requirements the following default configuration is
        // chosen.
        // <tt>corePoolSize</tt> to be equal to number of processors on the
        // current machine. Even so spec says that corePoolSize is number of
        // threads to keep in pool they are actually created on demand, so if
        // there is no load, then threads are not created. But until pool has
        // less than <tt>corePoolSize</tt> threads, pool will create new thread,
        // to execute scheduled task, even though already created threads are
        // idle and have no tasks to execute.
        // <tt>keepAliveTime</tt> is configurable and specifies timeout before
        // idle core thread deleted from pool
        // <tt>removeOnCancelPolicy</tt> is set to true, to immediately remove
        // queued task from pool queue, because some task might be scheduled
        // with very big delay causing having reference to creator from pool
        //
        // Having <tt>corePoolSize</tt> is set to 0 with unlimited pool size
        // <tt>maximumPoolSize</tt> is observed to create only 1 thread in pool
        // no matter how many task are queued and become eligible to execute.
        final ScheduledThreadPoolExecutor executor
            = new ScheduledThreadPoolExecutor(
                Runtime.getRuntime().availableProcessors(), threadFactory);
        executor.setKeepAliveTime(threadKeepAliveTime, timeUnit);
        executor.allowCoreThreadTimeOut(true);
        executor.setRemoveOnCancelPolicy(true);
        return Executors.unconfigurableScheduledExecutorService(executor);
    }
}
