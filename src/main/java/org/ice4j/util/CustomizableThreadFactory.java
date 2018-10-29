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
 * A thread factory which supports customizing name prefix of created threads
 * and if produced threads are daemons or not.
 */
public final class CustomizableThreadFactory implements ThreadFactory
{
    private final ThreadFactory defaultThreadFactory
        = Executors.defaultThreadFactory();

    private final String threadNamePrefix;

    private final boolean isDaemon;

    public CustomizableThreadFactory(String threadNamePrefix, boolean isDaemon)
    {
        this.threadNamePrefix = threadNamePrefix;
        this.isDaemon = isDaemon;
    }

    @Override
    public Thread newThread(Runnable r)
    {
        Thread thread = this.defaultThreadFactory.newThread(r);
        if (this.threadNamePrefix != null && !threadNamePrefix.isEmpty())
        {
            thread.setName(this.threadNamePrefix + thread.getName());
        }
        if (thread.isDaemon() != this.isDaemon)
        {
            thread.setDaemon(this.isDaemon);
        }
        return thread;
    }
}
