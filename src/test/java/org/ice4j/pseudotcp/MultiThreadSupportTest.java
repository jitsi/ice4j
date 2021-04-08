/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
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
package org.ice4j.pseudotcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * This class enables multi thread tests where main thread waits in loop for
 * specified condition to be met, while others perform some operations. For
 * example until the connection is established or closed. It also registers
 * default uncaught exception handler to catch exceptions from other threads.
 * <p>
 * Condition checks are passed as IWaitUntilDone interface.
 *
 * @author Pawel Domas
 */
public class MultiThreadSupportTest implements Thread.UncaughtExceptionHandler
{
    private volatile Throwable testError;

    private volatile Thread errorThread;

    private final Object testLock = new Object();

    @Override
    public void uncaughtException(Thread t, Throwable e)
    {
        synchronized (testLock)
        {
            testError = e;
            errorThread = t;
            testLock.notifyAll();
        }
    }

    private static final long ASSERT_WAIT_INTERVAL = 100;

    protected boolean assert_wait_until(BooleanSupplier wait, long timeoutMs)
    {
        long timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        try
        {
            long start = System.nanoTime();
            while (!wait.getAsBoolean() && (System.nanoTime() - start) < timeoutNanos)
            {
                synchronized (testLock)
                {
                    testLock.wait(ASSERT_WAIT_INTERVAL);
                    if (testError != null)
                    {
                        testError.printStackTrace();
                        fail("Error in thread: " + errorThread.getName() + " : "
                            + testError.getMessage());
                    }
                }
            }
            return wait.getAsBoolean();
        }
        catch (InterruptedException ex)
        {
            ex.printStackTrace();
            fail("assert_wait - interrupted");
            //return is unreachable
            return false;
        }
    }
}
