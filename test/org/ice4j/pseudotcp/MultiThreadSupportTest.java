package org.ice4j.pseudotcp;

import junit.framework.*;
import static org.junit.Assert.*;

/**
 * This class enables multi thread tests where main thread waits in loop 
 * for specified condition to be met, while others perform some operations.
 * For example until the connection is established or closed. 
 * It also registers default uncaught exception handler to catch exceptions 
 * from other threads.
 * 
 * Condition checks are passed as IWaitUntilDone interface.
 * 
 * @author Pawel Domas
 */
public class MultiThreadSupportTest extends TestCase
{
    private volatile Throwable testError;
    private volatile Thread errorThread;
    private final Object testLock = new Object();

    public MultiThreadSupportTest()
    {
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler()
        {
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
        });
    }
    
    private long assertWaitInterval = 100;
    protected interface IWaitUntilDone
    {
        public boolean isDone();
    }    
    
    protected boolean assert_wait_until(IWaitUntilDone wait, long timeoutMs)
    {
        try
        {
            long start = System.currentTimeMillis();
            while (!wait.isDone() && (System.currentTimeMillis() - start) < timeoutMs)
            {
                synchronized (testLock)
                {
                    testLock.wait(assertWaitInterval);
                    if (testError != null)
                    {
                        testError.printStackTrace();
                        fail("Error in thread: " + errorThread.getName() + " : " + testError.getMessage());
                    }
                }
            }
            return wait.isDone();
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
