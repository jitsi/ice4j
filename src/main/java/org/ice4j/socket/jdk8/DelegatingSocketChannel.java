/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2018 - present 8x8, Inc.
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
package org.ice4j.socket.jdk8;

import java.io.*;
import java.lang.reflect.*;
import java.nio.channels.*;
import java.util.logging.*;

import org.ice4j.socket.*;

import sun.nio.ch.*;

/**
 * Implements a {@code SocketChannel} which delegates (its method calls) to
 * another {@code SocketChannel}. In other words, the former wraps the latter.
 *
 * @author Lyubomir Marinov
 */
class DelegatingSocketChannel<T extends SocketChannel>
    extends BaseDelegatingSocketChannel<T>
    implements SelChImpl
{
    /**
     * The {@link Logger} used by the {@link DelegatingSocketChannel}
     * class and its instances for logging output.
     */
    private static final java.util.logging.Logger classLogger
        = java.util.logging.Logger.getLogger(
            DelegatingSocketChannel.class.getName());

    /**
     * The view of {@link #delegate} as a <tt>SelChImpl</tt> interface instance
     * required by {@link Selector} and related functionality.
     */
    protected final SelChImpl delegateAsSelChImpl;

    /**
     * The translateAndSetInterestOps method available in java 8.
     */
    private final Method translateAndSetInterestOpsMethod;

    /**
     * The translateInterestOps method available in java 11.
     */
    private final Method translateInterestOpsMethod;

    /**
     * Initializes a new {@code DelegatingSocketChannel} instance which is to
     * delegate (its method calls) to a specific {@code SocketChannel}.
     *
     * @param delegate the {@code SocketChannel} the new instance is to delegate
     * (its method calls) to
     */
    public DelegatingSocketChannel(T delegate)
    {
        super(delegate);

        delegateAsSelChImpl
            = (delegate instanceof SelChImpl) ? (SelChImpl) delegate : null;

        Method method;
        try
        {
            method = SelChImpl.class.getMethod(
                "translateAndSetInterestOps",
                Integer.TYPE, SelectionKeyImpl.class);
        }
        catch(NoSuchMethodException e)
        {
            method = null;

        }
        translateAndSetInterestOpsMethod = method;

        try
        {
            method = SelChImpl.class.getMethod(
                "translateInterestOps", Integer.TYPE);
        }
        catch(NoSuchMethodException e)
        {
            method = null;
        }
        translateInterestOpsMethod = method;

        if (translateInterestOpsMethod == null
            && translateAndSetInterestOpsMethod == null)
        {
            classLogger.log(
                Level.SEVERE, "Cannot find translateInterestOps " +
                    "or translateAndSetInterestOps!");
        }
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public FileDescriptor getFD()
    {
        return delegateAsSelChImpl.getFD();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public int getFDVal()
    {
        return delegateAsSelChImpl.getFDVal();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public void kill()
        throws IOException
    {
        delegateAsSelChImpl.kill();
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @SuppressWarnings("unused")
    public void translateAndSetInterestOps(int ops, SelectionKeyImpl sk)
    {
        try
        {
            if (translateAndSetInterestOpsMethod != null)
            {
                translateAndSetInterestOpsMethod.invoke(
                    delegateAsSelChImpl, ops, sk);
            }
        }
        catch(IllegalAccessException | InvocationTargetException e)
        {
            classLogger.log(
                Level.SEVERE,
                "Cannot execute method translateAndSetInterestOpsMethod", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @SuppressWarnings("unused")
    public int translateInterestOps(int ops)
    {
        try
        {
            if (translateInterestOpsMethod != null)
            {
                return (Integer) translateInterestOpsMethod.invoke(
                    delegateAsSelChImpl, ops);
            }
        }
        catch(IllegalAccessException | InvocationTargetException e)
        {
            classLogger.log(
                Level.SEVERE,
                "Cannot execute method translateInterestOpsMethod", e);
        }

        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean translateAndSetReadyOps(int ops, SelectionKeyImpl sk)
    {
        return delegateAsSelChImpl.translateAndSetReadyOps(ops, sk);
    }

    /**
     * {@inheritDoc}
     *
     * Forwards to {@link #delegate}.
     */
    @Override
    public boolean translateAndUpdateReadyOps(int ops, SelectionKeyImpl sk)
    {
        return delegateAsSelChImpl.translateAndUpdateReadyOps(ops, sk);
    }
}
