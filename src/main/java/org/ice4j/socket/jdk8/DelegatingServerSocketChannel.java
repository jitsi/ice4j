/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.socket.jdk8;

import java.io.*;
import java.nio.channels.*;

import org.ice4j.socket.*;

import sun.nio.ch.*;

/**
 * Implements a {@code ServerSocketChannel} which delegates (its method calls)
 * to another {@code ServerSocketChannel}. In other words, the former wraps the
 * latter.
 *
 * @author Lyubomir Marinov
 */
class DelegatingServerSocketChannel<T extends ServerSocketChannel>
    extends BaseDelegatingServerSocketChannel<T>
    implements SelChImpl
{
    /**
     * The view of {@link #delegate} as a <tt>SelChImpl</tt> interface instance
     * required by {@link Selector} and related functionality.
     */
    protected final SelChImpl delegateAsSelChImpl;

    /**
     * Initializes a new {@code DelegatingServerSocketChannel} instance which is
     * to delegate (its method calls) to a specific {@code ServerSocketChannel}.
     *
     * @param delegate the {@code ServerSocketChannel} the new instance is to
     * delegate (its method calls) to
     */
    public DelegatingServerSocketChannel(T delegate)
    {
        super(delegate);

        delegateAsSelChImpl
            = (delegate instanceof SelChImpl) ? (SelChImpl) delegate : null;
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
    @Override
    public void translateAndSetInterestOps(int ops, SelectionKeyImpl sk)
    {
        delegateAsSelChImpl.translateAndSetInterestOps(ops, sk);
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
