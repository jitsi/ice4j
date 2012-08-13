/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.pseudotcp;

import java.io.*;
import java.util.*;
import java.util.logging.*;
import org.ice4j.pseudotcp.util.*;

/**
 * Base class for other pseduoTCP logic tests. Runs all threads required for the
 * protocol to work. There are two instances of pseudoTCP logic being run. Data
 * packets between them are passes directly with some loss and/or delay
 * introduced optionally.
 *
 * @author Pawel Domas
 */
public abstract class PseudoTcpTestBase extends MultiThreadSupportTest
    implements IPseudoTcpNotify
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(PseudoTCPBase.class.getName());
    /**
     * Remote peer TCP logic instance
     */
    private final PseudoTCPBase remoteTcp;
    /**
     * Local peer TCP logic instance
     */
    private final PseudoTCPBase localTcp;
    private int local_mtu_;
    private int remote_mtu_;
    /**
     * Delay in ms introduced to packets delivery
     */
    private int delay_;
    /**
     * Simulated packets loss in %
     */
    private int loss_;
    /**
     * Stores info about connection state for use by child classes
     */
    protected boolean have_connected_;
    protected boolean have_disconnected_;
    /**
     * Timer used to delay packets delivery
     */
    private Timer timer = new Timer("Delay timer");
    /**
     * Timeout for connect operation in ms
     */
    static final int kConnectTimeoutMs = 5000;  // ~3 * default RTO of 3000ms
    //static final int kMinTransferRate = 1050000;
    /**
     * Transfer rate used to calculate timeout for transfer operations. This
     * timeout counts before the transfer tests will fail.
     */
    static final int kMinTransferRate = 1000;
    /**
     * Transfer blocks size
     */
    static final int kBlockSize = 4096;

    public PseudoTcpTestBase()
    {
        this.remoteTcp = new PseudoTCPBase(this, 1);
        //Debug names are usefull to identify peers in log messages
        remoteTcp.debugName = "REM";
        this.localTcp = new PseudoTCPBase(this, 1);
        localTcp.debugName = "LOC";
        SetLocalMtu(65535);
        SetRemoteMtu(65535);
    }

    /**
     * Creates some random data array
     *
     * @param size
     * @return
     */
    static public byte[] createDummyData(int size)
    {
        byte[] dummy = new byte[size];
        Random r = new Random();
        r.nextBytes(dummy);
        return dummy;
    }

    /**
     * Sets the <tt>mtu</tt> for local peer
     *
     * @param mtu
     */
    void SetLocalMtu(int mtu)
    {
        localTcp.NotifyMTU(mtu);
        local_mtu_ = mtu;
    }

    /**
     * Sets the <tt>mtu</tt> for remote peer
     *
     * @param mtu
     */
    void SetRemoteMtu(int mtu)
    {
        remoteTcp.NotifyMTU(mtu);
        remote_mtu_ = mtu;
    }

    /**
     * Sets the delay introduced to packets delivery between peers
     *
     * @param delay
     */
    void SetDelay(int delay)
    {
        delay_ = delay;
    }

    /**
     * Sets loss % of packets transferred between local and remote peers
     *
     * @param percent
     */
    void SetLoss(int percent)
    {
        loss_ = percent;
    }

    /**
     * Sets OptNagling for both local and remote peers
     *
     * @param enable_nagles
     */
    void SetOptNagling(boolean enable_nagles)
    {
        localTcp.SetOption(Option.OPT_NODELAY, enable_nagles ? 0 : 1);
        remoteTcp.SetOption(Option.OPT_NODELAY, enable_nagles ? 0 : 1);

    }

    /**
     * Sets ack delay option for local and remote peers
     *
     * @param ack_delay
     */
    void SetOptAckDelay(int ack_delay)
    {
        localTcp.SetOption(Option.OPT_ACKDELAY, ack_delay);
        remoteTcp.SetOption(Option.OPT_ACKDELAY, ack_delay);
    }

    /**
     * Sets send buffer option for local and remote peers
     *
     * @param size
     */
    void SetOptSndBuf(int size)
    {
        localTcp.SetOption(Option.OPT_SNDBUF, size);
        remoteTcp.SetOption(Option.OPT_SNDBUF, size);
    }

    /**
     * Sets receive buffer size option for remote peer
     *
     * @param size
     */
    void SetRemoteOptRcvBuf(int size)
    {
        remoteTcp.SetOption(Option.OPT_RCVBUF, size);
    }

    /**
     * Sets receive buffer size option for local peer
     *
     * @param size
     */
    void SetLocalOptRcvBuf(int size)
    {
        localTcp.SetOption(Option.OPT_RCVBUF, size);
    }

    /**
     * Disable window scaling for remote peer
     */
    void DisableRemoteWindowScale()
    {
        remoteTcp.disableWindowScale();
    }

    /**
     * Disable window scaling for local peer
     */
    void DisableLocalWindowScale()
    {
        localTcp.disableWindowScale();
    }

    /**
     * Starts the connection from local to remote peer
     *
     * @throws IOException
     */
    void Connect() throws IOException
    {
        localTcp.Connect();
        UpdateLocalClock();
    }

    /**
     * Closes the connection
     */
    void Close()
    {
        localTcp.Close(false);
        UpdateLocalClock();
    }

    /**
     * Catches the event OnTcpOpen on the local peer and marks have_connected
     * flag
     *
     * @param tcp
     */
    @Override
    public void OnTcpOpen(PseudoTCPBase tcp)
    {
        if (tcp == localTcp)
        {
            have_connected_ = true;
            OnTcpWriteable(tcp);
        }
    }

    /**
     * Catches OnTcpClosed event on remote peer and marks have_disconnected flag
     *
     * @param tcp
     * @param exc
     */
    @Override
    public void OnTcpClosed(PseudoTCPBase tcp, IOException exc)
    {
        assert exc == null;
        if (tcp == remoteTcp)
        {
            have_disconnected_ = true;
        }
    }
    /**
     * Randomizer instance used to decide about packet loss
     */
    private Random random = new Random();

    int RandomInt()
    {
        return random.nextInt(100);
    }

    /**
     * Send the <tt>data</tt> from local to remote peer
     *
     * @param data
     * @param len
     * @return
     * @throws IOException
     */
    int LocalSend(byte[] data, int len) throws IOException
    {
        return localTcp.Send(data, len);
    }

    /**
     * Receive data as local peer
     *
     * @param buffer
     * @param len
     * @return
     * @throws IOException
     */
    int LocalRecv(byte[] buffer, int len) throws IOException
    {
        return localTcp.Recv(buffer, len);
    }

    /**
     * Receive data as remote peer
     *
     * @param buffer
     * @param len
     * @return
     * @throws IOException
     */
    int RemoteRecv(byte[] buffer, int len) throws IOException
    {

        return remoteTcp.Recv(buffer, len);
    }

    /**
     * Sends the <tt>data</tt> from remote to local peer
     *
     * @param data
     * @param len
     * @return
     * @throws IOException
     */
    int RemoteSend(byte[] data, int len)
        throws IOException
    {
        return remoteTcp.Send(data, len);
    }

    /**
     * Simulates packet received by local peer
     *
     * @param data
     * @param len
     * @throws IOException
     */
    private void LocalPacket(byte[] data, int len)
        throws IOException
    {
        localTcp.NotifyPacket(data, len);
        UpdateLocalClock();
    }

    /**
     * Simulates packet received by remote peer
     *
     * @param data
     * @param len
     * @throws IOException
     */
    private void RemotePacket(byte[] data, int len)
        throws IOException
    {
        remoteTcp.NotifyPacket(data, len);
        UpdateRemoteClock();
    }

    /**
     * Creates <tt>TimerTask</tt> with @link(RemotePacket) action
     *
     * @param data
     * @param len
     * @return
     */
    private TimerTask getWriteRemotePacketTask(final byte[] data, final int len)
    {
        return new TimerTask()
        {
            @Override
            public void run()
            {
                try
                {
                    RemotePacket(data, len);
                }
                catch (IOException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        };
    }

    /**
     * Creates <tt>TimerTask</tt> with @link(LocalPacket) action
     *
     * @param data
     * @param len
     * @return
     */
    private TimerTask getWriteLocalPacketTask(final byte[] data, final int len)
    {
        return new TimerTask()
        {
            @Override
            public void run()
            {
                try
                {
                    LocalPacket(data, len);
                }
                catch (IOException ex)
                {
                    throw new RuntimeException(ex);
                }
            }
        };
    }

    /**
     * Handles passing packets between local and remote peers. Here are taken
     * decisions about packets loss and delay.
     *
     * @param tcp
     * @param buffer
     * @param len
     * @return
     */
    @Override
    public WriteResult TcpWritePacket(PseudoTCPBase tcp, byte[] buffer, int len)
    {
        // Randomly drop the desired percentage of packets.
        // Also drop packets that are larger than the configured MTU.
        if (RandomInt() < loss_)
        {
            if (logger.isLoggable(Level.FINE))
            {
                logger.log(Level.FINE, "Randomly dropping packet, size=" + len);
            }
        }
        else
        {
            if (len > Math.min(local_mtu_, remote_mtu_))
            {
                if (logger.isLoggable(Level.FINE))
                {
                    logger.log(Level.FINE,
                               "Dropping packet that exceeds path MTU, size="
                        + len);
                }
            }
            else
            {
                if (tcp == localTcp)
                {
                    timer.schedule(getWriteRemotePacketTask(buffer, len), delay_);
                }
                else
                {
                    timer.schedule(getWriteLocalPacketTask(buffer, len), delay_);
                }
            }
        }
        return WriteResult.WR_SUCCESS;
    }

    /**
     * Wakes up local clock thread from wait method causing forced time update
     */
    protected void UpdateLocalClock()
    {
        if (localClockThread != null)
        {
            synchronized (localClockLock)
            {
                localClockLock.notifyAll();
            }
        }
    }

    /**
     * Wakes up remote clock thread from wait method causing forced time update
     */
    protected void UpdateRemoteClock()
    {
        if (remoteClockThread != null)
        {
            synchronized (remoteClockLock)
            {
                remoteClockLock.notifyAll();
            }
        }
    }

    /**
     * Method handles time update for pseudoTCP logic class
     *
     * @param tcp
     * @param lock
     */
    private void UpdateNextClock(final PseudoTCPBase tcp, final Object lock)
    {
        try
        {

            long now = PseudoTCPBase.Now();
            //System.out.println(tcp.debugName + " NOTIFY CLOCK: " + now);
            synchronized (tcp)
            {
                tcp.NotifyClock(now);
            }
            //UpdateClock(tcp);
            long interval;  // NOLINT
            synchronized (tcp)
            {
                interval = tcp.GetNextClock(PseudoTCPBase.Now());
            }
            //interval = Math.max(interval, 0L);  // sometimes interval is < 0 
            if (logger.isLoggable(Level.FINEST))
            {
                logger.log(Level.FINEST,
                           tcp.debugName + " CLOCK sleep for " + interval);
            }
            if (interval < 0)
            {
                if (interval == -1)
                {
                    interval = 1000;
                }
                else
                {
                    return;
                }
            }
            synchronized (lock)
            {
                lock.wait(interval);
            }
        }
        catch (InterruptedException ex)
        {
            //Logger.getLogger(PseudoTcpTestBase.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    /**
     * Local peer clock thread
     */
    private Thread localClockThread;
    private final Object localClockLock = new Object();
    /**
     * Remote peer clock thread
     */
    private Thread remoteClockThread;
    private final Object remoteClockLock = new Object();
    /**
     * The "run flag" for clock threads
     */
    private boolean runClocks = false;

    /**
     * Start clock threads
     */
    protected void StartClocks()
    {
        if (localClockThread == null && remoteClockThread == null)
        {
            runClocks = true;
            localClockThread = new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    while (runClocks)
                    {
                        //localTcp.NotifyClock(PseudoTCPBase.Now());
                        UpdateNextClock(localTcp, localClockLock);

                    }

                }
            }, "LocalClockThread");
            remoteClockThread = new Thread(new Runnable()
            {
                @Override
                public void run()
                {
                    while (runClocks)
                    {
                        //remoteTcp.NotifyClock(PseudoTCPBase.Now());
                        UpdateNextClock(remoteTcp, remoteClockLock);
                    }

                }
            }, "RemoteClockThread");
            localClockThread.start();
            remoteClockThread.start();
        }
        else
        {
            throw new IllegalStateException();
        }
    }

    /**
     * Stops clock threads
     */
    protected void StopClocks()
    {
        if (localClockThread != null && remoteClockThread != null)
        {
            try
            {
                runClocks = false;
                localClockThread.interrupt();
                remoteClockThread.interrupt();
                localClockThread.join();
                localClockThread = null;
                remoteClockThread.join();
                remoteClockThread = null;
            }
            catch (InterruptedException ex)
            {
                ex.printStackTrace();
            }
        }
        else
        {
            throw new IllegalStateException();
        }
    }

    /**
     * This method waits <tt>kConnectTimeoutMs</tt> miliseconds or until the
     * connection has been established between local and remote peers
     *
     * @param kConnectTimeoutMs
     * @return <tt>isDone</tt> result
     */
    protected boolean assert_Connected_wait(int kConnectTimeoutMs)
    {
        return assert_wait_until(new IWaitUntilDone()
        {
            @Override
            public boolean isDone()
            {
                return PseudoTcpTestBase.this.have_connected_;
            }
        }, kConnectTimeoutMs);
    }

    /**
     * This method waits <tt>kTransferTimeoutMs</tt> miliseconds or until the
     * connection has been closed, which means that the data was transferred
     *
     * @param kTransferTimeoutMs
     * @return <tt>isDone</tt> result
     */
    protected boolean assert_Disconnected_wait(long kTransferTimeoutMs)
    {
        return assert_wait_until(new IWaitUntilDone()
        {
            @Override
            public boolean isDone()
            {
                return PseudoTcpTestBase.this.have_disconnected_;
            }
        }, kTransferTimeoutMs);
    }

    /**
     * @return the remoteTcp
     */
    PseudoTCPBase getRemoteTcp()
    {
        return remoteTcp;
    }

    /**
     * @return the localTcp
     */
    PseudoTCPBase getLocalTcp()
    {
        return localTcp;
    }

    /**
     * Calculates maximum transfer time of <tt>size</tt> bytes for specified
     * transfer rate
     *
     * @param size
     * @param kBps
     * @return timeout for transfer in ms(minimum 3000 ms)
     */
    public long MaxTransferTime(long size, long kBps)
    {
        long transferTout = ((size) / kBps) * 8 * 1000;
        return transferTout > 3000 ? transferTout : 3000;
    }
}
