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
 * Main protocol logic class. To open connection use Connect() method. Then @link(Recv) and @link(Send) operations may be used for data transfer.
 * To operate this class requires implementation of @link(IPseudoTcpNotify)
 * Also it must be notified about the time progress.
 *
 * @author Pawel Domas
 */
public class PseudoTCPBase
{
    /**
     * The logger.
     */
    private static final Logger logger =
        Logger.getLogger(PseudoTCPBase.class.getName());
    /**
     * Keepalive - disabled by default
     */
    private static boolean PSEUDO_KEEPALIVE = false;
    /**
     * Packet maximum levels
     */
    static final int[] PACKET_MAXIMUMS = new int[]
    {
        65535, // Theoretical maximum, Hyperchannel
        32000, // Nothing
        17914, // 16Mb IBM Token Ring
        8166, // IEEE 802.4
        //4464,   // IEEE 802.5 (4Mb max)
        4352, // FDDI
        //2048,   // Wideband Network
        2002, // IEEE 802.5 (4Mb recommended)
        //1536,   // Expermental Ethernet Networks
        //1500,   // Ethernet, Point-to-Point (default)
        1492, // IEEE 802.3
        1006, // SLIP, ARPANET
        //576,    // X.25 Networks
        //544,    // DEC IP Portal
        //512,    // NETBIOS
        508, // IEEE 802/Source-Rt Bridge, ARCNET
        296, // Point-to-Point (low delay)
        //68,     // Official minimum
        0, // End of list marker
    };
    static final int MAX_PACKET = 65535;
    // Note: we removed lowest level because packet overhead was larger!
    static final int MIN_PACKET = 296;
    static final int IP_HEADER_SIZE = 20; // (+ up to 40 bytes of options?)
    static final int ICMP_HEADER_SIZE = 8;
    static final int UDP_HEADER_SIZE = 8;
    // TODO: Make JINGLE_HEADER_SIZE transparent to this code?
    static final int JINGLE_HEADER_SIZE = 64; // when relay framing is in use
    // Default size for receive and send buffer.
    static final int DEFAULT_RCV_BUF_SIZE = 60 * 1024;
    static final int DEFAULT_SND_BUF_SIZE = 90 * 1024;
    //////////////////////////////////////////////////////////////////////
    // Global Constants and Functions
    //////////////////////////////////////////////////////////////////////
    //
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  0 |                      Conversation Number                      |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  4 |                        Sequence Number                        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  8 |                     Acknowledgment Number                     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |               |   |U|A|P|R|S|F|                               |
    // 12 |    Control    |   |R|C|S|S|Y|I|            Window             |
    //    |               |   |G|K|H|T|N|N|                               |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 16 |                       Timestamp sending                       |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 20 |                      Timestamp receiving                      |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 24 |                             data                              |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    //////////////////////////////////////////////////////////////////////
    static final long MAX_SEQ = 0xFFFFFFFFL;
    static final int HEADER_SIZE = 24;
    static final int PACKET_OVERHEAD = HEADER_SIZE + UDP_HEADER_SIZE + IP_HEADER_SIZE + JINGLE_HEADER_SIZE;
    static final long MIN_RTO = 250; // 250 ms (RFC1122, Sec 4.2.3.1 "fractions of a second")
    static final long DEF_RTO = 3000; // 3 seconds (RFC1122, Sec 4.2.3.1)
    static final long MAX_RTO = 60000; // 60 seconds
    static final long DEF_ACK_DELAY = 100; // 100 milliseconds
    static final short FLAG_CTL = 0x02;
    static final short FLAG_RST = 0x04;
    static final short CTL_CONNECT = 0;
    //static final short CTL_REDIRECT = 1;
    static final short CTL_EXTRA = 255;
    // TCP options.
    /**
     * End of list
     */
    static final short TCP_OPT_EOL = 0;
    /**
     * No-op
     */
    static final short TCP_OPT_NOOP = 1;
    /**
     * Maximum segment size
     */
    static final short TCP_OPT_MSS = 2;
    /**
     * Window scale factor
     */
    static final short TCP_OPT_WND_SCALE = 3;
    //static final short FLAG_FIN = 0x01; static final short FLAG_SYN = 0x02;
    //static final short FLAG_ACK = 0x10;
    static final int CTRL_BOUND = 0x80000000;
    /**
     * If there are no pending clocks, wake up every 4 seconds
     */
    static final long DEFAULT_TIMEOUT = 4000;
    /**
     * If the connection is closed, once per minute
     */
    static final long CLOSED_TIMEOUT = 60 * 1000; // 
    /**
     * Idle ping interval
     */
    static final int IDLE_PING = 20 * 1000; // 20 seconds (note: WinXP SP2 firewall udp timeout is 90 seconds)
    /**
     * Idle timeout(used if keepalive is enabled)
     */
    static final int IDLE_TIMEOUT = 90 * 1000; // 90 seconds;
    // TCB data
    /**
     * Tcp state
     */
    PseudoTcpState m_state;
    /**
     * Conversation number
     */
    long m_conv;
    boolean m_bReadEnable, m_bWriteEnable, m_bOutgoing;
    /**
     * Last traffic timestamp
     */
    long m_lasttraffic;
    /**
     * List of incoming segments. Segments store info like stream offset and
     * control flags. If segment contains any data it is stored in the receive
     * buffer.
     */
    List<RSegment> m_rlist = new ArrayList<RSegment>();
    /**
     * Last receive timestamp
     */
    long m_lastrecv;
    /**
     * Receive buffer length
     */
    int m_rbuf_len;
    /**
     * The sequence number of the next byte of data that is expected from the
     * other device
     */
    int m_rcv_nxt;
    /**
     * Receive window size
     */
    int m_rcv_wnd;
    /**
     * Window scale factor
     */
    private short m_rwnd_scale;
    /**
     * The receive buffer
     */
    ByteFifoBuffer m_rbuf;
    /**
     * Outgoing segments list
     */
    List<SSegment> m_slist = new ArrayList<SSegment>();
    /**
     * Last send timestamp
     */
    long m_lastsend;
    /**
     * The sequence number of the next byte of data to be sent
     */
    long m_snd_nxt;
    /**
     * The sequence number of the first byte of data that has been sent but not
     * yet acknowledged
     */
    long m_snd_una;
    /**
     * The send buffer's size
     */
    int m_sbuf_len;
    /**
     * Send window size
     */
    private int m_snd_wnd;
    /**
     * Send window scale factor
     */
    private short m_swnd_scale;
    /**
     * The send buffer
     */
    ByteFifoBuffer m_sbuf;
    // Maximum segment size, estimated protocol level, largest segment sent
    /**
     *
     */
    long m_mss;
    /**
     *
     */
    long m_largest;
    /**
     *
     */
    long m_mtu_advise;
    /**
     *
     */
    int m_msslevel;
    /**
     * Retransmit timer
     */
    long m_rto_base;
    /**
     * Timestamp tracking
     */
    long m_ts_recent, m_ts_lastack;
    /**
     * Round-trip calculation
     */
    long m_rx_rttvar, m_rx_srtt, m_rx_rto;
    /**
     * Congestion avoidance, Fast retransmit/recovery, Delayed ACKs
     */
    long m_ssthresh, m_cwnd;
    short m_dup_acks;
    long m_recover;
    long m_t_ack;
    // Configuration options
    /**
     * Use nagling
     */
    boolean m_use_nagling;
    /*
     * Acknowledgment delay
     */
    long m_ack_delay;
    boolean m_support_wnd_scale;
    IPseudoTcpNotify m_notify;
    EnShutdown m_shutdown;
    /**
     * Debug name used to identify peers in log messages
     */
    String debugName = "";

    //////////////////////////////////////////////////////////////////////
    // PseudoTcp
    //////////////////////////////////////////////////////////////////////
    /**
     *
     * @param notify {@link IPseudoTcpNotify} implementation
     * @param conv the conversation number used by this instance
     */
    public PseudoTCPBase(IPseudoTcpNotify notify, long conv)
    {
        m_notify = notify;
        m_shutdown = EnShutdown.SD_NONE;
        m_rbuf_len = DEFAULT_RCV_BUF_SIZE;
        m_rbuf = new ByteFifoBuffer(m_rbuf_len);
        m_sbuf_len = DEFAULT_SND_BUF_SIZE;
        m_sbuf = new ByteFifoBuffer(m_sbuf_len);
        // Sanity check on buffer sizes (needed for OnTcpWriteable notification logic)
        assert m_rbuf_len + MIN_PACKET < m_sbuf_len;
        long now = Now();

        m_state = PseudoTcpState.TCP_LISTEN;
        m_conv = conv;
        m_rcv_wnd = m_rbuf_len;
        m_rwnd_scale = m_swnd_scale = 0;
        m_snd_nxt = 0;
        m_snd_wnd = 1;
        m_snd_una = m_rcv_nxt = 0;
        m_bReadEnable = true;
        m_bWriteEnable = false;
        m_t_ack = 0;

        m_msslevel = 0;
        m_largest = 0;
        assert MIN_PACKET > PACKET_OVERHEAD;
        m_mss = MIN_PACKET - PACKET_OVERHEAD;
        m_mtu_advise = MAX_PACKET;

        m_rto_base = 0;

        m_cwnd = 2 * m_mss;
        m_ssthresh = m_rbuf_len;
        m_lastrecv = m_lastsend = m_lasttraffic = now;
        m_bOutgoing = false;

        m_dup_acks = 0;
        m_recover = 0;

        m_ts_recent = m_ts_lastack = 0;

        m_rx_rto = DEF_RTO;
        m_rx_srtt = m_rx_rttvar = 0;

        m_use_nagling = true;
        m_ack_delay = DEF_ACK_DELAY;
        m_support_wnd_scale = true;
    }

    /**
     * Enqueues connect message and starts connection procedure
     *
     * @throws IOException if the protocol is not in initial state
     */
    public void Connect() throws IOException
    {
        if (m_state != PseudoTcpState.TCP_LISTEN)
        {
            //m_error = PseudoTcpError.EINVAL;
            throw new IOException("Invalid socket state");
        }

        m_state = PseudoTcpState.TCP_SYN_SENT;
        logger.log(Level.FINE, "State: TCP_SYN_SENT", "");

        queueConnectMessage();
        attemptSend(SendFlags.sfNone);
    }

    /**
     * Set the MTU value
     *
     * @param mtu
     */
    public void NotifyMTU(int mtu)
    {
        m_mtu_advise = mtu;
        if (m_state == PseudoTcpState.TCP_ESTABLISHED)
        {
            adjustMTU();
        }
    }

    /**
     *
     * @return current timestamp limited to 32 bits
     */
    public static long Now()
    {
        return System.currentTimeMillis() & 0xFFFFFFFFL;
    }

    /**
     * Evaluate next interval between @link(GetNextClock) calls.
     * It is based on current protocol action timeout
     *
     * @param now current timestamp
     * @return next interval
     */
    public long GetNextClock(long now)
    {
        return clock_check(now);
    }

    /**
     * This method should be called in time intervals retrieved from @link(GetNextClock)
     *
     * @param now current timestamp
     */
    public void NotifyClock(long now)
    {
        if (logger.isLoggable(Level.FINEST))
        {
            logger.log(Level.FINEST, debugName + " update clock " + now);
        }
        if (m_state == PseudoTcpState.TCP_CLOSED)
        {
            return;
        }

        now = now & 0xFFFFFFFFL;

        // Check if it's time to retransmit a segment
        if (m_rto_base > 0 && (TimeDiff(m_rto_base + m_rx_rto, now) <= 0))
        {
            assert m_slist.isEmpty() == false;
            // retransmit segments
            if (logger.isLoggable(Level.FINER))
            {
                logger.log(Level.FINER, "timeout retransmit (rto: " + m_rx_rto
                    + ")(rto_base: " + m_rto_base + ") (now: " + now + ") (dup_acks: "
                    + m_dup_acks + ")");
            }
            if (!transmit(m_slist.get(0), now))
            {
                closedown(new IOException("Connection aborted"));
                return;
            }

            long nInFlight = m_snd_nxt - m_snd_una;
            m_ssthresh = Math.max(nInFlight / 2, 2 * m_mss);
            //Logger.Log(LS_INFO) << "m_ssthresh: " << m_ssthresh << "  nInFlight: " << nInFlight << "  m_mss: " << m_mss;
            m_cwnd = m_mss;

            // Back off retransmit timer.  Note: the limit is lower when connecting.
            long rto_limit = (m_state.ordinal() < PseudoTcpState.TCP_ESTABLISHED.ordinal())
                ? DEF_RTO : MAX_RTO;
            m_rx_rto = Math.min(rto_limit, m_rx_rto * 2);
            m_rto_base = now;
        }

        // Check if it's time to probe closed windows
        if ((getM_snd_wnd() == 0) && (TimeDiff(m_lastsend + m_rx_rto, now) <= 0))
        {
            if (TimeDiff(now, m_lastrecv) >= 15000)
            {
                closedown(new IOException("Connection aborted"));
                return;
            }
            // probe the window
            packet(m_snd_nxt - 1, (short) 0, 0, 0);
            m_lastsend = now;

            // back off retransmit timer
            m_rx_rto = Math.min(MAX_RTO, m_rx_rto * 2);
        }

        // Check if it's time to send delayed acks
        long timeDiff = TimeDiff(m_t_ack + m_ack_delay, now);
        if (m_t_ack > 0 && (timeDiff <= 0))
        {
            packet(m_snd_nxt, (short) 0, 0, 0);
        }

        if (PSEUDO_KEEPALIVE) // Check for idle timeout
        {
            if ((m_state == PseudoTcpState.TCP_ESTABLISHED)
                && (TimeDiff(m_lastrecv + IDLE_TIMEOUT, now) <= 0))
            {
                closedown(new IOException("Connection aborted"));
                return;
            }

            // Check for ping timeout (to keep udp mapping open)
            if ((m_state == PseudoTcpState.TCP_ESTABLISHED)
                && (TimeDiff(m_lasttraffic + (m_bOutgoing ? IDLE_PING * 3 / 2 : IDLE_PING), now) <= 0))
            {
                packet(m_snd_nxt, (short) 0, 0, 0);
            }

        }
    }

    /**
     * Use this method to notify protocol about packets received from the
     * network
     *
     * @param buffer packet's data
     * @param len data length
     * @return true if packet was successfully parsed
     */
    synchronized public boolean NotifyPacket(byte[] buffer, int len)
    {
        if (len > MAX_PACKET)
        {
            logger.log(Level.WARNING, debugName + " packet too large");
            return false;
        }
        return parse(buffer, len);
    }

    /**
     * Retrieve option's value. See {@link Option} for available options
     *
     * @param opt option which value will be retrieved
     * @return
     */
    long GetOption(Option opt)
    {
        if (opt == Option.OPT_NODELAY)
        {
            return m_use_nagling ? 0 : 1;
        }
        else
        {
            if (opt == Option.OPT_ACKDELAY)
            {
                return m_ack_delay;
            }
            else
            {
                if (opt == Option.OPT_SNDBUF)
                {
                    return m_sbuf_len;
                }
                else
                {
                    assert opt == Option.OPT_RCVBUF;
                    return m_rbuf_len;
                }
            }
        }
    }

    /**
     * Sets {@link Option} value
     *
     * @param opt option whose value will be set
     * @param value the value to be set
     */
    void SetOption(Option opt, int value)
    {
        if (opt == Option.OPT_NODELAY)
        {
            m_use_nagling = value == 0;
        }
        else
        {
            if (opt == Option.OPT_ACKDELAY)
            {
                m_ack_delay = value;
            }
            else
            {
                if (opt == Option.OPT_SNDBUF)
                {
                    assert m_state == PseudoTcpState.TCP_LISTEN;
                    resizeSendBuffer(value);
                }
                else
                {
                    assert opt == Option.OPT_RCVBUF;
                    assert m_state == PseudoTcpState.TCP_LISTEN;
                    resizeReceiveBuffer(value);
                }
            }
        }
    }

    /**
     *
     * @return congestion window size
     */
    long GetCongestionWindow()
    {
        return m_cwnd;
    }

    /**
     *
     * @return bytes in flight
     */
    long GetBytesInFlight()
    {
        return m_snd_nxt - m_snd_una;
    }

    /**
     *
     * @return bytes buffered, but not sent yet
     */
    long GetBytesBufferedNotSent()
    {
        long buffered_bytes = m_sbuf.GetBuffered();
        return m_snd_una + buffered_bytes - m_snd_nxt;
    }

    /**
     *
     * @return bytes available in receive buffer
     */
    int GetAvailable()
    {
        return m_rbuf.GetBuffered();
    }

    /**
     *
     * @return space available in the send buffer
     */
    int GetAvailableSendBuffer()
    {
        return m_sbuf.GetWriteRemaining();
    }

    /**
     *
     * @return round trip time estimate in ms
     */
    long GetRoundTripTimeEstimateMs()
    {
        return m_rx_srtt;
    }

    /**
     * Reads the data available in receive buffer. This method returns 0 if
     * there's no data available at the moment.
     *
     * @param buffer destination buffer
     * @param offset destination buffer's offset
     * @param len bytes to be read
     * @return byte count actually read
     * @throws IOException if the protocol is not in the connected state
     */
    public synchronized int Recv(byte[] buffer, int offset, int len) throws IOException
    {
        if (m_state != PseudoTcpState.TCP_ESTABLISHED)
        {
            throw new IOException("Socket not connected");
        }

        int read = m_rbuf.Read(buffer, len);

        // If there's no data in |m_rbuf|.
        if (read == 0)
        {
            m_bReadEnable = true;
            return 0;
        }
        assert read != -1;

        int available_space = m_rbuf.GetWriteRemaining();
        if (available_space - m_rcv_wnd >= Math.min(m_rbuf_len / 8, m_mss))
        {
            boolean bWasClosed = (m_rcv_wnd == 0); // !?! Not sure about this was closed business
            m_rcv_wnd = available_space;

            if (bWasClosed)
            {
                attemptSend(SendFlags.sfImmediateAck);
            }
        }
        return read;
    }

    /**
     *
     * @param buffer
     * @param len
     * @return
     * @throws IOException
     */
    public int Recv(byte[] buffer, int len) throws IOException
    {
        return Recv(buffer, 0, len);
    }

    /**
     *
     * @param buffer
     * @param len
     * @return
     * @throws IOException
     */
    public int Send(byte[] buffer, int len) throws IOException
    {
        return Send(buffer, 0, len);
    }

    /**
     * Enqueues data in the send buffer
     *
     * @param buffer source data buffer
     * @param offset offset of the source data buffer
     * @param len bytes count to be sent
     * @return bytes count written to the send buffer
     * @throws IOException if the protocol is not in connected state
     */
    public synchronized int Send(byte[] buffer, int offset, int len)
        throws IOException
    {
        if (m_state != PseudoTcpState.TCP_ESTABLISHED)
        {
            throw new IOException("Socket not connected");
        }

        long available_space;
        available_space = m_sbuf.GetWriteRemaining();

        if (available_space == 0)
        {
            m_bWriteEnable = true;
            return 0;
        }

        int written = queue(buffer, offset, len, false);
        attemptSend(SendFlags.sfNone);
        return written;
    }

    /**
     * Shuts down the protocol which enters closed state
     *
     * @param force if true all data received from this moment will be discarded
     */
    public void Close(boolean force)
    {
        logger.log(Level.FINE, debugName + " close (" + force + ")");
        m_shutdown = force ? EnShutdown.SD_FORCEFUL : EnShutdown.SD_GRACEFUL;
        if (force)
        {
            m_state = PseudoTcpState.TCP_CLOSED;
        }
    }

//
// Internal Implementation
//
    /**
     * Enqueues data segment in the send buffer
     *
     * @param buffer source buffer
     * @param offset source buffer's offset
     * @param len data length
     * @param bCtrl true for control data
     * @return written byte count
     */
    int queue(byte[] buffer, int offset, int len, boolean bCtrl)
    {
        int available_space;
        available_space = m_sbuf.GetWriteRemaining();
        if (len > available_space)
        {
            assert !bCtrl;
            len = available_space;
        }

        // We can concatenate data if the last segment is the same type
        // (control v. regular data), and has not been transmitted yet
        SSegment back = null;
        if (!m_slist.isEmpty())
        {
            back = m_slist.get(m_slist.size() - 1);
        }
        if (back != null && (back.bCtrl == bCtrl) && (back.xmit == 0))
        {
            back.len += len;
        }
        else
        {
            long snd_buffered;
            snd_buffered = m_sbuf.GetBuffered();
            SSegment sseg = new SSegment(
                m_snd_una + snd_buffered,
                len,
                bCtrl);
            //m_slist.push_back(sseg);
            if (logger.isLoggable(Level.FINEST))
            {
                logger.log(Level.FINEST, debugName + " enqueued send segment seq: "
                    + sseg.seq + " len: " + sseg.len);
            }
            m_slist.add(sseg);
        }

        int written = m_sbuf.Write(buffer, len);
        return written;
    }

    /**
     * Creates a packet starting at <tt>offset</tt> in the send buffer of
     * specified length and sends it with help of @link(IPseudoTcpNotify).
     *
     * @param seq used sequence number
     * @param flags
     * @param offset in the send buffer
     * @param len length of data from
     * @return @link(WriteResult) returned by @link(IPseudoTcpNotify)
     */
    WriteResult packet(long seq, short flags, long offset, long len)
    {
        assert HEADER_SIZE + len <= MAX_PACKET;

        long now = Now();

        byte[] buffer = new byte[MAX_PACKET];
        long_to_bytes(m_conv, buffer, 0);
        long_to_bytes(seq, buffer, 4);
        long_to_bytes(m_rcv_nxt, buffer, 8);
        buffer[12] = 0;
        buffer[13] = (byte) (flags & 0xFF);
        short_to_bytes(m_rcv_wnd >> m_rwnd_scale, buffer, 14);

        // Timestamp computations
        long_to_bytes(now, buffer, 16);
        long_to_bytes(m_ts_recent, buffer, 20);
        m_ts_lastack = m_rcv_nxt;

        if (len > 0)
        {
            int bytes_read = m_sbuf.ReadOffset(buffer, HEADER_SIZE,
                                               (int) len,
                                               (int) offset);
            assert bytes_read == len;
        }
        if (logger.isLoggable(Level.FINE))
        {
            logger.log(Level.FINE, "<-- " + debugName + " <CONV=" + m_conv + "><FLG="
                + flags + "><SEQ=" + seq + ":" + (seq + len) + "><ACK=" + m_rcv_nxt + ">"
                + "<WND=" + m_rcv_wnd + "><SCALE=" + m_rwnd_scale + "><TS=" + now
                + "><TSR=" + m_ts_recent + "><LEN=" + len + ">");
        }
        WriteResult wres = m_notify.TcpWritePacket(this,
                                                   buffer,
                                                   (int) len + HEADER_SIZE);
        /**
         * Note: When len is 0, this is an ACK packet. We don't read the return
         * value for those, and thus we won't retry. So go ahead and treat the
         * packet as a success (basically simulate as if it were dropped), which
         * will prevent our timers from being messed up.
         */
        if ((wres != WriteResult.WR_SUCCESS) && (0 != len))
        {
            return wres;
        }
        m_t_ack = 0;
        if (len > 0)
        {
            m_lastsend = now;
        }
        m_lasttraffic = now;
        m_bOutgoing = true;

        return WriteResult.WR_SUCCESS;
    }

    /**
     * Creates new segment from the data in <tt>buffer</tt> which is processed
     * by the protocol.
     *
     * @param buffer source buffer
     * @param size data length
     * @return true if successfully parsed the data
     */
    boolean parse(byte[] buffer, int size)
    {
        if (size < 12)
        {
            return false;
        }

        Segment seg = new Segment();
        seg.conv = bytes_to_long(buffer, 0);
        seg.seq = bytes_to_long(buffer, 4);
        seg.ack = bytes_to_long(buffer, 8);
        seg.flags = buffer[13];
        seg.wnd = bytes_to_short(buffer, 14);

        seg.tsval = bytes_to_long(buffer, 16);
        seg.tsecr = bytes_to_long(buffer, 20);

        seg.data = copy_buffer(buffer, HEADER_SIZE, size - HEADER_SIZE);
        seg.len = size - HEADER_SIZE;

        if (logger.isLoggable(Level.FINE))
        {
            logger.log(Level.FINE,
                       "--> " + debugName + "<CONV=" + seg.conv + "><FLG=" + seg.flags
                + "><SEQ=" + seg.seq + ":" + (seg.seq + seg.len) + "><ACK=" + seg.ack
                + "><WND=" + seg.wnd + "><SCALE=" + m_swnd_scale + "><TS=" + seg.tsval
                + "><TSR=" + seg.tsecr + "><LEN=" + seg.len + ">");
        }
        return process(seg);
    }

    /**
     * Calculates timeout in ms for current operation
     *
     * @param now current timestamp in ms
     * @return next timeout or -1 in case of an error
     */
    long clock_check(long now)
    {
        if (m_shutdown == EnShutdown.SD_FORCEFUL)
        {
            return -1;
        }

        long nTimeout;
        long snd_buffered;
        snd_buffered = m_sbuf.GetBuffered();
        if ((m_shutdown == EnShutdown.SD_GRACEFUL)
            && ((m_state != PseudoTcpState.TCP_ESTABLISHED)
            || ((snd_buffered == 0) && (m_t_ack == 0))))
        {
            return -1;
        }

        if (m_state == PseudoTcpState.TCP_CLOSED)
        {
            return CLOSED_TIMEOUT;
        }

        nTimeout = DEFAULT_TIMEOUT;

        if (m_t_ack > 0)
        {
            nTimeout = Math.min(nTimeout, TimeDiff(m_t_ack + m_ack_delay, now));
        }
        if (m_rto_base > 0)
        {
            nTimeout = Math.min(nTimeout, TimeDiff(m_rto_base + m_rx_rto, now));
        }
        if (getM_snd_wnd() == 0)
        {
            nTimeout = Math.min(nTimeout, TimeDiff(m_lastsend + m_rx_rto, now));
        }
        if (PSEUDO_KEEPALIVE)
        {
            if (m_state == PseudoTcpState.TCP_ESTABLISHED)
            {
                nTimeout = Math.min(
                    nTimeout,
                    TimeDiff(m_lasttraffic + (m_bOutgoing ? IDLE_PING * 3 / 2 : IDLE_PING), now));
            }
        }
        //nTimeout is used on wait methods, so cannot be equal to 0
        return nTimeout <= 0 ? 1 : nTimeout;
    }

    /**
     * Process given segment
     *
     * @param seg
     * @return false in case of error
     */
    boolean process(Segment seg)
    {
        // If this is the wrong conversation, send a reset!?! (with the correct conversation?)
        if (seg.conv != m_conv)
        {
            //if ((seg.flags & FLAG_RST) == 0) {
            //  packet(tcb, seg.ack, 0, FLAG_RST, 0, 0);
            //}
            closedown(new IOException(
                debugName + " wrong conversation number, this: " + m_conv
                + " remote: " + seg.conv));
            return false;
        }

        long now = Now();
        m_lasttraffic = m_lastrecv = now;
        m_bOutgoing = false;

        if (m_state == PseudoTcpState.TCP_CLOSED)
        {
            // !?! send reset?
            closedown(new IOException(debugName + " in closed state"));
            return false;
        }

        // Check if this is a reset segment
        if ((seg.flags & FLAG_RST) > 0)
        {
            //closedown(PseudoTcpError.ECONNRESET);
            closedown(new IOException("Connection reset"));
            return false;
        }

        // Check for control data
        boolean bConnect = false;
        if ((seg.flags & FLAG_CTL) > 0)
        {
            if (seg.len == 0)
            {
                logger.log(Level.SEVERE, debugName + " Missing control code");
                return false;
            }
            else
            {
                if (seg.data[0] == CTL_CONNECT)
                {
                    bConnect = true;

                    // TCP options are in the remainder of the payload after CTL_CONNECT.
                    parseOptions(seg.data, 1, seg.len - 1);

                    if (m_state == PseudoTcpState.TCP_LISTEN)
                    {
                        m_state = PseudoTcpState.TCP_SYN_RECEIVED;
                        logger.log(Level.FINE,
                                   debugName + " State: TCP_SYN_RECEIVED");
                        //m_notify->associate(addr);
                        queueConnectMessage();
                    }
                    else
                    {
                        if (m_state == PseudoTcpState.TCP_SYN_SENT)
                        {
                            m_state = PseudoTcpState.TCP_ESTABLISHED;
                            logger.log(Level.FINE,
                                       debugName + " State: TCP_ESTABLISHED");
                            adjustMTU();
                            if (m_notify != null)
                            {
                                m_notify.OnTcpOpen(this);
                            }
                            //notify(evOpen);
                        }
                    }
                }
                else
                {
                    logger.log(Level.SEVERE,
                               debugName + " Unknown control code: " + seg.data[0]);
                    return false;
                }
            }
        }

        // Update timestamp
        if ((seg.seq <= m_ts_lastack) && (m_ts_lastack < seg.seq + seg.len))
        {
            m_ts_recent = seg.tsval;
        }

        // Check if this is a valuable ack
        if ((seg.ack > m_snd_una) && (seg.ack <= m_snd_nxt))
        {
            // Calculate round-trip time
            if (seg.tsecr > 0)
            {
                long rtt = TimeDiff(now, seg.tsecr);
                assert rtt >= 0;
                if (m_rx_srtt == 0)
                {
                    m_rx_srtt = rtt;
                    m_rx_rttvar = rtt / 2;
                }
                else
                {
                    m_rx_rttvar = (3 * m_rx_rttvar + Math.abs(rtt - m_rx_srtt)) / 4;
                    m_rx_srtt = (7 * m_rx_srtt + rtt) / 8;
                }
                m_rx_rto = bound(MIN_RTO, m_rx_srtt
                    + Math.max(1, 4 * m_rx_rttvar),
                                 MAX_RTO);
                if (logger.isLoggable(Level.FINER))
                {
                    logger.log(Level.FINER,
                               "rtt: " + rtt + " srtt: " + m_rx_srtt + " rto: " + m_rx_rto);
                }
            }

            m_snd_wnd = seg.wnd << m_swnd_scale;
            //setWindowWithScale(seg.wnd, getM_swnd_scale());
            //setM_snd_wnd(seg.wnd << m_swnd_scale);

            long nAcked = seg.ack - m_snd_una;
            m_snd_una = seg.ack;

            m_rto_base = (m_snd_una == m_snd_nxt) ? 0 : now;

            m_sbuf.ConsumeReadData((int) nAcked);
            synchronized (ack_notify)
            {
                if (logger.isLoggable(Level.FINER))
                {
                    logger.log(Level.FINER,
                               debugName + " acked: " + nAcked
                        + " m_snd_una: " + m_snd_una);
                }
                ack_notify.notifyAll();
            }

            for (long nFree = nAcked; nFree > 0;)
            {
                assert !m_slist.isEmpty();
                if (nFree < m_slist.get(0).len)
                {
                    m_slist.get(0).len -= nFree;
                    nFree = 0;
                }
                else
                {
                    if (m_slist.get(0).len > m_largest)
                    {
                        m_largest = m_slist.get(0).len;
                    }
                    nFree -= m_slist.get(0).len;
                    m_slist.remove(0);
                    //m_slist.pop_front();
                }
            }

            if (m_dup_acks >= 3)
            {
                if (m_snd_una >= m_recover)
                { // NewReno
                    long nInFlight = m_snd_nxt - m_snd_una;
                    m_cwnd = Math.min(m_ssthresh, nInFlight + m_mss); // (Fast Retransmit)
                    logger.log(Level.FINE, "exit recovery");
                    m_dup_acks = 0;
                }
                else
                {
                    logger.log(Level.FINE, "recovery retransmit");
                    if (!transmit(m_slist.get(0), now))
                    {
                        //closedown(PseudoTcpError.ECONNABORTED);
                        closedown(new IOException("Connection aborted"));
                        return false;
                    }
                    m_cwnd += m_mss - Math.min(nAcked, m_cwnd);
                }
            }
            else
            {
                m_dup_acks = 0;
                // Slow start, congestion avoidance
                if (m_cwnd < m_ssthresh)
                {
                    m_cwnd += m_mss;
                }
                else
                {
                    m_cwnd += Math.max(1, m_mss * m_mss / m_cwnd);
                }
            }
        }
        else
        {
            if (seg.ack == m_snd_una)
            {
                // !?! Note, tcp says don't do this... but otherwise how does a closed window become open?
                //setWindowWithScale(seg.wnd, getM_swnd_scale());
                m_snd_wnd = seg.wnd << m_swnd_scale;
                //setM_snd_wnd(seg.wnd << m_swnd_scale);

                // Check duplicate acks
                if (seg.len > 0)
                {
                    // it's a dup ack, but with a data payload, so don't modify m_dup_acks
                }
                else
                {
                    if (m_snd_una != m_snd_nxt)
                    {
                        m_dup_acks += 1;
                        if (m_dup_acks == 3)
                        { // (Fast Retransmit)
                            if (logger.isLoggable(Level.FINE))
                            {
                                logger.log(Level.FINE,
                                           debugName + " enter recovery");
                                logger.log(Level.FINE,
                                           debugName + " recovery retransmit");
                            }
                            if (!transmit(m_slist.get(0), now))
                            {
                                closedown(new IOException("Connection aborted"));
                                //closedown(PseudoTcpError.ECONNABORTED);
                                return false;
                            }
                            m_recover = m_snd_nxt;
                            long nInFlight = m_snd_nxt - m_snd_una;
                            m_ssthresh = Math.max(nInFlight / 2, 2 * m_mss);
                            //Logger.Log(LS_INFO) << "m_ssthresh: " << m_ssthresh << "  nInFlight: " << nInFlight << "  m_mss: " << m_mss;
                            m_cwnd = m_ssthresh + 3 * m_mss;
                        }
                        else
                        {
                            if (m_dup_acks > 3)
                            {
                                m_cwnd += m_mss;
                            }
                        }
                    }
                    else
                    {
                        m_dup_acks = 0;
                    }
                }
            }
        }
        // !?! A bit hacky
        if ((m_state == PseudoTcpState.TCP_SYN_RECEIVED) && !bConnect)
        {
            m_state = PseudoTcpState.TCP_ESTABLISHED;
            logger.log(Level.FINE, debugName + " State: TCP_ESTABLISHED");
            adjustMTU();
            if (m_notify != null)
            {
                m_notify.OnTcpOpen(this);
            }
            //notify(evOpen);
        }
        // If we make room in the send queue, notify the user
        // The goal it to make sure we always have at least enough data to fill the
        // window.  We'd like to notify the app when we are halfway to that point.
        long kIdealRefillSize = (m_sbuf_len + m_rbuf_len) / 2;
        long snd_buffered = m_sbuf.GetBuffered();
        if (m_bWriteEnable && snd_buffered < kIdealRefillSize)
        {
            m_bWriteEnable = false;
            if (m_notify != null)
            {
                m_notify.OnTcpWriteable(this);
            }
            //notify(evWrite);
        }
        // Conditions were acks must be sent:
        // 1) Segment is too old (they missed an ACK) (immediately)
        // 2) Segment is too new (we missed a segment) (immediately)
        // 3) Segment has data (so we need to ACK!) (delayed)
        // ... so the only time we don't need to ACK, is an empty segment that points to rcv_nxt!
        SendFlags sflags = SendFlags.sfNone;
        if (seg.seq != m_rcv_nxt)
        {
            sflags = SendFlags.sfImmediateAck; // (Fast Recovery)
        }
        else
        {
            if (seg.len
                != 0)
            {
                if (m_ack_delay == 0)
                {
                    sflags = SendFlags.sfImmediateAck;
                }
                else
                {
                    sflags = SendFlags.sfDelayedAck;
                }
            }
        }

        if (sflags == SendFlags.sfImmediateAck)
        {
            if (seg.seq > m_rcv_nxt)
            {
                logger.log(Level.FINER, "too new");
            }
            else
            {
                if (seg.seq + seg.len <= m_rcv_nxt)
                {
                    logger.log(Level.FINER, "too old");
                }
            }
        }

        // Adjust the incoming segment to fit our receive buffer
        if (seg.seq < m_rcv_nxt)
        {
            long nAdjust = m_rcv_nxt - seg.seq;
            if (nAdjust < seg.len)
            {
                seg.seq += nAdjust;
                seg.data = ScrollBuffer(seg.data, nAdjust);
                seg.len -= nAdjust;
            }
            else
            {
                seg.len = 0;
            }
        }
        long available_space = m_rbuf.GetWriteRemaining();
        if ((seg.seq + seg.len - m_rcv_nxt) > available_space)
        {
            long nAdjust = seg.seq + seg.len - m_rcv_nxt - available_space;
            if (nAdjust < seg.len)
            {
                seg.len -= nAdjust;
            }
            else
            {
                seg.len = 0;
            }
        }
        boolean bIgnoreData = ((seg.flags & FLAG_CTL) > 0) || (m_shutdown != EnShutdown.SD_NONE);
        boolean bNewData = false;
        if (seg.len > 0)
        {
            if (bIgnoreData)
            {
                if (seg.seq == m_rcv_nxt)
                {
                    m_rcv_nxt += seg.len;
                }
            }
            else
            {
                long nOffset = seg.seq - m_rcv_nxt;

                int result = m_rbuf.WriteOffset(seg.data, seg.len,
                                                (int) nOffset);
                assert result == seg.len;

                if (seg.seq == m_rcv_nxt)
                {
                    if (logger.isLoggable(Level.FINEST))
                    {
                        logger.log(Level.FINEST,
                                   "Avail space: " + available_space
                            + " seg.len: " + seg.len);
                    }
                    m_rbuf.ConsumeWriteBuffer(seg.len);
                    m_rcv_nxt += seg.len;
                    m_rcv_wnd -= seg.len;
                    bNewData = true;


                    Iterator<RSegment> iter = m_rlist.iterator();
                    List<RSegment> toBeRemoved = new ArrayList<RSegment>();
                    while (iter.hasNext())
                    {
                        RSegment it = iter.next();
                        if (it.seq > m_rcv_nxt)
                        {
                            break;
                        }
                        if (it.seq + it.len > m_rcv_nxt)
                        {
                            sflags = SendFlags.sfImmediateAck; // (Fast Recovery)
                            long nAdjust = (it.seq + it.len) - m_rcv_nxt;
                            if (logger.isLoggable(Level.FINE))
                            {
                                logger.log(Level.FINE,
                                           "Recovered " + nAdjust + " bytes ("
                                    + m_rcv_nxt + " -> " + (m_rcv_nxt + nAdjust)
                                    + ")");
                            }
                            m_rbuf.ConsumeWriteBuffer((int) nAdjust);
                            m_rcv_nxt += nAdjust;
                            m_rcv_wnd -= nAdjust;
                        }
                        toBeRemoved.add(it);
                    }
                    m_rlist.removeAll(toBeRemoved);
                }
                else
                {
                    if (logger.isLoggable(Level.FINE))
                    {
                        logger.log(Level.FINE,
                                   "Saving " + seg.len + " bytes (" + seg.seq
                            + " -> " + (seg.seq + seg.len) + ")");
                    }
                    RSegment rseg = new RSegment(seg.seq, seg.len);
                    int insertPos;
                    for (insertPos = 0; insertPos < m_rlist.size(); insertPos++)
                    {
                        RSegment it = m_rlist.get(insertPos);
                        if (it.seq >= rseg.seq)
                        {
                            break;
                        }
                    }
                    m_rlist.add(insertPos, rseg);
                }
            }
        }

        attemptSend(sflags);
        // If we have new data, notify the user
        if (bNewData && m_bReadEnable)
        {
            m_bReadEnable = false;
            if (m_notify != null)
            {
                m_notify.OnTcpReadable(this);
            }
            //notify(evRead);
        }
        return true;
    }

    /**
     * Util time method
     *
     * @param later timestamp in ms
     * @param earlier timestamp in ms
     * @return difference between <tt>later</tt> and <tt>earlier</tt>
     */
    private static long TimeDiff(long later, long earlier)
    {
        return later - earlier;
    }

    /**
     * Stores 32 bit unsigned int in a buffer at specified offset
     *
     * @param anUnsignedInt
     * @param buf destination buffer
     * @param offset destination buffer's offset
     */
    private static void long_to_bytes(long anUnsignedInt, byte[] buf, int offset)
    {
        buf[offset] = (byte) ((anUnsignedInt & 0xFF000000L) >>> 24);
        buf[offset + 1] = (byte) ((anUnsignedInt & 0x00FF0000L) >>> 16);
        buf[offset + 2] = (byte) ((anUnsignedInt & 0x0000FF00L) >>> 8);
        buf[offset + 3] = (byte) ((anUnsignedInt & 0x000000FFL));
        //java.nio.ByteBuffer.wrap(buffer, offset, 4).putInt((int) (m_conv & 0xFFFFFFFFL));
    }

    /**
     * Stores 16 bit unsigned int in the buffer at specified offset
     *
     * @param anUnsignedShort
     * @param buf destination buffer
     * @param offset destination buffer's offset
     */
    private static void short_to_bytes(int anUnsignedShort, byte[] buf, int offset)
    {
        buf[offset] = (byte) ((anUnsignedShort & 0xFF00) >>> 8);
        buf[offset + 1] = (byte) ((anUnsignedShort & 0x00FF));
        //java.nio.ByteBuffer.wrap(buffer, offset, 2).putShort((short) (shrt & 0xFFFF));
    }

    /**
     * Reads 32 bit unsigned int from the buffer at specified offset
     *
     * @param buffer
     * @param offset
     * @return 32 bit unsigned value
     */
    private static long bytes_to_long(byte[] buffer, int offset)
    {
        int fByte = (0x000000FF & ((int) buffer[offset]));
        int sByte = (0x000000FF & ((int) buffer[offset + 1]));
        int tByte = (0x000000FF & ((int) buffer[offset + 2]));
        int foByte = (0x000000FF & ((int) buffer[offset + 3]));
        return ((long) (fByte << 24
            | sByte << 16
            | tByte << 8
            | foByte))
            & 0xFFFFFFFFL;
    }

    /**
     * Reads 16 bit unsigned int from the buffer at specified offset
     *
     * @param buffer
     * @param offset
     * @return 16 bit unsigned int
     */
    private static int bytes_to_short(byte[] buffer, int offset)
    {
        int fByte = (0x000000FF & ((int) buffer[offset]));
        int sByte = (0x000000FF & ((int) buffer[offset + 1]));
        return ((fByte << 8
            | sByte))
            & 0xFFFF;
    }

    /**
     * Wrapped system function arrayCopy
     *
     * @param buffer source buffer
     * @param sOffset source buffer offset
     * @param len bytes count to be copied
     * @return new buffer size of <tt>len</tt>
     */
    private static byte[] copy_buffer(byte[] buffer, int sOffset, int len)
    {
        byte[] newData = new byte[len];
        System.arraycopy(buffer, sOffset, newData, 0, len);
        return newData;
    }

    /**
     *
     * @param lower
     * @param middle
     * @param upper
     * @return
     */
    private long bound(long lower, long middle, long upper)
    {
        return Math.min(Math.max(lower, middle), upper);
    }

    private byte[] ScrollBuffer(byte[] data, long nAdjust)
    {
        //TODO: never been hit so far, to be implemented
        throw new UnsupportedOperationException("Not yet implemented");
    }

    /**
     * Transmits given segment
     *
     * @param seg segment to be sent
     * @param now current timestamp
     * @return false in case of error
     */
    boolean transmit(SSegment seg, long now)
    {
        //  Logger.Log(LS_INFO) << "seg->xmit: "<< seg->xmit;
        if (seg.xmit >= ((m_state == PseudoTcpState.TCP_ESTABLISHED) ? 15 : 30))
        {
            logger.log(Level.FINE, "too many retransmits");
            return false;
        }

        long nTransmit = Math.min(seg.len, m_mss);

        while (true)
        {
            long seq = seg.seq;
            short flags = (seg.bCtrl ? FLAG_CTL : 0);
            WriteResult wres = packet(seq,
                                      flags,
                                      seg.seq - m_snd_una,
                                      nTransmit);

            if (wres == WriteResult.WR_SUCCESS)
            {
                break;
            }

            if (wres == WriteResult.WR_FAIL)
            {
                logger.log(Level.WARNING, "packet failed");
                return false;
            }

            assert wres == WriteResult.WR_TOO_LARGE;

            while (true)
            {
                if (PACKET_MAXIMUMS[(m_msslevel + 1)] == 0)
                {
                    logger.log(Level.INFO, "MTU too small");
                    return false;
                }
                // !?! We need to break up all outstanding and pending packets and then retransmit!?!

                m_mss = PACKET_MAXIMUMS[++m_msslevel] - PACKET_OVERHEAD;
                m_cwnd = 2 * m_mss; // I added this... haven't researched actual formula
                if (m_mss < nTransmit)
                {
                    nTransmit = m_mss;
                    break;
                }
            }
            if (logger.isLoggable(Level.INFO))
            {
                logger.log(Level.INFO, "Adjusting mss to " + m_mss + " bytes");
            }
        }

        if (nTransmit < seg.len)
        {
            if (logger.isLoggable(Level.INFO))
            {
                logger.log(Level.INFO, "mss reduced to " + m_mss);
            }
            SSegment subseg = new SSegment(seg.seq + nTransmit,
                                           seg.len - nTransmit, seg.bCtrl);
            //subseg.tstamp = seg->tstamp;
            subseg.xmit = seg.xmit;
            seg.len = nTransmit;

            //SList::iterator next = seg;                        
            m_slist.add(m_slist.indexOf(seg) + 1, subseg);
        }

        if (seg.xmit == 0)
        {
            m_snd_nxt += seg.len;
        }
        seg.xmit += 1;
        //seg->tstamp = now;
        if (m_rto_base == 0)
        {
            m_rto_base = now;
        }

        return true;
    }

    /**
     * This method checks if it's time to send a packet(ack or retransmit
     * anything)
     *
     * @param sflags
     */
    void attemptSend(SendFlags sflags)
    {
        long now = Now();

        if (TimeDiff(now, m_lastsend) > m_rx_rto)
        {
            m_cwnd = m_mss;
        }
        boolean bFirst = true;

        while (true)
        {
            long cwnd = m_cwnd;
            if ((m_dup_acks == 1) || (m_dup_acks == 2))
            { // Limited Transmit
                cwnd += m_dup_acks * m_mss;
            }
            long nWindow = Math.min(getM_snd_wnd(), cwnd);
            long nInFlight = m_snd_nxt - m_snd_una;
            long nUseable = (nInFlight < nWindow) ? (nWindow - nInFlight) : 0;

            long snd_buffered = m_sbuf.GetBuffered();
            /*
             * System.out.println("is available? buffered: " + snd_buffered + "
             * inFlight: " + nInFlight + " m_mss: " + m_mss + " m_snd_wnd: " +
             * getM_snd_wnd() + " cwnd: " + cwnd + " nWindow: " + nWindow + "
             * nUseable: " + nUseable);
             */
            long nAvailable = Math.min(snd_buffered - nInFlight, m_mss);

            if (nAvailable > nUseable)
            {
                if (nUseable * 4 < nWindow)
                {
                    // RFC 813 - avoid SWS
                    logger.log(Level.FINER,
                               "RFC 813 - avoid SWS(nAvailable = 0)");
                    nAvailable = 0;
                }
                else
                {
                    nAvailable = nUseable;
                }
            }

            if (bFirst)
            {
                long available_space = m_sbuf.GetWriteRemaining();

                bFirst = false;
                if (logger.isLoggable(Level.FINE))
                {
                    logger.log(Level.FINE,
                               "[cwnd: " + m_cwnd + " nWindow: " + nWindow
                        + " nInFlight: " + nInFlight + " nAvailable: " + nAvailable
                        + " nQueued: " + snd_buffered + " nEmpty: " + available_space
                        + " ssthresh: " + m_ssthresh + "]");
                }
            }

            if (nAvailable == 0)
            {
                if (sflags == SendFlags.sfNone)
                {
                    logger.log(Level.FINEST, "nAvailable == 0: quit");
                    return;
                }

                // If this is an immediate ack, or the second delayed ack
                if ((sflags == SendFlags.sfImmediateAck) || (m_t_ack > 0))
                {
                    packet(m_snd_nxt, (short) 0, 0, 0);
                    logger.log(Level.FINER, "Immediate ack: ");
                }
                else
                {
                    m_t_ack = Now();
                    logger.log(Level.FINER, "Delayed ack, m_t_ack: " + m_t_ack);
                }
                return;
            }

            // Nagle's algorithm.
            // If there is data already in-flight, and we haven't a full segment of
            // data ready to send then hold off until we get more to send, or the
            // in-flight data is acknowledged.
            if (m_use_nagling && (m_snd_nxt > m_snd_una) && (nAvailable < m_mss))
            {
                logger.log(Level.FINER, "wait untill more data is acked");
                return;
            }

            // Find the next segment to transmit
            SSegment seg = null;
            Iterator<SSegment> iter = m_slist.iterator();
            do
            {
                SSegment it = iter.next();
                if (it.xmit == 0)
                {
                    seg = it;
                    break;
                }
            }
            while (iter.hasNext());

            assert seg != null;

            // If the segment is too large, break it into two
            if (seg.len > nAvailable)
            {
                logger.log(Level.FINEST, "Break a segment into 2");
                SSegment subseg = new SSegment(
                    seg.seq + nAvailable,
                    seg.len - nAvailable,
                    seg.bCtrl);
                seg.len = nAvailable;
                //m_slist.insert(++it, subseg);
                m_slist.add(m_slist.indexOf(seg) + 1, subseg);
            }
            if (logger.isLoggable(Level.FINEST))
            {
                logger.log(Level.FINEST,
                           "TRANSMIT SEGMENT seq: " + seg.seq
                    + " len: " + seg.len);
            }
            if (!transmit(seg, now))
            {
                logger.log(Level.SEVERE, "transmit failed");
                // TODO: consider closing socket
                return;
            }

            sflags = SendFlags.sfNone;
        }
    }

    /**
     * This metod is called in case of en error. Tcp enters closed state and
     * notifies listener about it.
     *
     * @param e exception to be propagated
     */
    void closedown(IOException e)
    {
        logger.log(Level.FINE, debugName + " State: TCP_CLOSED ");
        m_state = PseudoTcpState.TCP_CLOSED;
        if (m_notify != null)
        {
            m_notify.OnTcpClosed(this, e);
        }
    }

    /**
     * Adjusts MTU
     */
    void adjustMTU()
    {
        // Determine our current mss level, so that we can adjust appropriately later
        for (m_msslevel = 0; PACKET_MAXIMUMS[(m_msslevel + 1)] > 0; ++m_msslevel)
        {
            if (PACKET_MAXIMUMS[m_msslevel] <= m_mtu_advise)
            {
                break;
            }
        }
        m_mss = m_mtu_advise - PACKET_OVERHEAD;
        // !?! Should we reset m_largest here?        
        logger.log(Level.INFO, "Adjusting mss to " + m_mss + " bytes");

        // Enforce minimums on ssthresh and cwnd
        m_ssthresh = Math.max(m_ssthresh, 2 * m_mss);
        m_cwnd = Math.max(m_cwnd, m_mss);
    }

    /**
     *
     * @return true if receive buffer is full
     */
    boolean isReceiveBufferFull()
    {
        return m_rbuf.GetWriteRemaining() == 0;
    }

    /**
     * Disables window scaling. Must be called before the connection is
     * established.
     */
    void disableWindowScale()
    {
        m_support_wnd_scale = false;
    }

    /**
     * Enqueues connect message
     */
    void queueConnectMessage()
    {
        byte[] buff = new byte[4];
        buff[0] = CTL_CONNECT & 0xFF;
        if (m_support_wnd_scale)
        {
            buff[1] = TCP_OPT_WND_SCALE & 0xFF;
            buff[2] = 1;
            buff[3] = (byte) (m_rwnd_scale & 0xFF);
        }
        m_snd_wnd = buff.length;
        queue(buff, 0, buff.length, true);
    }

    /**
     * Parse and process option in given buffer/offset/length
     *
     * @param data source buffer
     * @param offset source offset
     * @param len byte count
     */
    void parseOptions(byte[] data, int offset, int len)
    {
        List<Short> options_specified = new ArrayList<Short>();

        // See http://www.freesoft.org/CIE/Course/Section4/8.htm for
        // parsing the options list.
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(data, offset, len);
        while (buf.hasRemaining())
        {
            short kind = TCP_OPT_EOL;
            short tmp = buf.get();
            if (tmp != -1)
            {
                kind = tmp;
            }
            if (kind == TCP_OPT_EOL)
            {
                // End of option list.
                break;
            }
            else
            {
                if (kind == TCP_OPT_NOOP)
                {
                    // No op.
                    continue;
                }
            }

            // Length of this option.
            assert len != 0;
            //UNUSED(len);
            short opt_len = buf.get();

            // Content of this option.
            if (opt_len <= buf.remaining())
            {
                byte[] opt_data = new byte[opt_len];
                buf.get(opt_data);
                applyOption(kind, opt_data, opt_len);
            }
            else
            {
                logger.log(Level.SEVERE, "Invalid option length received.");
                return;
            }
            options_specified.add(kind);
        }

        if (options_specified.indexOf(TCP_OPT_WND_SCALE) == -1)//options_specified.size() - 1)
        {
            logger.log(Level.WARNING, "Peer doesn't support window scaling");
            if (getM_rwnd_scale() > 0)
            {
                // Peer doesn't support TCP options and window scaling.
                // Revert receive buffer size to default value.
                resizeReceiveBuffer(DEFAULT_RCV_BUF_SIZE);
                m_swnd_scale = 0;
            }
        }
    }

    /**
     * Applies <tt>kind</tt> of option and it's data
     *
     * @param kind option type
     * @param data option's data buffer
     * @param len data length
     */
    void applyOption(short kind, byte[] data, long len)
    {
        if (kind == TCP_OPT_MSS)
        {
            logger.log(
                Level.WARNING,
                "Peer specified MSS option which is not supported.");
            // TODO: Implement.
        }
        else
        {
            if (kind == TCP_OPT_WND_SCALE)
            {
                // Window scale factor.
                // http://www.ietf.org/rfc/rfc1323.txt
                if (len != 1)
                {
                    logger.log(Level.SEVERE, "Invalid window scale option received.");
                    return;
                }
                applyWindowScaleOption(data[0]);
            }
        }
    }

    /**
     * Applies window scale option with given <tt>scale_factor</tt>
     *
     * @param scale_factor
     */
    void applyWindowScaleOption(short scale_factor)
    {
        m_swnd_scale = scale_factor;
    }

    /**
     * Resizes send buffer to <tt>new_size</tt>
     *
     * @param new_size
     */
    void resizeSendBuffer(int new_size)
    {
        m_sbuf_len = new_size;
        m_sbuf.SetCapacity(new_size);
    }

    /**
     * Resizes receive buffer to <tt>new_size</tt>
     *
     * @param new_size
     */
    void resizeReceiveBuffer(int new_size)
    {
        short scale_factor = 0;

        // Determine the scale factor such that the scaled window size can fit
        // in a 16-bit unsigned integer.
        while (new_size > 0xFFFF)
        {
            ++scale_factor;
            new_size >>= 1;
        }

        // Determine the proper size of the buffer.
        new_size <<= scale_factor;
        boolean result = m_rbuf.SetCapacity(new_size);

        // Make sure the new buffer is large enough to contain data in the old
        // buffer. This should always be true because this method is called either
        // before connection is established or when peers are exchanging connect
        // messages.
        assert result;
        m_rbuf_len = new_size;
        m_rwnd_scale = scale_factor;
        m_ssthresh = new_size;

        int available_space = m_rbuf.GetWriteRemaining();
        m_rcv_wnd = available_space;
    }

    /**
     * @return send window size
     */
    int getM_snd_wnd()
    {
        return m_snd_wnd;
    }

    /**
     *
     * @return current @link{PseudoTcpState}
     */
    public PseudoTcpState getState()
    {
        return m_state;
    }

    /**
     *
     * @return send buffer's length
     */
    int getSendBufferSize()
    {
        return m_sbuf_len;
    }

    /**
     *
     * @return receive buffer's length
     */
    int getRecvBufferSize()
    {
        return m_rbuf_len;
    }

    /**
     * @return the receive window scale
     */
    public short getM_rwnd_scale()
    {
        return m_rwnd_scale;
    }

    /**
     * @return the send window scale
     */
    public short getM_swnd_scale()
    {
        return m_swnd_scale;
    }
    private final Object ack_notify = new Object();

    public Object GetAckNotify()
    {
        return ack_notify;
    }
}

/**
 * Class used internally as a structure for receive segments
 *
 * @author Pawel
 */
class RSegment
{
    public long seq, len;

    public RSegment(long seq, long len)
    {
        this.seq = seq;
        this.len = len;
    }
}

/**
 * Class used internally as a structure for send segments
 *
 * @author Pawel Domas
 */
class SSegment
{
    long seq, len;
    //uint32 tstamp;
    short xmit;
    boolean bCtrl;

    SSegment(long s, long l, boolean c)
    {
        seq = s;
        len = l;
        xmit = 0;
        bCtrl = c;
    }
}

/**
 * Shutdown enum used internally
 *
 * @author Pawel Domas
 */
enum EnShutdown
{
    /**
     * There was no shutdown
     */
    SD_NONE,
    /**
     * There was a graceful shutdown
     */
    SD_GRACEFUL,
    /**
     * There was a forceful shutdown
     */
    SD_FORCEFUL
};

/**
 * Options used in pseudotcp
 *
 * @author Pawel Domas
 */
enum Option
{
    /**
     * Whether to enable Nagle's algorithm (0 == off)
     */
    OPT_NODELAY,
    /**
     * The Delayed ACK timeout (0 == off).
     */
    OPT_ACKDELAY,
    /**
     * Set the receive buffer size, in bytes.
     */
    OPT_RCVBUF,
    /**
     * Set the send buffer size, in bytes.
     */
    OPT_SNDBUF,
};

/**
 * Send flags used internally
 *
 * @author Pawel Domas
 */
enum SendFlags
{
    sfNone, sfImmediateAck, sfDelayedAck;
}

/**
 * Class used internally as a segment structure
 *
 * @author Pawel Domas
 */
class Segment
{
    long conv;
    long seq;
    long ack;
    byte flags;
    int wnd;
    long tsval;
    long tsecr;
    byte[] data;
    int len;
}