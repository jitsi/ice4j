/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.pseudotcp;

import java.io.*;
import java.net.*;
import java.util.logging.*;

public class PseudoTcpSocket implements IPseudoTcpNotify
{
    /**
     * The logger.
     */
    private static final java.util.logging.Logger logger =
        java.util.logging.Logger.getLogger(PseudoTCPBase.class.getName());
    /**
     * Pseudotcp logic instance
     */
    private final PseudoTCPBase pseudoTcp;
    /**
     * Datagram socket used to handle network operations
     */
    private final DatagramSocket socket;
    /**
     * Current socket address of remote socket that we are connected to
     */
    private SocketAddress remoteAddr;
    /**
     * Receive buffer size used for receiving packets TODO: this should be
     * checked with MTU ?
     */
    private int DATAGRAM_RCV_BUFFER_SIZE = 70000;
    /**
     * Monitor object used to block threads on write operation. That is when the
     * send buffer is full.
     */
    private final Object write_notify = new Object();
    /**
     * Monitor object used to block threads on read operation. That is when
     * there's no more data available for reading.
     */
    private final Object read_notify = new Object();
    /**
     * Monitor object used to block thread waiting for change of TCP state.
     */
    private final Object state_notify = new Object();
    /**
     * Monitor object used by clock thread. Clock thread sleeps for some
     * intervals given by pseudotcp logic, but sometimes it is required to
     * finish this sleep earlier. In that case notify method of this monitor is
     * called.
     */
    private final Object clock_notify = new Object();
    /**
     * Exception which occurred in pseudotcp logic and must be propagated to
     * threads blocked on any operations.
     */
    private IOException exception;

    /**
     *
     * @param conv_id conversation id, must be the same on both sides
     * @param sock datagram socket used for network operations
     */
    public PseudoTcpSocket(long conv_id, DatagramSocket sock)
    {
        pseudoTcp = new PseudoTCPBase(this, conv_id);
        this.socket = sock;
    }

    /**
     * This constructor creates <tt>DatagramSocket</tt> with random port. Should
     * be used for clients.
     *
     * @param conv_id conversation id, must be the same on both sides
     * @throws SocketException
     */
    public PseudoTcpSocket(long conv_id)
        throws SocketException
    {
        this(conv_id, new DatagramSocket());
    }

    /**
     * Binds <tt>DatagramSocket</tt> to given <tt>local_port</tt>
     *
     * @param conv_id conversation id, must be the same on both sides
     * @param local_port
     * @throws SocketException
     */
    public PseudoTcpSocket(long conv_id, int local_port)
        throws SocketException
    {
        this(conv_id, new DatagramSocket(local_port));
    }

    /**
     * Creates DatagramSocket for <tt>local_ip</tt>:<tt>local_port</tt>
     *
     * @param conv_id conversation id, must be the same on both sides
     * @param local_ip used by <tt>DatagramSocket</tt>
     * @param local_port used by <tt>DatagramSocket</tt>
     * @throws SocketException
     * @throws UnknownHostException
     */
    public PseudoTcpSocket(long conv_id, String local_ip, int local_port)
        throws SocketException,
               UnknownHostException
    {
        this(conv_id, new DatagramSocket(local_port,
                                         InetAddress.getByName(local_ip)));
    }

    /**
     * Start connection procedure
     *
     * @param remoteAddress to which this socket connects to
     * @param timeout for this operation in ms
     * @throws IOException
     */
    public void Connect(InetSocketAddress remoteAddress, long timeout)
        throws IOException
    {
        this.remoteAddr = remoteAddress;
        StartThreads();
        pseudoTcp.Connect();
        UpdateClock();
        try
        {
            long elapsed = 0;
            //Here the threads is blocked untill we reach TCP_ESTABLISHED state
            //There's also check for timeout for that op
            synchronized (state_notify)
            {
                while (pseudoTcp.getState() != PseudoTcpState.TCP_ESTABLISHED
                    && elapsed < timeout)
                {
                    long start = System.currentTimeMillis();
                    state_notify.wait(timeout);
                    long end = System.currentTimeMillis();
                    elapsed += end - start;
                }
                if (pseudoTcp.getState() != PseudoTcpState.TCP_ESTABLISHED)
                {
                    throw new IOException("Connect timeout");
                }
            }
        }
        catch (InterruptedException ex)
        {
            Close();
            throw new IOException("Connect aborted");
        }
    }

    /**
     * Start connection procedure
     *
     * @param ip destination ip address
     * @param port destination port
     * @param timeout for this operation in ms
     * @throws IOException
     */
    public void Connect(String ip, int port, long timeout)
        throws IOException
    {
        //this.remoteAddr = InetAddress.getByName(ip);
        //this.remotePort = port;
        Connect(new InetSocketAddress(InetAddress.getByName(ip), port), timeout);
    }

    /**
     * Blocking method waits for connection.
     *
     * @param timeout for this operation in ms
     * @throws IOException If socket gets closed or timeout expires
     */
    public void Accept(int timeout)
        throws IOException
    {
        try
        {
            StartThreads();
            PseudoTcpState state = pseudoTcp.getState();
            if (state == PseudoTcpState.TCP_CLOSED)
            {
                throw new IOException("Socket closed");
            }
            if (pseudoTcp.getState() != PseudoTcpState.TCP_ESTABLISHED)
            {
                synchronized (state_notify)
                {
                    state_notify.wait(timeout);
                }
            }
            if (pseudoTcp.getState() != PseudoTcpState.TCP_ESTABLISHED)
            {
                throw new IOException("Accept timeout");
            }
        }
        catch (InterruptedException ex)
        {
            IOException e = new IOException("Accept aborted");
            pseudoTcp.closedown(e);
            throw e;
        }
    }

    /**
     *
     * @return current TCP state
     */
    public PseudoTcpState getState()
    {
        return pseudoTcp.getState();
    }

    /**
     * Interrupts clock thread's wait method to force time update
     */
    private void UpdateClock()
    {
        synchronized (clock_notify)
        {
            clock_notify.notifyAll();
        }
    }

    /**
     * Starts all threads required by the socket
     */
    private void StartThreads()
    {
        pseudoTcp.NotifyClock(System.currentTimeMillis());
        receiveThread = new Thread(new Runnable()
        {
            public void run()
            {
                ReceivePackets();
            }
        }, "PseudoTcpReceiveThread");
        clockThread = new Thread(new Runnable()
        {
            public void run()
            {
                RunClock();
            }
        }, "PseudoTcpClockThread");
        runReceive = true;
        runClock = true;
        receiveThread.start();
        clockThread.start();
    }

    /**
     * Shutdown the socket
     *
     * @throws IOException
     */
    public void Close() throws IOException
    {
        try
        {
            pseudoTcp.Close(true);
            //System.out.println("ON CLOSE: in flight "+pseudoTcp.GetBytesInFlight());
            //System.out.println("ON CLOSE: buff not sent "+pseudoTcp.GetBytesBufferedNotSent());
            OnTcpClosed(pseudoTcp, null);
            socket.close();
            JoinAllThreads();
            //UpdateClock();
            //TODO: closing procedure
            //Here the thread should be blocked until TCP
            //reaches CLOSED state, but there's no closing procedure
            /*
             * synchronized(state_notify){ while(pseudoTcp.getState() !=
             * PseudoTcpState.TCP_CLOSED){ try { state_notify.wait(); } catch
             * (InterruptedException ex) { throw new IOException("Close
             * connection aborted"); } } }
             */
        }
        catch (InterruptedException ex)
        {
            throw new IOException("Closing socket interrupted", ex);
        }

    }

    /**
     * Implements @link(IPseudoTcpNotify)
     * Called when TCP enters connected state.
     *
     * @param tcp
     */
    public void OnTcpOpen(PseudoTCPBase tcp)
    {
        logger.log(Level.FINE, "tcp opened");
        //Release threads blocked at state_notify monitor object.
        synchronized (state_notify)
        {
            state_notify.notifyAll();
        }
        //TCP is considered writeable at this point
        OnTcpWriteable(tcp);
    }

    /**
     * Implements @link(IPseudoTcpNotify)
     *
     * @param tcp
     */
    public void OnTcpReadable(PseudoTCPBase tcp)
    {
        //release all thread blocked at read_notify monitor
        synchronized (read_notify)
        {
            logger.log(
                Level.FINER,
                "TCP READABLE data available for reading: ");
            read_notify.notifyAll();
        }
    }

    /**
     * Implements @link(IPseudoTcpNotify)
     *
     * @param tcp
     */
    public void OnTcpWriteable(PseudoTCPBase tcp)
    {

        logger.log(Level.FINER, "stream writeable");
        //release all threads blocked at write monitor
        synchronized (write_notify)
        {
            write_notify.notifyAll();
        }
        //writeSemaphore.release(1);        
        logger.log(Level.FINER, "write notified - now !");

    }

    /**
     * Implements @link(IPseudoTcpNotify)
     *
     * @param tcp
     * @param e
     */
    public void OnTcpClosed(PseudoTCPBase tcp, IOException e)
    {
        if (e != null)
        {
            e.printStackTrace();
            logger.log(Level.SEVERE, "PseudoTcp closed: " + e);
        }
        else
        {
            logger.log(Level.FINE, "PseudoTcp closed");
        }
        runReceive = false;
        runClock = false;
        this.exception = e;
        releaseAllLocks();
    }

    /**
     * Releases all monitor objects so that the threads will check their "run
     * flags"
     */
    private void releaseAllLocks()
    {
        synchronized (read_notify)
        {
            read_notify.notifyAll();
        }
        synchronized (write_notify)
        {
            write_notify.notifyAll();
        }
        synchronized (state_notify)
        {
            state_notify.notifyAll();
        }
        //this interrupt won't work for DatagramSocket read packet operation
        //receiveThread.interrupt();
        clockThread.interrupt();
    }

    /**
     * Joins all running threads
     *
     * @throws InterruptedException
     */
    private void JoinAllThreads() throws InterruptedException
    {
        clockThread.join();
        receiveThread.join();
    }

    /**
     * Implements @link(IPseudoTcpNotify)
     *
     * @param tcp
     * @param buffer
     * @param len
     * @return
     */
    public WriteResult TcpWritePacket(PseudoTCPBase tcp, byte[] buffer, int len)
    {
        if (logger.isLoggable(Level.FINEST))
        {
            logger.log(Level.FINEST, "write packet to network " + len);
        }
        try
        {
            DatagramPacket packet = new DatagramPacket(buffer, len, remoteAddr);
            socket.send(packet);
            return WriteResult.WR_SUCCESS;
        }
        catch (IOException ex)
        {
            logger.log(Level.SEVERE, "TcpWritePacket exception: " + ex);
            return WriteResult.WR_FAIL;
        }

    }
    /**
     * Flag which enables packets receive thread
     */
    private boolean runReceive = false;
    /**
     * Thread receiving packets from the network
     */
    private Thread receiveThread;

    /**
     * Receives packets from the network and passes them to TCP logic class
     */
    private void ReceivePackets()
    {
        byte[] buffer = new byte[DATAGRAM_RCV_BUFFER_SIZE];
        DatagramPacket packet = new DatagramPacket(buffer, DATAGRAM_RCV_BUFFER_SIZE);
        while (runReceive)
        {
            try
            {
                socket.receive(packet);
                //Here is the binding point for remote socket if wasn't
                //specified earlier
                if (remoteAddr == null)
                {
                    remoteAddr = packet.getSocketAddress();
                }
                else
                {
                    if (!packet.getSocketAddress().equals(remoteAddr))
                    {
                        logger.log(Level.WARNING,
                                   "Ignoring packet from " + packet.getAddress()
                            + ":" + packet.getPort() + " should be: " + remoteAddr);
                    }
                }
                synchronized (pseudoTcp)
                {
                    pseudoTcp.NotifyPacket(buffer, packet.getLength());
                    //we need to update the clock after new packet is receivied
                    UpdateClock();
                }
            }
            catch (IOException ex)
            {
                //this exception occurs even when the socket 
                //is closed with the close operation, so we check
                //here if this exception is important
                if (runReceive)
                {
                    logger.log(Level.SEVERE,
                               "ReceivePackets exception: " + ex);
                    pseudoTcp.closedown(ex);
                }
                break;
            }
        }
    }
    /**
     * The run flag for clock thread
     */
    private boolean runClock = false;
    private Thread clockThread;

    /**
     * Method runs cyclic notification about time progress for TCP logic class
     * It runs in a separate thread
     */
    private void RunClock()
    {
        long sleep;
        while (runClock)
        {
            synchronized (pseudoTcp)
            {
                pseudoTcp.NotifyClock(System.currentTimeMillis());
                sleep = pseudoTcp.GetNextClock(System.currentTimeMillis());
            }

            //there might be negative interval even if there's no error
            if (sleep == -1)
            {
                releaseAllLocks();
                if (exception != null)
                {
                    logger.log(Level.SEVERE,
                               "STATE: " + pseudoTcp.getState()
                        + " ERROR: " + exception.getMessage());
                }
                break;
            }
            synchronized (clock_notify)
            {
                try
                {
                    logger.log(Level.FINEST, "Clock sleep for " + sleep);
                    clock_notify.wait(sleep);
                }
                catch (InterruptedException ex)
                {
                    //interruption means end of task, as in normal operation 
                    //notify will be called
                    break;
                }
            }

        }
    }
    private OutputStream outputstream;

    /**
     * Lazy initialization for socket class
     *
     * @return output socket object
     */
    public OutputStream getOutputStream()
    {
        if (outputstream == null)
        {
            outputstream = new PseudoTcpOutputStream();
        }
        return outputstream;
    }
    private PseudoTcpInputStream inputStream;

    /**
     * Lazy initialization for socket class
     *
     * @return output socket object
     */
    public InputStream getInputStream()
    {
        if (inputStream == null)
        {
            inputStream = new PseudoTcpInputStream();
        }
        return inputStream;
    }

    /**
     * This class implements @link(InputStream)     *
     */
    class PseudoTcpInputStream extends InputStream
    {
        public PseudoTcpInputStream()
        {
        }

        @Override
        public boolean markSupported()
        {
            return false;
        }

        /**
         * There's no end of stream detection at the moment. Method blocks until
         * it returns any data or an exception is thrown
         *
         * @return read byte count
         * @throws IOException in case of en error
         */
        @Override
        public int read() throws IOException
        {
            byte[] buff = new byte[1];
            int readCount = read(buff, 0, 1);
            return readCount == 1 ? buff[0] : -1;
        }

        @Override
        public int read(byte[] bytes) throws IOException
        {
            return read(bytes, 0, bytes.length);
        }

        /**
         * This method blocks until any data is available
         *
         * @param buffer destination buffer
         * @param offset destination buffer's offset
         * @param length maximum count of bytes that can be read
         * @return byte count actually read
         * @throws IOException
         */
        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException
        {
            int read;
            while (true)
            {
                logger.log(Level.FINER, "Read Recv");
                read = pseudoTcp.Recv(buffer, offset, length);
                if (logger.isLoggable(Level.FINER))
                {
                    logger.log(Level.FINER, "Read Recv read count: " + read);
                }
                if (read > 0)
                {
                    return read;
                }
                try
                {
                    synchronized (read_notify)
                    {
                        logger.log(Level.FINER, "Read wait for data available");
                        read_notify.wait();
                        if (logger.isLoggable(Level.FINER))
                        {
                            logger.log(Level.FINER,
                                       "Read notified: " + pseudoTcp.GetAvailable());
                        }
                    }
                    if (exception != null)
                    {
                        throw exception;
                    }
                }
                catch (InterruptedException ex)
                {
                    if (exception != null)
                    {
                        throw new IOException("Read aborted", exception);
                    }
                    else
                    {
                        throw new IOException("Read aborted");
                    }
                }
            }
        }

        @Override
        public int available() throws IOException
        {
            return pseudoTcp.GetAvailable();
        }

        @Override
        public void close() throws IOException
        {
        }
    }

    /**
     * Implements @link(OutputStream)
     */
    class PseudoTcpOutputStream extends OutputStream
    {
        @Override
        public void write(int b) throws IOException
        {
            byte[] bytes = new byte[1];
            bytes[0] = (byte) b;
            write(b);
        }

        @Override
        public void write(byte[] bytes) throws IOException
        {
            write(bytes, 0, bytes.length);
        }

        /**
         * This method blocks until all data has been written or an exception
         * occurs
         *
         * @param buffer source buffer
         * @param offset source buffer's offset
         * @param length byte count to be written
         * @throws IOException
         */
        @Override
        public void write(byte[] buffer, int offset, int length) throws IOException
        {
            int toSend = length;
            int sent;
            while (toSend > 0)
            {
                synchronized (pseudoTcp)
                {
                    sent = pseudoTcp.Send(buffer, offset + length - toSend, toSend);
                }
                if (sent > 0)
                {
                    toSend -= sent;
                }
                else
                {
                    try
                    {
                        logger.log(Level.FINER, "Write wait for notify");
                        synchronized (write_notify)
                        {
                            write_notify.wait();
                        }
                        logger.log(Level.FINER,
                                   "Write notified, available: "
                            + pseudoTcp.GetAvailableSendBuffer());
                        if (exception != null)
                        {
                            throw exception;
                        }
                    }
                    catch (InterruptedException ex)
                    {
                        if (exception != null)
                        {
                            throw new IOException("Write aborted", exception);
                        }
                        else
                        {
                            throw new IOException("Write aborted", ex);
                        }
                    }
                }
            }
        }

        /**
         * This method block until all buffered data has been written
         *
         * @throws IOException
         */
        @Override
        public synchronized void flush() throws IOException
        {
            logger.log(Level.FINE, "Flushing...");
            final Object ackNotify = pseudoTcp.GetAckNotify();
            while (pseudoTcp.GetBytesBufferedNotSent() > 0)
            {
                synchronized (ackNotify)
                {
                    try
                    {
                        ackNotify.wait();
                    }
                    catch (InterruptedException ex)
                    {
                        throw new IOException("Flush stream interrupted", ex);
                    }
                }
            }
            logger.log(Level.FINE, "Flushing completed");
        }

        @Override
        public void close() throws IOException
        {
        }
    }
}
