package org.ice4j.util;

import org.junit.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.*;
import java.util.logging.Logger;  // Disambiguation

/**
 * A test to check behaviour of {@link java.net.DatagramSocket} on
 * {@link java.net.DatagramPacket} with various offset/length restrictions.
 *
 * @author Yura Yaroshevich
 */
public class DatagramPacketBufferTest
{
    /**
     * The <tt>Logger</tt> used by the <tt>DatagramPacketBufferTest</tt> class
     * and its instances for logging output.
     */
    private static final java.util.logging.Logger logger
        = Logger.getLogger(PacketQueueBenchmarkTests.class.getName());

    @Test
    public void testDatagramPacketOffsetAndLengthRespected() throws Exception
    {
        final CountDownLatch serverCompleted = new CountDownLatch(1);

        // A boolean to capture by lambda which executes server receive and
        // holds flag if all checks were succeeded.
        final AtomicBoolean allChecksSucceeded = new AtomicBoolean(true);

        final int MAX_SEND_DATAGRAM_SIZE = 256;

        final ExecutorService serverExecutor
            = Executors.newSingleThreadExecutor();

        try (DatagramSocket server = new DatagramSocket())
        {
            // do not hang forever in receive if test goes wrong in some way
            server.setSoTimeout(1000);

            logger.fine(
                "Server is listening on: " + server.getLocalSocketAddress());

            serverExecutor.submit(() ->
            {
                try
                {
                    // Specify max datagram size, which
                    // server socket can receive
                    final int MAX_RECV_DATAGRAM_SIZE = 16;

                    // Specify the number of padding bytes. They are used
                    // to ensure DatagramSocket does not write out of the bounds
                    // specified by DatagramPacket(buffer, offset, length)
                    // passed into DatagramSocket.receive()
                    final int PAD_SIZE = 8;

                    // Use single shared array to represent "big" receive buffer
                    // which can serve multiple DatagramPacket instances
                    // with non-overlapping byte-ranges within buffer.
                    // For example, there could be single byte[] buffer of size
                    // 100, which can serve 10 DatagramPackets of length 100,
                    // when DatagramPacket is constructed to have disjoint
                    // byte range within underlying byte[] buffer.
                    final byte[] receiveBuffer =
                        new byte[PAD_SIZE + MAX_RECV_DATAGRAM_SIZE + PAD_SIZE];

                    // Allocate byte-range within `receiveBuffer` array where
                    // DatagramSocket/Packet will store received bytes.
                    // Use non-zero offset to later verify it is respected
                    // by socket implementation.
                    final DatagramPacket receivePacket
                        = new DatagramPacket(
                            receiveBuffer, PAD_SIZE, MAX_RECV_DATAGRAM_SIZE);

                    for (int iter = 1; iter < MAX_SEND_DATAGRAM_SIZE; iter++)
                    {
                        // erase whole receive buffer to later verify
                        // that no data is written by socket out of bounds
                        // specified in DatagramPacket.
                        Arrays.fill(receiveBuffer, (byte) 0);

                        // restoring length is actually not necessary, because
                        // DatagramPacket has two fields: one to store the
                        // size of the underlying buffer and other field
                        // to store an actual length of received datagram.
                        // But that is an implementation detail.
                        // When receive() is called only the length field of
                        // received datagram is changed, not the length field
                        // of the underlying buffer.
                        receivePacket.setLength(MAX_RECV_DATAGRAM_SIZE);

                        server.receive(receivePacket);

                        logger.fine(
                            "Received packet from " + receivePacket.getAddress()
                            + " of size " + receivePacket.getLength()
                            + " with content: "
                            + Arrays.toString(receivePacket.getData()));

                        Assert.assertEquals("DatagramSocket.receive()"
                            + " must not replace an receive byte-buffer",
                            receiveBuffer, receivePacket.getData());

                        final int expectedReceivedBytes
                            = Math.min(iter, MAX_RECV_DATAGRAM_SIZE);

                        Assert.assertEquals("DatagramSocket.receive() "
                            + "must respect the length of DatagramPacket",
                            expectedReceivedBytes, receivePacket.getLength());

                        for (int i = 0; i < receiveBuffer.length; i++)
                        {
                            if (i >= PAD_SIZE &&
                                i < PAD_SIZE + receivePacket.getLength())
                            {
                                Assert.assertEquals("DatagramSocket.receive()"
                                    + " must fill DatagramPacket's buffer with"
                                    + " (possibly trimmed) content of packet"
                                    + " which is being sent by client."
                                    + " By test convention the packet is filled"
                                    + " with iteration number",
                                    (byte) iter, receiveBuffer[i]);
                            }
                            else
                            {
                                Assert.assertEquals("DatagramSocket.receive()"
                                    + " must respect the offset and length"
                                    + " within byte buffer and must not"
                                    + " write outsize of the specified"
                                    + " bounds",
                                    0, receiveBuffer[i]);
                            }
                        }
                    }
                }
                catch (IOException e)
                {
                    logger.log(Level.SEVERE, e, () -> "Failed to receive");
                    allChecksSucceeded.set(false);
                }
                catch (AssertionError e)
                {
                    logger.log(Level.SEVERE, e, () -> "Assertion failed");
                    allChecksSucceeded.set(false);
                }
                finally
                {
                    serverCompleted.countDown();
                }
            });

            final SocketAddress serverAddress
                = new InetSocketAddress("127.0.0.1", server.getLocalPort());

            try (DatagramSocket client = new DatagramSocket())
            {
                for (int iter = 1; iter < MAX_SEND_DATAGRAM_SIZE; iter++)
                {
                    // fill packet with predictable length and content, i.e.
                    // iteration (packet) number, so server can verify received
                    // content
                    final byte[] sendBuffer = new byte[iter];
                    Arrays.fill(sendBuffer, (byte) iter);

                    final DatagramPacket p
                        = new DatagramPacket(sendBuffer, sendBuffer.length);
                    p.setSocketAddress(serverAddress);

                    client.send(p);
                }
            }

            serverCompleted.await();

            if (!allChecksSucceeded.get())
            {
                Assert.fail("One or more server checks failed, see logs"
                    + " for details");
            }
        }
    }
}
