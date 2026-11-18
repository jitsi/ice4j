/*
 * Copyright @ 2020 - Present, 8x8 Inc
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
package org.ice4j.socket

import org.jitsi.ecn4j.Ecn
import org.jitsi.ecn4j.EcnDatagramSocket
import org.jitsi.utils.logging2.createLogger
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.DatagramSocketImpl
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.channels.DatagramChannel

/** A pool of datagram sockets all bound on the same port.
 *
 * This is necessary to allow multiple threads to send packets simultaneously from the same source address,
 * in JDK 15 and later, because the [DatagramChannel]-based implementation of [DatagramSocketImpl] introduced
 * in that version locks the socket during a call to [DatagramSocket.send].
 *
 * (The old [DatagramSocketImpl] implementation can be used by setting the system property
 * `jdk.net.usePlainDatagramSocketImpl` in JDK versions 15 through 17, but was removed in versions 18 and later.)
 *
 * This feature may also be useful on older JDK versions on non-Linux operating systems, such as macOS,
 * which block simultaneous writes through the same UDP socket at the operating system level.
 *
 * The sockets are opened such that packets will be _received_ on exactly one socket. Use [receive] to read from it.
 *
 * The pool can also hold a second set of sockets, which send packets with the ECT(1) marking (RFC 9331). A packet is
 * then sent with or without the marking by choosing the socket to send it on, see [send].
 */
class SocketPool(
    /** The address to which to bind the pool of sockets. */
    address: SocketAddress,
    /** The number of sockets to create for the pool.  If this is set to zero (the default), the number
     * will be set automatically to an appropriate value.
     */
    requestedNumSockets: Int = 0,
    /** Whether to receive on a socket which reports the ECN field of received packets, where the platform has one. */
    receiveEcn: Boolean = false,
    /**
     * Whether to also open sockets which send packets with the ECT(1) marking, as many as there are other sockets.
     */
    sendEct1: Boolean = false
) {
    init {
        require(requestedNumSockets >= 0) { "RequestedNumSockets must be >= 0" }
    }

    internal class SocketAndIndex(
        val socket: DatagramSocket,
        var count: Int = 0
    )

    val numSockets: Int =
        if (requestedNumSockets != 0) {
            requestedNumSockets
        } else {
            // TODO: set this to 1 in situations where pools aren't needed?
            Runtime.getRuntime().availableProcessors()
        }

    private val useEcnSocket = receiveEcn && ecnSocketSupported(address)

    /** The sockets which send packets with the ECT(1) marking. Empty unless that was requested and is possible. */
    private val ect1Sockets: List<SocketAndIndex>

    /** The sockets which send packets without an ECN marking. */
    private val sockets: List<SocketAndIndex>

    init {
        // The ECN socket and the ECT(1) sockets are more sockets bound to the same address.
        val shareAddress = numSockets > 1 || useEcnSocket || sendEct1
        var bindAddr = address

        fun open(trafficClass: Int?): SocketAndIndex {
            val sock = DatagramSocket(null)
            try {
                if (shareAddress) {
                    sock.reuseAddress = true
                }
                if (trafficClass != null) {
                    sock.trafficClass = trafficClass
                    if (sock.trafficClass != trafficClass) {
                        throw IOException("The traffic class of the socket is ${sock.trafficClass}")
                    }
                }
                sock.bind(bindAddr)
            } catch (e: IOException) {
                sock.close()
                throw e
            }
            if (shareAddress) {
                bindAddr = sock.localSocketAddress
            }
            return SocketAndIndex(sock, 0)
        }

        // The ECT(1) sockets are bound first: the socket bound last is the one which receives.
        ect1Sockets = if (sendEct1) {
            val opened = mutableListOf<SocketAndIndex>()
            try {
                repeat(numSockets) { opened.add(open(Ecn.ECT_1)) }
            } catch (e: IOException) {
                logger.warn("Failed to open sockets which send ECT(1), packets will be sent without it", e)
                opened.forEach { it.socket.close() }
                opened.clear()
                bindAddr = address
            }
            opened
        } else {
            emptyList()
        }
        sockets = buildList {
            repeat(numSockets) { add(open(null)) }
        }
    }

    /**
     * The socket on which packets are received when [receiveEcn] was requested and is available, or null. It is bound
     * after all the others, which makes it the one which receives packets.
     */
    private val ecnSocket: EcnDatagramSocket? = if (useEcnSocket) {
        try {
            EcnDatagramSocket(sockets.first().socket.localSocketAddress as InetSocketAddress, true)
        } catch (e: IOException) {
            logger.warn("Failed to open a socket to receive ECN on, packets will be received without it", e)
            null
        }
    } else {
        if (receiveEcn) {
            logger.info(
                "Receiving ECN is not supported for $address on this platform, packets will be received without it"
            )
        }
        null
    }

    /** Whether [receive] reports the ECN field of received packets. */
    val receivesEcn: Boolean
        get() = ecnSocket != null

    /**
     * The last of the pool's [DatagramSocket]s, which is the one that receives packets unless [receivesEcn] is true.
     * Use [receive] to receive, which reads from the right socket.
     */
    val receiveSocket: DatagramSocket
        // On all platforms I've tested, the last-bound socket is the one which receives packets.
        // TODO: should we support Linux's flavor of SO_REUSEPORT, in which packets can be received on *all* the
        //  sockets, spreading load?
        get() = sockets.last().socket

    /** The size of the receive buffer (SO_RCVBUF) of the socket on which packets are received. */
    var receiveBufferSize: Int
        get() = ecnSocket?.receiveBufferSize ?: receiveSocket.receiveBufferSize
        set(value) {
            ecnSocket?.let { it.receiveBufferSize = value } ?: run { receiveSocket.receiveBufferSize = value }
        }

    /**
     * Receives a packet, blocking until one arrives. This behaves like [DatagramSocket.receive], except that a socket
     * timeout is not supported.
     *
     * @return the ECN field (RFC 3168) of the packet's IP header: 0 (Not-ECT), 1 (ECT(1)), 2 (ECT(0)) or 3 (CE).
     * It is always 0 unless [receivesEcn] is true.
     */
    @Throws(IOException::class)
    fun receive(packet: DatagramPacket): Int {
        val ecnSocket = this.ecnSocket
        if (ecnSocket == null) {
            receiveSocket.receive(packet)
            return Ecn.NOT_ECT
        }
        return Ecn.fromTrafficClass(ecnSocket.receive(packet))
    }

    /** Whether [send] can send a packet with the ECT(1) marking. */
    val sendsEct1: Boolean
        get() = ect1Sockets.isNotEmpty()

    private var warnedOfEct1 = false

    /**
     * Sends a packet.
     *
     * @param ect1 whether to send it with the ECT(1) marking. If [sendsEct1] is false the packet is sent without the
     * marking.
     */
    @JvmOverloads
    @Throws(IOException::class)
    fun send(packet: DatagramPacket, ect1: Boolean = false) {
        if (ect1 && !sendsEct1 && !warnedOfEct1) {
            warnedOfEct1 = true
            logger.warn(
                "A packet was to be sent as ECT(1) on a socket pool which cannot, sending it without the marking. " +
                    "This is logged once for each pool."
            )
        }
        val sendSocket = getSendSocket(ect1)
        try {
            sendSocket.socket.send(packet)
        } finally {
            returnSocket(sendSocket)
        }
    }

    /**
     * Gets a socket on which packets can be sent, chosen from among all the available send sockets.
     *
     * @param ect1 whether to choose from the sockets which send ECT(1), if there are any.
     */
    internal fun getSendSocket(ect1: Boolean = false): SocketAndIndex {
        val group = if (ect1 && sendsEct1) ect1Sockets else sockets
        if (numSockets == 1) {
            return group.first()
        }
        synchronized(group) {
            val min = group.minBy { it.count }
            min.count++

            return min
        }
    }

    internal fun returnSocket(socket: SocketAndIndex) {
        if (numSockets == 1) {
            return
        }
        // The count is only read and written with the lock of the group the socket is in.
        synchronized(if (ect1Sockets.contains(socket)) ect1Sockets else sockets) {
            socket.count--
        }
    }

    fun close() {
        ecnSocket?.close()
        ect1Sockets.forEach { it.socket.close() }
        sockets.forEach { it.socket.close() }
    }

    companion object {
        private val logger = createLogger()

        private val isMac = System.getProperty("os.name").startsWith("Mac")

        /**
         * Whether an [EcnDatagramSocket] can be used to receive the packets sent to [address]. It has to share the
         * address with the pool's other sockets and be the one which receives. macOS does not deliver packets to it
         * when the address is the wildcard address.
         */
        private fun ecnSocketSupported(address: SocketAddress): Boolean = EcnDatagramSocket.isSupported() &&
            !(isMac && (address as? InetSocketAddress)?.address?.isAnyLocalAddress != false)
    }
}
