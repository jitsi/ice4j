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

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.DatagramSocketImpl
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
 * The sockets are opened such that packets will be _received_ on exactly one socket.
 */
class SocketPool(
    /** The address to which to bind the pool of sockets. */
    address: SocketAddress,
    /** The number of sockets to create for the pool.  If this is set to zero (the default), the number
     * will be set automatically to an appropriate value.
     */
    requestedNumSockets: Int = 0
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
            2 * Runtime.getRuntime().availableProcessors()
        }

    private val sockets = buildList {
        val multipleSockets = numSockets > 1
        var bindAddr = address
        for (i in 0 until numSockets) {
            val sock = DatagramSocket(null)
            if (multipleSockets) {
                sock.reuseAddress = true
            }
            sock.bind(bindAddr)
            if (i == 0 && multipleSockets) {
                bindAddr = sock.localSocketAddress
            }
            add(SocketAndIndex(sock, 0))
        }
    }

    /** The socket on which packets will be received. */
    val receiveSocket: DatagramSocket
        // On all platforms I've tested, the last-bound socket is the one which receives packets.
        // TODO: should we support Linux's flavor of SO_REUSEPORT, in which packets can be received on *all* the
        //  sockets, spreading load?
        get() = sockets.last().socket

    fun send(packet: DatagramPacket) {
        val sendSocket = getSendSocket()
        sendSocket.socket.send(packet)
        returnSocket(sendSocket)
    }

    /** Gets a socket on which packets can be sent, chosen from among all the available send sockets. */
    internal fun getSendSocket(): SocketAndIndex {
        if (numSockets == 1) {
            return sockets.first()
        }
        synchronized(sockets) {
            val min = sockets.minBy { it.count }
            min.count++

            return min
        }
    }

    internal fun returnSocket(socket: SocketAndIndex) {
        synchronized(sockets) {
            socket.count--
        }
    }

    fun close() {
        sockets.forEach { it.socket.close() }
    }
}
