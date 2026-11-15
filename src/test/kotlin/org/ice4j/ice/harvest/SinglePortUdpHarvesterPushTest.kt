/*
 * Copyright @ 2026 - Present, 8x8 Inc
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
package org.ice4j.ice.harvest

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.ice4j.ConfigTest
import org.ice4j.Transport
import org.ice4j.TransportAddress
import org.ice4j.ice.Agent
import org.ice4j.ice.ComponentTestUtils
import org.ice4j.ice.KeepAliveStrategy
import org.ice4j.socket.SocketPool
import org.ice4j.util.Buffer
import org.ice4j.util.BufferHandler
import org.jitsi.ecn4j.EcnDatagramSocket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Tests that payload received on a [SinglePortUdpHarvester] is delivered through the push API, with the ECN field it
 * was received with when the harvester is configured to receive it.
 */
class SinglePortUdpHarvesterPushTest : ConfigTest() {
    private val loopback = InetAddress.getByName("127.0.0.1")

    /** The traffic classes to send payload with: each ECN codepoint, and two of them combined with a DSCP. */
    private val trafficClasses = listOf(0, 1, 2, 3, 0xb8 or 1, 0xb8 or 3)

    init {
        context("Payload pushed by a harvester which does not receive ECN") {
            should("have no ECN field") {
                withNewConfig("ice4j.harvest.udp.receive-ecn = false") {
                    receivedEcn() shouldBe trafficClasses.map { 0 }
                }
            }
        }
        context("Payload pushed by a harvester which receives ECN") {
            should("have the ECN field it was sent with, where the platform can report it") {
                withNewConfig("ice4j.harvest.udp.receive-ecn = true") {
                    receivedEcn() shouldBe trafficClasses.map { if (EcnDatagramSocket.isSupported()) it and 0x3 else 0 }
                }
            }
        }
        if (EcnDatagramSocket.isSupported()) {
            context("A packet sent through a candidate of a harvester which does not send ECT(1)") {
                should("not have the marking, even if it was asked for") {
                    withNewConfig("ice4j.harvest.udp.send-ect1 = false") {
                        sentEcn() shouldBe Pair(false, listOf(0, 0))
                    }
                }
            }
            context("A packet sent through a candidate of a harvester which sends ECT(1)") {
                should("have the marking if it was asked for") {
                    withNewConfig("ice4j.harvest.udp.send-ect1 = true") {
                        sentEcn() shouldBe Pair(true, listOf(1, 0))
                    }
                }
            }
        }
    }

    /**
     * Sets up a harvester with one candidate, starts a session on it from a client which reports the ECN field of
     * what it receives, sends a packet to the client through the candidate's socket with and without asking for
     * ECT(1), and returns whether the socket says it supports ECT(1) and the ECN field of the two packets as the
     * client received them.
     */
    private fun sentEcn(): Pair<Boolean, List<Int>> {
        val savedUsePushApi = AbstractUdpListener.USE_PUSH_API
        AbstractUdpListener.USE_PUSH_API = true
        val harvester = SinglePortUdpHarvester(TransportAddress(loopback, 0, Transport.UDP))
        val agent = Agent()
        val client = SocketPool(InetSocketAddress(loopback, 0), 1, receiveEcn = true)
        try {
            val component = ComponentTestUtils.createComponent(
                agent.createMediaStream("stream"),
                KeepAliveStrategy.SELECTED_ONLY
            )
            harvester.harvest(component)

            val pushed = LinkedBlockingQueue<Buffer>()
            component.setBufferCallback(object : BufferHandler {
                override fun handleBuffer(buffer: Buffer) {
                    pushed.add(buffer)
                }
            })

            // A Binding Request for the candidate's ufrag makes the harvester accept packets from the client, and
            // open a socket to send to it. Once payload from the client has been pushed, that has happened.
            val request = bindingRequest("${agent.localUfrag}:remote")
            client.send(DatagramPacket(request, request.size, harvester.localAddress))
            val hello = byteArrayOf(0x80.toByte()) + "hello".toByteArray()
            client.send(DatagramPacket(hello, hello.size, harvester.localAddress))
            pushed.poll(5, TimeUnit.SECONDS).shouldNotBeNull()

            val clientAddress = client.receiveSocket.localSocketAddress
            val socket = ComponentTestUtils.getCandidateSocket(component, clientAddress).shouldNotBeNull()

            val received = listOf(true, false).map { ect1 ->
                val payload = byteArrayOf(0x80.toByte()) + "ect1 $ect1".toByteArray()
                socket.send(DatagramPacket(payload, payload.size, clientAddress), ect1)

                // The harvester answers the Binding Request too. Skip anything which is not the payload.
                var ecn: Int
                val packet = DatagramPacket(ByteArray(1500), 1500)
                do {
                    ecn = client.receive(packet)
                } while (!packet.data.copyOfRange(0, packet.length).contentEquals(payload))
                packet.socketAddress shouldBe harvester.localAddress
                ecn
            }
            return Pair(socket.supportsEct1(), received)
        } finally {
            client.close()
            agent.free()
            harvester.close()
            AbstractUdpListener.USE_PUSH_API = savedUsePushApi
        }
    }

    /**
     * Sets up a harvester with one candidate, starts a session on it from a client socket, sends one payload packet
     * with each of [trafficClasses], and returns the ECN field of the buffers pushed to the component, having checked
     * their contents.
     */
    private fun receivedEcn(): List<Int> {
        val savedUsePushApi = AbstractUdpListener.USE_PUSH_API
        AbstractUdpListener.USE_PUSH_API = true
        val harvester = SinglePortUdpHarvester(TransportAddress(loopback, 0, Transport.UDP))
        val agent = Agent()
        try {
            val component = ComponentTestUtils.createComponent(
                agent.createMediaStream("stream"),
                KeepAliveStrategy.SELECTED_ONLY
            )
            harvester.harvest(component)

            val pushed = LinkedBlockingQueue<Buffer>()
            component.setBufferCallback(object : BufferHandler {
                override fun handleBuffer(buffer: Buffer) {
                    pushed.add(buffer)
                }
            })

            DatagramSocket(InetSocketAddress(loopback, 0)).use { client ->
                // A Binding Request for the candidate's ufrag makes the harvester accept packets from the client.
                val request = bindingRequest("${agent.localUfrag}:remote")
                client.send(DatagramPacket(request, request.size, harvester.localAddress))

                return trafficClasses.map { trafficClass ->
                    client.trafficClass = trafficClass
                    // The first byte keeps the payload from looking like STUN.
                    val payload = byteArrayOf(0x80.toByte()) + "payload $trafficClass".toByteArray()
                    client.send(DatagramPacket(payload, payload.size, harvester.localAddress))

                    val buffer = pushed.poll(5, TimeUnit.SECONDS).shouldNotBeNull()
                    buffer.buffer.copyOfRange(buffer.offset, buffer.offset + buffer.length) shouldBe payload
                    buffer.remoteAddress shouldBe client.localSocketAddress
                    buffer.localAddress shouldBe harvester.localAddress
                    buffer.receivedTime.shouldNotBeNull()
                    buffer.ecn
                }
            }
        } finally {
            agent.free()
            harvester.close()
            AbstractUdpListener.USE_PUSH_API = savedUsePushApi
        }
    }

    /** Builds a STUN Binding Request (RFC 8489) whose only attribute is a USERNAME. */
    private fun bindingRequest(username: String): ByteArray {
        val value = username.toByteArray()
        val paddedLength = (value.size + 3) / 4 * 4
        return ByteBuffer.allocate(20 + 4 + paddedLength).apply {
            putShort(0x0001)
            putShort((4 + paddedLength).toShort())
            putInt(0x2112A442)
            put(ByteArray(12) { it.toByte() })
            putShort(0x0006)
            putShort(value.size.toShort())
            put(value)
        }.array()
    }
}
