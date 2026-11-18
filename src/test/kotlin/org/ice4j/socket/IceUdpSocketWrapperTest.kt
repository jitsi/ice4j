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

import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.jitsi.ecn4j.Ecn
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger

/** Tests what a socket which cannot mark packets, such as the one of a candidate with its own port, does with ECT(1). */
class IceUdpSocketWrapperTest : ShouldSpec() {
    private val loopbackAny = InetSocketAddress("127.0.0.1", 0)

    init {
        context("A wrapper of a plain UDP socket") {
            val records = mutableListOf<LogRecord>()
            val handler = object : Handler() {
                override fun publish(record: LogRecord) {
                    records.add(record)
                }
                override fun flush() {}
                override fun close() {}
            }
            val wrapperLogger = Logger.getLogger(IceSocketWrapper::class.java.name)
            wrapperLogger.addHandler(handler)

            val wrapper = IceUdpSocketWrapper(DatagramSocket(loopbackAny))
            // The peer reports the ECN field of what it receives, where the platform can.
            val peer = SocketPool(loopbackAny, 1, receiveEcn = true)
            try {
                should("say that it cannot send ECT(1)") {
                    wrapper.supportsEct1() shouldBe false
                }
                should("send a packet which was to be ECT(1) without the marking, and warn once") {
                    repeat(3) { i ->
                        val buf = i.toString().toByteArray()
                        wrapper.send(DatagramPacket(buf, buf.size, peer.receiveSocket.localSocketAddress), i != 1)

                        val packet = DatagramPacket(ByteArray(1500), 1500)
                        peer.receive(packet) shouldBe Ecn.NOT_ECT
                        packet.data.decodeToString(0, packet.length).toInt() shouldBe i
                        packet.socketAddress shouldBe wrapper.localSocketAddress
                    }
                    val warnings = records.filter { it.level == Level.WARNING }
                    warnings shouldHaveSize 1
                    warnings[0].message shouldContain "ECT(1)"
                    warnings[0].message shouldContain "IceUdpSocketWrapper"
                }
                should("not warn when the marking is not asked for") {
                    val other = IceUdpSocketWrapper(DatagramSocket(loopbackAny))
                    val before = records.size
                    val buf = "plain".toByteArray()
                    other.send(DatagramPacket(buf, buf.size, peer.receiveSocket.localSocketAddress), false)
                    other.send(DatagramPacket(buf, buf.size, peer.receiveSocket.localSocketAddress))
                    records.size shouldBe before
                    other.close()
                }
            } finally {
                wrapperLogger.removeHandler(handler)
                wrapper.close()
                peer.close()
            }
        }
    }
}
