package org.ice4j.socket

import io.kotest.core.spec.style.ShouldSpec
import io.kotest.core.test.Enabled
import io.kotest.core.test.TestCase
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.beInstanceOf
import org.jitsi.ecn4j.Ecn
import org.jitsi.ecn4j.EcnDatagramSocket
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CyclicBarrier

private val loopbackAny = InetSocketAddress("127.0.0.1", 0)
private val loopbackDiscard = InetSocketAddress("127.0.0.1", 9)

@OptIn(io.kotest.common.ExperimentalKotest::class)
class SocketPoolTest : ShouldSpec() {
    init {
        context("Creating a new socket pool") {
            val pool = SocketPool(loopbackAny)
            should("Bind to a random port") {
                val local = pool.receiveSocket.localSocketAddress
                local should beInstanceOf<InetSocketAddress>()
                (local as InetSocketAddress).port shouldNotBe 0
            }
            pool.close()
        }

        context("Getting multiple send sockets from a pool") {
            val numSockets = 4
            val pool = SocketPool(loopbackAny, numSockets)
            val sockets = mutableListOf<DatagramSocket>()
            should("be possible") {
                repeat(numSockets) {
                    sockets.add(pool.getSendSocket().socket)
                }
            }
            // All sockets should be distinct
            sockets.toSet().size shouldBe sockets.size
            pool.close()
        }

        context("Packets sent from each of the send sockets in the pool") {
            val numSockets = 4
            val pool = SocketPool(loopbackAny, numSockets)
            val local = pool.receiveSocket.localSocketAddress
            val sockets = mutableListOf<DatagramSocket>()
            repeat(numSockets) {
                sockets.add(pool.getSendSocket().socket)
            }
            sockets.forEachIndexed { i, it ->
                val buf = i.toString().toByteArray()
                val packet = DatagramPacket(buf, buf.size, local)
                it.send(packet)
            }

            should("be received") {
                for (i in 0 until numSockets) {
                    val buf = ByteArray(1500)
                    val packet = DatagramPacket(buf, buf.size)
                    pool.receiveSocket.soTimeout = 1 // Don't block if something's wrong
                    pool.receiveSocket.receive(packet)
                    packet.data.decodeToString(0, packet.length).toInt() shouldBe i
                    packet.socketAddress shouldBe local
                }
            }
            pool.close()
        }

        context("The number of send sockets") {
            val numSockets = 4
            val pool = SocketPool(loopbackAny, numSockets)

            val sockets = mutableSetOf<DatagramSocket>()

            repeat(2 * numSockets) {
                // This should cycle through all the available send sockets
                sockets.add(pool.getSendSocket().socket)
            }

            should("be correct") {
                sockets.size shouldBe numSockets
            }

            pool.close()
        }

        context("A pool which was not asked to receive ECN") {
            val pool = SocketPool(loopbackAny, 2)
            val local = pool.receiveSocket.localSocketAddress
            should("not receive it") {
                pool.receivesEcn shouldBe false
            }
            should("receive packets through receive(), reporting them as Not-ECT") {
                DatagramSocket(loopbackAny).use { sender ->
                    sender.trafficClass = Ecn.ECT_1
                    val buf = "hello".toByteArray()
                    sender.send(DatagramPacket(buf, buf.size, local))

                    val packet = DatagramPacket(ByteArray(1500), 1500)
                    pool.receive(packet) shouldBe Ecn.NOT_ECT
                    packet.data.decodeToString(0, packet.length) shouldBe "hello"
                    packet.socketAddress shouldBe sender.localSocketAddress
                }
            }
            pool.close()
        }

        val enableIfEcnSupported: (TestCase) -> Enabled = {
            if (EcnDatagramSocket.isSupported()) {
                Enabled.enabled
            } else {
                Enabled.disabled("The ecn4j native library is not available on this platform")
            }
        }

        for (numSockets in listOf(1, 4)) {
            context("A pool of $numSockets which receives ECN").config(enabledOrReasonIf = enableIfEcnSupported) {
                val pool = SocketPool(loopbackAny, numSockets, receiveEcn = true)
                val local = pool.receiveSocket.localSocketAddress

                should("report that it does") {
                    pool.receivesEcn shouldBe true
                }
                should("report the ECN field of each received packet") {
                    DatagramSocket(loopbackAny).use { sender ->
                        // Each ECN codepoint, twice, and combined with a DSCP.
                        for (trafficClass in listOf(0, 1, 2, 3, 3, 2, 1, 0, 0xb8 or Ecn.ECT_1, 0xb8 or Ecn.CE)) {
                            sender.trafficClass = trafficClass
                            val buf = "tc $trafficClass".toByteArray()
                            sender.send(DatagramPacket(buf, buf.size, local))

                            val packet = DatagramPacket(ByteArray(1500), 1500)
                            pool.receive(packet) shouldBe (trafficClass and Ecn.MASK)
                            packet.data.decodeToString(0, packet.length) shouldBe "tc $trafficClass"
                            packet.socketAddress shouldBe sender.localSocketAddress
                        }
                    }
                }
                should("still send from the pool's address on every send socket") {
                    DatagramSocket(loopbackAny).use { peer ->
                        peer.soTimeout = 1000
                        repeat(2 * numSockets) { i ->
                            val buf = i.toString().toByteArray()
                            pool.send(DatagramPacket(buf, buf.size, peer.localSocketAddress))

                            val packet = DatagramPacket(ByteArray(1500), 1500)
                            peer.receive(packet)
                            packet.data.decodeToString(0, packet.length).toInt() shouldBe i
                            packet.socketAddress shouldBe local
                        }
                    }
                }
                should("apply the receive buffer size to the socket which receives") {
                    pool.receiveBufferSize = 32 * 1024
                    val small = pool.receiveBufferSize
                    pool.receiveBufferSize = 128 * 1024
                    pool.receiveBufferSize shouldBeGreaterThan small
                }
                should("wake a blocked receive when closed") {
                    var thrown: Throwable? = null
                    val receiver = Thread {
                        try {
                            pool.receive(DatagramPacket(ByteArray(1500), 1500))
                        } catch (t: Throwable) {
                            thrown = t
                        }
                    }
                    receiver.start()
                    Thread.sleep(100)
                    pool.close()
                    receiver.join(5000)
                    receiver.isAlive shouldBe false
                    thrown should beInstanceOf<IOException>()
                }
                pool.close()
            }
        }

        context("A pool which was not asked to send ECT(1)") {
            val pool = SocketPool(loopbackAny, 2)
            should("report that it cannot") {
                pool.sendsEct1 shouldBe false
            }
            should("send a packet which was to be ECT(1) without the marking").config(
                enabledOrReasonIf = enableIfEcnSupported
            ) {
                val peer = SocketPool(loopbackAny, 1, receiveEcn = true)
                try {
                    val buf = "hello".toByteArray()
                    pool.send(DatagramPacket(buf, buf.size, peer.receiveSocket.localSocketAddress), ect1 = true)

                    val packet = DatagramPacket(ByteArray(1500), 1500)
                    peer.receive(packet) shouldBe Ecn.NOT_ECT
                    packet.data.decodeToString(0, packet.length) shouldBe "hello"
                } finally {
                    peer.close()
                }
            }
            pool.close()
        }

        for (numSockets in listOf(1, 4)) {
            context("A pool of $numSockets which sends ECT(1)") {
                val pool = SocketPool(loopbackAny, numSockets, sendEct1 = true)
                val local = pool.receiveSocket.localSocketAddress

                should("report that it can") {
                    pool.sendsEct1 shouldBe true
                }
                should("have as many sockets which send ECT(1) as sockets which do not") {
                    val plain = mutableSetOf<DatagramSocket>()
                    val ect1 = mutableSetOf<DatagramSocket>()
                    repeat(2 * numSockets) {
                        plain.add(pool.getSendSocket().also { pool.returnSocket(it) }.socket)
                        ect1.add(pool.getSendSocket(ect1 = true).also { pool.returnSocket(it) }.socket)
                    }
                    if (numSockets > 1) {
                        // With more than one socket the least used one is chosen, and none is in use here.
                        plain.size shouldBe 1
                        ect1.size shouldBe 1
                    }
                    plain.intersect(ect1).size shouldBe 0
                    ect1.forEach { (it.trafficClass and Ecn.MASK) shouldBe Ecn.ECT_1 }
                    plain.forEach { (it.trafficClass and Ecn.MASK) shouldBe Ecn.NOT_ECT }

                    val inUse = (0 until numSockets).map { pool.getSendSocket(ect1 = true) }
                    inUse.map { it.socket }.toSet().size shouldBe numSockets
                    inUse.forEach { pool.returnSocket(it) }
                }
                should("send each packet with or without the marking, from the pool's address").config(
                    enabledOrReasonIf = enableIfEcnSupported
                ) {
                    val peer = SocketPool(loopbackAny, 1, receiveEcn = true)
                    try {
                        repeat(4 * numSockets) { i ->
                            val ect1 = i % 3 != 0
                            val buf = i.toString().toByteArray()
                            pool.send(DatagramPacket(buf, buf.size, peer.receiveSocket.localSocketAddress), ect1)

                            val packet = DatagramPacket(ByteArray(1500), 1500)
                            peer.receive(packet) shouldBe (if (ect1) Ecn.ECT_1 else Ecn.NOT_ECT)
                            packet.data.decodeToString(0, packet.length).toInt() shouldBe i
                            packet.socketAddress shouldBe local
                        }
                    } finally {
                        peer.close()
                    }
                }
                should("still receive the packets sent to its address") {
                    DatagramSocket(loopbackAny).use { sender ->
                        repeat(3) { i ->
                            val buf = i.toString().toByteArray()
                            sender.send(DatagramPacket(buf, buf.size, local))

                            val packet = DatagramPacket(ByteArray(1500), 1500)
                            pool.receiveSocket.soTimeout = 1000 // Don't block if something's wrong
                            pool.receive(packet)
                            packet.data.decodeToString(0, packet.length).toInt() shouldBe i
                            packet.socketAddress shouldBe sender.localSocketAddress
                        }
                    }
                }
                pool.close()
            }
        }

        context("A pool which sends ECT(1) and receives ECN").config(enabledOrReasonIf = enableIfEcnSupported) {
            val pool1 = SocketPool(loopbackAny, 2, receiveEcn = true, sendEct1 = true)
            val pool2 = SocketPool(loopbackAny, 2, receiveEcn = true, sendEct1 = true)
            should("exchange marked and unmarked packets with another") {
                for ((from, to) in listOf(pool1 to pool2, pool2 to pool1)) {
                    for (ect1 in listOf(true, false, true)) {
                        val buf = "ect1 $ect1".toByteArray()
                        from.send(DatagramPacket(buf, buf.size, to.receiveSocket.localSocketAddress), ect1)

                        val packet = DatagramPacket(ByteArray(1500), 1500)
                        to.receive(packet) shouldBe (if (ect1) Ecn.ECT_1 else Ecn.NOT_ECT)
                        packet.data.decodeToString(0, packet.length) shouldBe "ect1 $ect1"
                        packet.socketAddress shouldBe from.receiveSocket.localSocketAddress
                    }
                }
            }
            pool1.close()
            pool2.close()
        }

        val disableIfOnlyOneCore: (TestCase) -> Enabled = {
            if (Runtime.getRuntime().availableProcessors() > 1) {
                Enabled.enabled
            } else {
                Enabled.disabled("Need multiple processors to run test")
            }
        }

        context("Sending packets from multiple threads").config(enabledOrReasonIf = disableIfOnlyOneCore) {
            val poolWarmup = SocketPool(loopbackAny, 1)
            sendTimeOnAllSockets(poolWarmup)

            val pool1 = SocketPool(loopbackAny, 1)
            val elapsed1 = sendTimeOnAllSockets(pool1)

            // 0 means pick the default value, currently Runtime.getRuntime().availableProcessors().
            val poolN = SocketPool(loopbackAny, 0)
            val elapsedN = sendTimeOnAllSockets(poolN)

            elapsedN shouldBeLessThan elapsed1 // Very weak test
        }

        val enableOnlyIfPropertySet: (TestCase) -> Enabled = {
            if (System.getProperty("doPerfTests") != null) {
                Enabled.enabled
            } else {
                Enabled.disabled("Set \"doPerfTests\" property to enable SocketPool performance tests")
            }
        }

        context("Test sending packets from multiple threads").config(enabledOrReasonIf = enableOnlyIfPropertySet) {
            testSending()
        }
    }
    private class Sender(
        private val count: Int,
        private val pool: SocketPool,
        private val destAddr: SocketAddress
    ) : Runnable {
        private val buf = ByteArray(BUFFER_SIZE)

        private fun sendToSocket(count: Int) {
            for (i in 0 until count) {
                pool.send(DatagramPacket(buf, BUFFER_SIZE, destAddr))
            }
        }

        override fun run() {
            barrier.await()

            start()
            sendToSocket(count)
            end()
        }

        companion object {
            private const val BUFFER_SIZE = 1500
            const val NUM_PACKETS = 600000
            private val clock = Clock.systemUTC()

            private var start = Instant.MAX
            private var end = Instant.MIN

            val elapsed: Duration
                get() = Duration.between(start, end)

            fun start() {
                val now = clock.instant()
                synchronized(this) {
                    if (start.isAfter(now)) {
                        start = now
                    }
                }
            }

            fun end() {
                val now = clock.instant()
                synchronized(this) {
                    if (end.isBefore(now)) {
                        end = now
                    }
                }
            }

            private var barrier: CyclicBarrier = CyclicBarrier(1)

            fun reset(numThreads: Int) {
                barrier = CyclicBarrier(numThreads)
                start = Instant.MAX
                end = Instant.MIN
            }
        }
    }

    companion object {
        private fun sendTimeOnAllSockets(
            pool: SocketPool,
            numThreads: Int = pool.numSockets,
            numPackets: Int = Sender.NUM_PACKETS
        ): Duration {
            val threads = mutableListOf<Thread>()
            Sender.reset(numThreads)
            repeat(numThreads) {
                val thread = Thread(Sender(numPackets / numThreads, pool, loopbackDiscard))
                threads.add(thread)
                thread.start()
            }
            threads.forEach { it.join() }
            return Sender.elapsed
        }

        private fun testSendingOnce(
            numSockets: Int,
            numThreads: Int,
            numPackets: Int = Sender.NUM_PACKETS,
            warmup: Boolean = false
        ) {
            val pool = SocketPool(loopbackAny, numSockets)
            val elapsed = sendTimeOnAllSockets(pool, numThreads, numPackets)
            if (!warmup) {
                println(
                    "Send $numPackets packets on $numSockets sockets on $numThreads threads " +
                        "took $elapsed"
                )
            }
        }

        fun testSending() {
            val numProcessors = Runtime.getRuntime().availableProcessors()

            testSendingOnce(1, 1, warmup = true)
            testSendingOnce(2 * numProcessors, 2 * numProcessors, warmup = true)

            testSendingOnce(1, 1)
            testSendingOnce(1, numProcessors)
            testSendingOnce(1, 2 * numProcessors)
            testSendingOnce(1, 4 * numProcessors)
            testSendingOnce(1, 8 * numProcessors)

            testSendingOnce(numProcessors, numProcessors)
            testSendingOnce(numProcessors, 2 * numProcessors)
            testSendingOnce(numProcessors, 4 * numProcessors)
            testSendingOnce(numProcessors, 8 * numProcessors)

            testSendingOnce(2 * numProcessors, 2 * numProcessors)
            testSendingOnce(2 * numProcessors, 4 * numProcessors)
            testSendingOnce(2 * numProcessors, 8 * numProcessors)

            testSendingOnce(4 * numProcessors, 4 * numProcessors)
            testSendingOnce(4 * numProcessors, 8 * numProcessors)

            testSendingOnce(8 * numProcessors, 8 * numProcessors)
        }

        @JvmStatic
        fun main(args: Array<String>) {
            if (args.size >= 2) {
                val numSockets = args[0].toInt()
                val numThreads = args[1].toInt()
                val numPackets = if (args.size > 2) {
                    args[2].toInt()
                } else {
                    Sender.NUM_PACKETS
                }
                testSendingOnce(numThreads = numThreads, numSockets = numSockets, numPackets = 10000, warmup = true)
                testSendingOnce(numThreads = numThreads, numSockets = numSockets, numPackets = numPackets)
            } else {
                testSending()
            }
        }
    }
}
