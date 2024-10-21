package org.ice4j.socket

import io.kotest.core.spec.style.ShouldSpec
import io.kotest.core.test.Enabled
import io.kotest.core.test.TestCase
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.beInstanceOf
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
                    sockets.add(pool.sendSocket)
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
                sockets.add(pool.sendSocket)
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
                sockets.add(pool.sendSocket)
            }

            should("be correct") {
                sockets.size shouldBe numSockets
            }
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

        context("Test sending packets from multiple threads") {
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
