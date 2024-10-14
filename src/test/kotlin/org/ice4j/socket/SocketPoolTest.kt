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

private val loopbackAny = InetSocketAddress("127.0.0.1", 0)
private val loopbackDiscard = InetSocketAddress("127.0.0.1", 9)

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
            val holders = mutableListOf<SocketPool.SocketHolder>()
            should("be possible") {
                repeat(numSockets) {
                    holders.add(pool.getSendSocket())
                }
            }
            holders.forEach { it.close() }
            pool.close()
        }

        context("Packets sent from each of the send sockets in the pool") {
            val numSockets = 4
            val pool = SocketPool(loopbackAny, numSockets)
            val local = pool.receiveSocket.localSocketAddress
            val holders = mutableListOf<SocketPool.SocketHolder>()
            repeat(numSockets) {
                holders.add(pool.getSendSocket())
            }
            holders.forEachIndexed { i, it ->
                val buf = i.toString().toByteArray()
                val packet = DatagramPacket(buf, buf.size, local)
                it.socket.send(packet)
            }
            holders.forEach { it.close() }

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
        }

        context("The number of send sockets") {
            val numSockets = 4
            val pool = SocketPool(loopbackAny, numSockets)

            val sockets = mutableSetOf<DatagramSocket>()

            repeat(2 * numSockets) {
                // This should cycle through all the available send sockets
                pool.getSendSocket().use { holder ->
                    sockets.add(holder.socket)
                }
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
            pool.getSendSocket().use {
                for (i in 0 until count) {
                    it.socket.send(DatagramPacket(buf, BUFFER_SIZE, destAddr))
                }
            }
        }

        override fun run() {
            val startTime: Instant = clock.instant()

            sendToSocket(count)

            val endTime: Instant = clock.instant()

            val myElapsed: Duration = Duration.between(startTime, endTime)
            setElapsed(myElapsed)
        }

        companion object {
            private const val BUFFER_SIZE = 1500
            const val NUM_PACKETS = 600000
            private val clock = Clock.systemUTC()

            var elapsed: Duration = Duration.ZERO
                private set

            fun setElapsed(myElapsed: Duration) {
                synchronized(this) {
                    if (elapsed < myElapsed) {
                        elapsed = myElapsed
                    }
                }
            }

            fun resetElapsed() {
                elapsed = Duration.ZERO
            }
        }
    }

    companion object {
        private fun sendTimeOnAllSockets(pool: SocketPool, numThreads: Int = pool.numSockets): Duration {
            val threads = mutableListOf<Thread>()
            Sender.resetElapsed()
            repeat(numThreads) {
                val thread = Thread(Sender(Sender.NUM_PACKETS / numThreads, pool, loopbackDiscard))
                threads.add(thread)
                thread.start()
            }
            threads.forEach { it.join() }
            return Sender.elapsed
        }

        fun testSending() {
            val poolWarmup = SocketPool(loopbackAny, 1)
            sendTimeOnAllSockets(poolWarmup)

            val pool1 = SocketPool(loopbackAny, 1)
            val elapsed11 = sendTimeOnAllSockets(pool1)
            println("Send ${Sender.NUM_PACKETS} packets on 1 socket on one thread took $elapsed11")

            val numProcessors = Runtime.getRuntime().availableProcessors()

            val elapsed1N = sendTimeOnAllSockets(pool1, numProcessors)
            println(
                "Send ${Sender.NUM_PACKETS} packets on 1 socket on $numProcessors threads took $elapsed1N"
            )

            val poolN = SocketPool(loopbackAny, numProcessors)
            val elapsedNN = sendTimeOnAllSockets(poolN, numProcessors)
            println(
                "Send ${Sender.NUM_PACKETS} packets on $numProcessors sockets on $numProcessors threads " +
                    "took $elapsedNN"
            )

            val elapsedN2N = sendTimeOnAllSockets(poolN, 2 * numProcessors)
            println(
                "Send ${Sender.NUM_PACKETS} packets on $numProcessors sockets on ${2 * numProcessors} threads " +
                    "took $elapsedN2N"
            )

            val pool2N = SocketPool(loopbackAny, 2 * numProcessors)
            val elapsed2N2N = sendTimeOnAllSockets(pool2N, 2 * numProcessors)
            println(
                "Send ${Sender.NUM_PACKETS} packets on ${2 * numProcessors} sockets " +
                    "on ${2 * numProcessors} threads took $elapsed2N2N"
            )
        }

        @JvmStatic
        fun main(args: Array<String>) {
            testSending()
        }
    }
}
