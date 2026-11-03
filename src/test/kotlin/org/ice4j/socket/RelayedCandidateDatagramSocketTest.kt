/*
 * Copyright @ 2026 - present 8x8, Inc.
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

import io.kotest.core.test.TestCase
import io.kotest.core.test.TestResult
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import org.ice4j.ConfigTest
import org.ice4j.Transport
import org.ice4j.TransportAddress
import org.ice4j.attribute.Attribute
import org.ice4j.attribute.XorPeerAddressAttribute
import org.ice4j.ice.Agent
import org.ice4j.ice.ComponentTestUtils
import org.ice4j.ice.HostCandidate
import org.ice4j.ice.KeepAliveStrategy
import org.ice4j.ice.RelayedCandidate
import org.ice4j.ice.harvest.TurnCandidateHarvest
import org.ice4j.ice.harvest.TurnCandidateHarvester
import org.ice4j.message.Message
import org.ice4j.message.MessageFactory
import org.ice4j.message.Request
import org.ice4j.message.Response
import org.ice4j.stack.StunStack
import org.ice4j.stack.TransactionID
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Tests the handling of failed TURN CreatePermission requests by [RelayedCandidateDatagramSocket] (ice4j issue #319):
 * a failed request must not be re-sent in a tight loop.
 *
 * The host candidate uses a [MultiplexingDatagramSocket], as in production, so the socket under test is in its
 * ChannelData mode: the first non-STUN packet to a peer forces a re-bind (CreatePermission plus ChannelBind).
 */
class RelayedCandidateDatagramSocketTest : ConfigTest() {
    private val peerA = InetAddress.getByName("10.1.2.3")
    private val peerB = InetAddress.getByName("10.4.5.6")

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()
    private val agent = Agent("test", null)
    private val component =
        ComponentTestUtils.createComponent(agent.createMediaStream("stream"), KeepAliveStrategy.SELECTED_ONLY)
    private val hostSocket = MultiplexingDatagramSocket(DatagramSocket(0, loopback))
    private val host = HostCandidate(IceUdpSocketWrapper(hostSocket), component).also {
        component.addLocalCandidate(it)
    }
    private val turnServer = TransportAddress(loopback, 3478, Transport.UDP)
    private val harvester = object : TurnCandidateHarvester(turnServer) {
        // The STUN stack is normally set when the harvester harvests a component.
        override fun getStunStack(): StunStack = agent.stunStack
    }

    /** The requests which the socket under test has asked the harvest to send. */
    private val requests = LinkedBlockingQueue<Request>()

    private val harvest = object : TurnCandidateHarvest(harvester, host) {
        override fun sendRequest(socket: RelayedCandidateDatagramSocket, request: Request): ByteArray {
            requests.add(request)
            return request.transactionID
        }

        // Don't try to send a Refresh to the (non-existent) TURN server when the socket is closed.
        override fun close(relayedCandidateSocket: RelayedCandidateDatagramSocket) {}
    }
    private val relayedCandidate =
        RelayedCandidate(TransportAddress(loopback, 40000, Transport.UDP), harvest, host.transportAddress)

    /** Created lazily so that each test can set its config before the socket reads it. */
    private val socket by lazy { RelayedCandidateDatagramSocket(relayedCandidate, harvest) }

    override suspend fun afterAny(testCase: TestCase, result: TestResult) {
        socket.close()
        agent.free()
        hostSocket.close()
    }

    /** A STUN Binding request, i.e. what a connectivity check looks like. Does not force a re-bind. */
    private val stunPayload: ByteArray = MessageFactory.createBindingRequest().let {
        it.transactionID = TransactionID.createNewTransactionID().bytes
        it.encode(agent.stunStack)
    }

    /** Something which is clearly not STUN, i.e. what media looks like. Forces a re-bind the first time. */
    private val mediaPayload = ByteArray(10) { 0x80.toByte() }

    private fun sendTo(peer: InetAddress, payload: ByteArray = stunPayload) =
        socket.send(DatagramPacket(payload, payload.size, peer, 1234))

    private fun Request.peerAddress(): InetAddress =
        (getAttribute(Attribute.XOR_PEER_ADDRESS) as XorPeerAddressAttribute).getAddress(transactionID).address

    /** Waits for a CreatePermission request for [peer] to be sent, or returns null if none is sent in [timeoutMs]. */
    private fun awaitCreatePermission(peer: InetAddress, timeoutMs: Long = 2000): Request? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            val request = requests.poll(remaining.coerceAtLeast(1), TimeUnit.MILLISECONDS) ?: return null
            if (request.messageType == Message.CREATEPERMISSION_REQUEST && request.peerAddress() == peer) {
                return request
            }
        }
    }

    /**
     * Keeps sending packets to [peer] until a new CreatePermission is sent. Returns the number of milliseconds since
     * [startNanos] at which that happened, and the new request itself.
     */
    private fun awaitRetry(peer: InetAddress, startNanos: Long): Pair<Long, Request> {
        while (true) {
            sendTo(peer)
            val retry = awaitCreatePermission(peer, 20)
            if (retry != null) {
                return Pair(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos), retry)
            }
            if (System.nanoTime() - startNanos > TimeUnit.SECONDS.toNanos(5)) {
                throw AssertionError("No retry within 5 seconds")
            }
        }
    }

    /**
     * Fails the pending CreatePermission [request] with a timeout, then keeps sending packets to [peer] until a new
     * CreatePermission is sent. Returns the number of milliseconds between the failure and the new request, and the
     * new request itself.
     */
    private fun timeUntilRetry(peer: InetAddress, request: Request): Pair<Long, Request> {
        val start = System.nanoTime()
        socket.processErrorOrFailure(null, request)
        return awaitRetry(peer, start)
    }

    private fun errorResponse(code: Int): Response = MessageFactory.createCreatePermissionErrorResponse(code.toChar())

    private val fastRetryConfig = """
        ice4j.harvest.turn.permission-retry {
          initial-delay = 100 ms
          max-delay = 300 ms
        }
    """.trimIndent()

    init {
        context("A CreatePermission request which fails with a permanent error") {
            listOf(400, 401, 403, 443).forEach { code ->
                should("not be retried after a $code, and packets to the peer should be dropped") {
                    sendTo(peerA)
                    val request = awaitCreatePermission(peerA).shouldNotBeNull()

                    socket.processErrorOrFailure(errorResponse(code), request)

                    // Neither the already queued packet nor new packets should trigger a new request, not even the
                    // first media packet, which would otherwise force a re-bind.
                    awaitCreatePermission(peerA, 300).shouldBeNull()
                    sendTo(peerA)
                    sendTo(peerA, mediaPayload)
                    sendTo(peerA)
                    awaitCreatePermission(peerA, 300).shouldBeNull()
                }
            }
            should("not affect other peers") {
                sendTo(peerA)
                val request = awaitCreatePermission(peerA).shouldNotBeNull()
                socket.processErrorOrFailure(errorResponse(403), request)

                sendTo(peerB)
                awaitCreatePermission(peerB).shouldNotBeNull()
            }
        }
        context("A CreatePermission request which fails with a transient error") {
            should("be retried only after a delay which doubles up to the maximum") {
                withNewConfig(fastRetryConfig) {
                    sendTo(peerA)
                    var request = awaitCreatePermission(peerA).shouldNotBeNull()

                    // Packets sent during the delay are dropped and do not trigger a retry.
                    val start = System.nanoTime()
                    socket.processErrorOrFailure(null, request)
                    sendTo(peerA)
                    awaitCreatePermission(peerA, 50).shouldBeNull()
                    val (firstDelay, firstRetry) = awaitRetry(peerA, start)
                    firstDelay shouldBeGreaterThanOrEqual 100L
                    request = firstRetry

                    // Only the lower bounds are checked strictly; the upper bounds just catch a wrong order of magnitude.
                    for (expectedDelay in listOf(200L, 300L, 300L)) {
                        val (delay, retry) = timeUntilRetry(peerA, request)
                        delay shouldBeGreaterThanOrEqual expectedDelay
                        delay shouldBeLessThan expectedDelay + 1000
                        request = retry
                    }
                }
            }
            should("have the delay reset after a success") {
                withNewConfig(fastRetryConfig) {
                    sendTo(peerA)
                    var request = awaitCreatePermission(peerA).shouldNotBeNull()
                    // Two failures: the delay is now 200 ms.
                    request = timeUntilRetry(peerA, request).second
                    request = timeUntilRetry(peerA, request).second
                    socket.processSuccess(MessageFactory.createCreatePermissionResponse(), request)

                    // The first media packet forces a re-bind, which gives us a new request to fail.
                    sendTo(peerA, mediaPayload)
                    request = awaitCreatePermission(peerA).shouldNotBeNull()
                    val (delay, _) = timeUntilRetry(peerA, request)
                    // Without the reset this would be 300 ms.
                    delay shouldBeGreaterThanOrEqual 100L
                    delay shouldBeLessThan 300L
                }
            }
        }
        context("A CreatePermission failure for a transaction we are not waiting for") {
            should("be ignored") {
                sendTo(peerA)
                val request = awaitCreatePermission(peerA).shouldNotBeNull()

                // A failure for a different transaction for the same peer.
                val otherTransactionID = TransactionID.createNewTransactionID().bytes
                val otherRequest = MessageFactory.createCreatePermissionRequest(
                    TransportAddress(peerA, 1234, Transport.UDP),
                    otherTransactionID
                ).also { it.transactionID = otherTransactionID }
                socket.processErrorOrFailure(null, otherRequest)

                // The pending request should still be the one we are waiting for, so its success binds the channel
                // and no further CreatePermission is needed.
                socket.processSuccess(MessageFactory.createCreatePermissionResponse(), request)
                sendTo(peerA)
                awaitCreatePermission(peerA, 300).shouldBeNull()

                // And a late failure for the original request should not unbind the channel either.
                socket.processErrorOrFailure(null, request)
                sendTo(peerA)
                awaitCreatePermission(peerA, 300).shouldBeNull()
            }
        }
    }
}
