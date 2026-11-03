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
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.ice4j.ConfigTest
import org.ice4j.Transport
import org.ice4j.TransportAddress
import org.ice4j.attribute.Attribute
import org.ice4j.attribute.AttributeFactory
import org.ice4j.attribute.NonceAttribute
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
import org.ice4j.security.LongTermCredential
import org.ice4j.stack.StunStack
import org.ice4j.stack.TransactionID
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Tests the handling of failed TURN CreatePermission requests by [RelayedCandidateDatagramSocket] when the request is
 * retried by the (real) [TurnCandidateHarvest] in response to a 401 Unauthorized or 438 Stale Nonce challenge. The
 * retry is a new STUN transaction, and the socket must recognize its result as the result of its own request.
 *
 * A fake TURN server on the loopback interface challenges the first CreatePermission request for a peer with a 401,
 * challenges the retry with a 438, and answers the second retry with the error code chosen by the test.
 */
class RelayedCandidateDatagramSocketChallengeTest : ConfigTest() {
    private val peerA = InetAddress.getByName("10.1.2.3")

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()
    private val agent = Agent("test", null)
    private val component =
        ComponentTestUtils.createComponent(agent.createMediaStream("stream"), KeepAliveStrategy.SELECTED_ONLY)
    private val hostSocket = MultiplexingDatagramSocket(DatagramSocket(0, loopback))
    private val host = HostCandidate(IceUdpSocketWrapper(hostSocket), component).also {
        component.addLocalCandidate(it)
        // As HostCandidateHarvester does, so that the STUN stack receives the TURN server's responses.
        agent.stunStack.addSocket(it.getStunSocket(null))
    }

    private val realm = "example.org".toByteArray()
    private val staleNonce = "stale".toByteArray()
    private val freshNonce = "fresh".toByteArray()

    /** The error code with which the fake TURN server answers a CreatePermission request with a fresh nonce. */
    @Volatile
    private var finalErrorCode = 500

    /** The CreatePermission requests received by the fake TURN server. */
    private val receivedRequests = LinkedBlockingQueue<Request>()

    private val serverSocket = DatagramSocket(0, loopback)
    private val turnServer = TransportAddress(loopback, serverSocket.localPort, Transport.UDP)
    private val serverThread = thread(name = "fake-turn-server", isDaemon = true) { serveTurn() }

    private val harvester = object : TurnCandidateHarvester(turnServer, LongTermCredential("user", "pass")) {
        // The STUN stack is normally set when the harvester harvests a component.
        override fun getStunStack(): StunStack = agent.stunStack
    }
    private val harvest = TurnCandidateHarvest(harvester, host)
    private val relayedCandidate =
        RelayedCandidate(TransportAddress(loopback, 40000, Transport.UDP), harvest, host.transportAddress)

    /** Created lazily so that each test can set its config before the socket reads it. */
    private val socket by lazy { RelayedCandidateDatagramSocket(relayedCandidate, harvest) }

    override suspend fun afterAny(testCase: TestCase, result: TestResult) {
        socket.close()
        agent.free()
        hostSocket.close()
        serverSocket.close()
        serverThread.join(5000)
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

    private fun Request.nonce(): ByteArray? = (getAttribute(Attribute.NONCE) as NonceAttribute?)?.nonce

    private fun serveTurn() {
        val buffer = ByteArray(1500)
        while (!serverSocket.isClosed) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                serverSocket.receive(packet)
            } catch (e: IOException) {
                // The socket has been closed.
                return
            }
            val message = Message.decode(packet.data, packet.offset, packet.length)
            if (message !is Request || message.messageType != Message.CREATEPERMISSION_REQUEST) {
                // E.g. the Refresh sent when the socket is closed. Let it time out.
                continue
            }
            receivedRequests.add(message)

            val response = when {
                !message.containsAttribute(Attribute.USERNAME) -> challenge(401, staleNonce)
                message.nonce().contentEquals(staleNonce) -> challenge(438, freshNonce)
                else -> MessageFactory.createCreatePermissionErrorResponse(finalErrorCode.toChar())
            }
            response.transactionID = message.transactionID
            val bytes = response.encode(agent.stunStack)
            serverSocket.send(DatagramPacket(bytes, bytes.size, packet.socketAddress))
        }
    }

    private fun challenge(code: Int, nonce: ByteArray) =
        MessageFactory.createCreatePermissionErrorResponse(code.toChar()).apply {
            putAttribute(AttributeFactory.createRealmAttribute(realm))
            putAttribute(AttributeFactory.createNonceAttribute(nonce))
        }

    /** Waits for a CreatePermission for [peer] to reach the server, or returns null if none does in [timeoutMs]. */
    private fun awaitCreatePermission(peer: InetAddress, timeoutMs: Long = 2000): Request? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            val request = receivedRequests.poll(remaining.coerceAtLeast(1), TimeUnit.MILLISECONDS) ?: return null
            if (request.peerAddress() == peer) {
                return request
            }
        }
    }

    /**
     * Sends a packet to [peer] and waits for the server to receive the initial CreatePermission, the retry after the
     * 401 and the retry after the 438. Returns the last of these.
     */
    private fun sendAndAwaitChallengedRequests(peer: InetAddress): Request {
        sendTo(peer)
        awaitCreatePermission(peer).shouldNotBeNull().containsAttribute(Attribute.USERNAME) shouldBe false
        awaitCreatePermission(peer).shouldNotBeNull().nonce().shouldNotBeNull().contentEquals(staleNonce) shouldBe true
        return awaitCreatePermission(peer).shouldNotBeNull().also {
            it.nonce().shouldNotBeNull().contentEquals(freshNonce) shouldBe true
        }
    }

    private val fastRetryConfig = """
        ice4j.harvest.turn.permission-retry {
          initial-delay = 100 ms
          max-delay = 300 ms
        }
    """.trimIndent()

    init {
        context("A CreatePermission request retried after 401 and 438 challenges") {
            should("be retried again after a transient failure of the retry") {
                withNewConfig(fastRetryConfig) {
                    finalErrorCode = 500
                    sendAndAwaitChallengedRequests(peerA)

                    // The 500 to the second retry fails the binding, so once the backoff has elapsed a new packet
                    // must trigger a new CreatePermission (now with credentials, so it is answered with a 500 too).
                    val start = System.nanoTime()
                    while (awaitCreatePermission(peerA, 20) == null) {
                        if (System.nanoTime() - start > TimeUnit.SECONDS.toNanos(5)) {
                            throw AssertionError("No new CreatePermission within 5 seconds")
                        }
                        sendTo(peerA)
                    }
                }
            }
            should("not be retried after a permanent failure of the retry") {
                withNewConfig(fastRetryConfig) {
                    finalErrorCode = 403
                    sendAndAwaitChallengedRequests(peerA)

                    // Give the 403 time to arrive, then check that nothing (not even media, which would otherwise
                    // force a re-bind) causes a new CreatePermission.
                    awaitCreatePermission(peerA, 300).shouldBeNull()
                    sendTo(peerA)
                    sendTo(peerA, mediaPayload)
                    sendTo(peerA)
                    awaitCreatePermission(peerA, 300).shouldBeNull()
                }
            }
        }
    }
}
