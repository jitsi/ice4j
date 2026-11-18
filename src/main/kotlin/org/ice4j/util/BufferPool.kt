/*
 * Copyright @ 2024 - present 8x8, Inc.
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
package org.ice4j.util

import java.net.SocketAddress
import java.time.Instant

/**
 * An overridable memory pool interface. Used when the push API is enabled.
 */
class BufferPool {
    companion object {
        @JvmField
        var getBuffer: (Int) -> Buffer = { size -> Buffer(ByteArray(size), 0, size) }

        @JvmField
        var returnBuffer: (Buffer) -> Unit = { }
    }
}

/** Represent a packet received from the network. */
class Buffer @JvmOverloads constructor(
    val buffer: ByteArray,
    var offset: Int,
    var length: Int,
    /** The time at which the buffer was received */
    var receivedTime: Instant? = null,
    /** The local address on which the packet was received */
    var localAddress: SocketAddress? = null,
    /** The remote address from which the packet was received */
    var remoteAddress: SocketAddress? = null
) {
    /**
     * The ECN field (RFC 3168) of the IP header the packet was received with: 0 (Not-ECT), 1 (ECT(1)), 2 (ECT(0)) or
     * 3 (CE). It is 0 if the socket the packet was received on can not report it.
     */
    var ecn: Int = 0
}

interface BufferHandler {
    fun handleBuffer(buffer: Buffer)
}
