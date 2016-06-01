/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
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
package org.ice4j.socket.jdk8;

import java.net.*;
import java.nio.*;

/**
 * Associates a {@link ByteBuffer} with a {@link DatagramPacket} so that the
 * {@code ByteBuffer} may be used for writing into a {@code byte} array and the
 * {@code DatagramPacket} may be used for reading from the same {@code byte}
 * array.
 *
 * @author Lyubomir Marinov
 */
class DatagramBuffer
    extends Timestamped<ByteBuffer>
{
    /**
     * The {@code DatagramPacket} which is associated with the
     * {@link ByteBuffer} {@link #o} and shares its {@code data} with.
     */
    private final DatagramPacket datagramPacket;

    /**
     * Initializes a new {@code DatagramBuffer} instance with a specific
     * capacity of {@code byte}s shared between a {@code ByteBuffer} and a
     * {@code DatagramPacket}.
     *
     * @param capacity the maximum number of {@code byte}s to be written into
     * and read from the new instance
     */
    public DatagramBuffer(int capacity)
    {
        super(ByteBuffer.allocate(capacity));

        datagramPacket
            = new DatagramPacket(o.array(), /* offset */ 0, /* length */ 0);
    }

    /**
     * Gets the {@code ByteBuffer} (view) of this instance.
     *
     * @return the {@code ByteBuffer} (view) of this instance
     */
    public ByteBuffer getByteBuffer()
    {
        return o;
    }

    /**
     * Gets the {@code DatagramPacket} (view) of this instance. The
     * {@code length} of the {@code DatagramPacket} equals the {@code position}
     * of the {@code ByteBuffer} so that the {@code byte}s written into the
     * {@code ByteBuffer} may be read from the {@code DatagramPacket}.
     *
     * @return the {@code DatagramPacket} (view) of this instance
     */
    public DatagramPacket getDatagramPacket()
    {
        datagramPacket.setLength(getByteBuffer().position());
        return datagramPacket;
    }
}
