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

/**
 * Represents an {@code Object} with a timestamp.
 *
 * @param <T> the type of the {@code Object} which has a timestamp (associated)
 * @author Lyubomir Marinov
 */
class Timestamped<T>
{
    /**
     * The {@code Object} associated with {@link #timestamp}.
     */
    final T o;

    /**
     * The timestamp (in milliseconds) associated with {@link #o}.
     */
    long timestamp;

    /**
     * Initializes a new {@code Timestamped} instance with a specific
     * {@code Object} and a default timestamp (value).
     *
     * @param o the {@code Object} to associate with a timestamp
     */
    public Timestamped(T o)
    {
        this(o, -1);
    }

    /**
     * Initializes a new {@code Timestamped} instance with a specific
     * {@code Object} and a specific timestamp (value).
     *
     * @param o the {@code Object} to associate with {@code timestamp}
     * @param timestamp the timestamp (in milliseconds) to associate with
     * {@code o}
     */
    public Timestamped(T o, long timestamp)
    {
        // It makes no sense to associate a timestamp with a null.
        if (o == null)
            throw new NullPointerException("o");

        this.o = o;
        this.timestamp = timestamp;
    }
}
