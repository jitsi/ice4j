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
package org.ice4j.stack;

import java.io.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * A STUN client retransmits requests as specified by the protocol.
 *
 * Once formulated and sent, the client sends the Binding Request.  Reliability
 * is accomplished through request retransmissions.  The ClientTransaction
 * retransmits the request starting with an interval of 100ms, doubling
 * every retransmit until the interval reaches 1.6s.  Retransmissions
 * continue with intervals of 1.6s until a response is received, or a
 * total of 9 requests have been sent. If no response is received by 1.6
 * seconds after the last request has been sent, the client SHOULD
 * consider the transaction to have failed. In other words, requests
 * would be sent at times 0ms, 100ms, 300ms, 700ms, 1500ms, 3100ms,
 * 4700ms, 6300ms, and 7900ms. At 9500ms, the client considers the
 * transaction to have failed if no response has been received.
 *
 * A server transaction is therefore responsible for retransmitting the same
 * response that was saved for the original request, and not let any
 * retransmissions go through to the user application.
 *
 * @author Emil Ivov
 */
public class StunServerTransaction
{
    /**
     * The time that we keep server transactions active.
     */
    static final long LIFETIME_MILLIS = 16000;

    /**
     * The id of the transaction.
     */
    private final TransactionID transactionID;

    /**
     * The <tt>StunStack</tt> that created us.
     */
    private final StunStack stackCallback;

    /**
     * The address that we are receiving requests from.
     */
    private final TransportAddress requestSource;

    /**
     * The <tt>TransportAddress</tt> that we received our request on.
     */
    private final TransportAddress localListeningAddress;

    /**
     * The response sent in response to the request.
     */
    private Response response = null;

    /**
     * The address that we are sending responses to.
     */
    private TransportAddress responseDestination = null;

    /**
     * The <tt>TransportAddress</tt> we use when sending responses
     */
    private TransportAddress localSendingAddress = null;

    /**
     * Determines whether or not the transaction has expired.
     */
    private final AtomicBoolean expired = new AtomicBoolean(false);

    /**
     * The timestamp when transaction is started. Used to determine if
     * transaction is expired
     */
    private final AtomicLong transactionStartedTimestampNanos
        = new AtomicLong(-1);

    /**
     * Creates a server transaction
     * @param stackCallback the stack that created us.
     * @param tranID the transaction id contained by the request that was the
     * cause for this transaction.
     * @param localListeningAddress the <tt>TransportAddress</tt> that this
     * transaction is receiving requests on.
     * @param requestSource the <tt>TransportAddress</tt> that this
     * transaction is receiving requests from.
     */
    public StunServerTransaction(StunStack        stackCallback,
                                 TransactionID    tranID,
                                 TransportAddress localListeningAddress,
                                 TransportAddress requestSource)
    {
        this.stackCallback  = stackCallback;
        this.transactionID  = tranID;
        this.localListeningAddress = localListeningAddress;
        this.requestSource = requestSource;
    }

    /**
     * Start the transaction. This launches the countdown to the moment the
     * transaction would expire.
     */
    public void start()
    {
        final boolean isUpdated = transactionStartedTimestampNanos
            .compareAndSet(-1, System.nanoTime());

        if (!isUpdated) {
            throw new IllegalStateException(
                "StunServerTransaction " + getTransactionID()
                    + " has already been started!");
        }
    }

    /**
     * Sends the specified response through the <code>sendThrough</code>
     * NetAccessPoint descriptor to the specified destination and changes
     * the transaction's state to retransmitting.
     *
     * @param response the response to send the transaction to.
     * @param sendThrough the local address through which responses are to
     * be sent
     * @param sendTo the destination for responses of this transaction.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails,
     */
    public void sendResponse(Response         response,
                             TransportAddress sendThrough,
                             TransportAddress sendTo)
        throws StunException,
               IOException,
               IllegalArgumentException
    {
        if (response == null)
        {
            throw new IllegalArgumentException("response must not be null");
        }

        if (this.response == null){
            this.response = response;
            //the transaction id might already have been set, but its our job
            //to make sure of that
            response.setTransactionID(this.transactionID.getBytes());
            this.localSendingAddress   = sendThrough;
            this.responseDestination   = sendTo;
        }

        retransmitResponse();
    }

    /**
     * Retransmits the response that was originally sent to the request that
     * caused this transaction.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails,
     */
    protected void retransmitResponse()
        throws StunException,
               IOException,
               IllegalArgumentException
    {
        //don't retransmit if we are expired or if the user application
        //hasn't yet transmitted a first response
        if(isExpired() || !isRetransmitting())
        {
            return;
        }

        stackCallback.getNetAccessManager().sendMessage(
                response,
                localSendingAddress,
                responseDestination);
    }

    /**
     * Cancels the transaction. Once this method is called the transaction is
     * considered terminated and will stop retransmissions.
     */
    public void expire()
    {
        expired.set(true);
    }

    /**
     * Determines whether this <tt>StunServerTransaction</tt> is expired now.
     *
     * @return <tt>true</tt> if this <tt>StunServerTransaction</tT> is expired
     * now; otherwise, <tt>false</tt>
     */
    public boolean isExpired()
    {
        if (expired.get())
        {
            return true;
        }

        if (isStarted())
        {
            return false;
        }

        long elapsedTime
            = System.nanoTime() - transactionStartedTimestampNanos.get();

        if (elapsedTime > TimeUnit.MILLISECONDS.toNanos(LIFETIME_MILLIS))
        {
            expire();
            return true;
        }
        return false;
    }

    /**
     * Returns the ID of the current transaction.
     *
     * @return the ID of the transaction.
     */
    public TransactionID getTransactionID()
    {
        return transactionID;
    }

    /**
     * Determines whether or not the transaction is in a retransmitting state.
     * In other words whether a response has already been sent once to the
     * transaction request.
     *
     * @return <tt>true</tt> if this transaction is still retransmitting and
     * false <tt>otherwise</tt>
     */
    public boolean isRetransmitting()
    {
        return response != null;
    }

    /**
     * Returns the local <tt>TransportAddress</tt> that this transaction is
     * sending responses from.
     *
     * @return the local <tt>TransportAddress</tt> that this transaction is
     * sending responses from.
     */
    public TransportAddress getSendingAddress()
    {
        return localSendingAddress;
    }

    /**
     * Returns the remote <tt>TransportAddress</tt> that this transaction is
     * receiving requests from.
     *
     * @return the remote <tt>TransportAddress</tt> that this transaction is
     * receiving requests from.
     */
    public TransportAddress getResponseDestinationAddress()
    {
        return responseDestination;
    }

    /**
     * Returns the local <tt>TransportAddress</tt> that this transaction is
     * receiving requests on.
     *
     * @return the local <tt>TransportAddress</tt> that this transaction is
     * receiving requests on.
     */
    public TransportAddress getLocalListeningAddress()
    {
        return localListeningAddress;
    }

    /**
     * Returns the remote <tt>TransportAddress</tt> that this transaction is
     * receiving requests from.
     *
     * @return the remote <tt>TransportAddress</tt> that this transaction is
     * receiving requests from.
     */
    public TransportAddress getRequestSourceAddress()
    {
        return requestSource;
    }

    /**
     * Returns the <tt>Response</tt> that the <tt>StunStack</tt> has sent
     * through this transaction or <tt>null</tt> if no <tt>Response</tt> has
     * been sent yet.
     *
     * @return the <tt>Response</tt> that the <tt>StunStack</tt> has sent
     * through this transaction or <tt>null</tt> if no <tt>Response</tt> has
     * been sent yet.
     */
    protected Response getResponse()
    {
        return response;
    }

    /**
     * Determines if transaction is started
     * @return true when transaction is started
     */
    private boolean isStarted()
    {
        return transactionStartedTimestampNanos.get() != -1;
    }
}
