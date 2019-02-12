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
import java.time.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.util.*;

/**
 * The {@code StunClientTransaction} class retransmits requests as specified by
 * RFC 3489.
 *
 * Once formulated and sent, the client sends the Binding Request.  Reliability
 * is accomplished through request retransmissions.  The
 * {@code StunClientTransaction} retransmits the request starting with an
 * interval of 100ms, doubling every retransmit until the interval reaches 1.6s.
 * Retransmissions continue with intervals of 1.6s until a response is received,
 * or a total of 9 requests have been sent. If no response is received by 1.6
 * seconds after the last request has been sent, the client SHOULD consider the
 * transaction to have failed. In other words, requests would be sent at times
 * 0ms, 100ms, 300ms, 700ms, 1500ms, 3100ms, 4700ms, 6300ms, and 7900ms. At
 * 9500ms, the client considers the transaction to have failed if no response
 * has been received.
 *
 * @author Emil Ivov.
 * @author Pascal Mogeri (contributed configuration of client transactions).
 * @author Lyubomir Marinov
 */
public class StunClientTransaction
{
    /**
     * Our class logger.
     */
    private static final java.util.logging.Logger logger
        = java.util.logging.Logger.getLogger(StunClientTransaction.class.getName());

    /**
     * The number of times to retransmit a request if no explicit value has been
     * specified by org.ice4j.MAX_RETRANSMISSIONS.
     */
    public static final int DEFAULT_MAX_RETRANSMISSIONS = 6;

    /**
     * The maximum number of milliseconds a client should wait between
     * consecutive retransmissions, after it has sent a request for the first
     * time.
     */
    public static final int DEFAULT_MAX_WAIT_INTERVAL = 1600;

    /**
     * The number of milliseconds a client should wait before retransmitting,
     * after it has sent a request for the first time.
     */
    public static final int DEFAULT_ORIGINAL_WAIT_INTERVAL = 100;

    /**
     * The pool of <tt>Thread</tt>s which schedules retransmission of
     * <tt>StunClientTransaction</tt>s.
     */
    private static final ScheduledExecutorService retransmissionTimer
        = ExecutorFactory.createSingleThreadScheduledExecutor(
            "ice4j.StunClientTransaction-timer-", 60, TimeUnit.SECONDS);

    /**
     * The pool of <tt>Thread</tt>s which retransmits
     * <tt>StunClientTransaction</tt>s.
     */
    private static final ExecutorService retransmissionExecutor
        = ExecutorFactory.createCachedThreadPool(
            "ice4j.StunClientTransaction-executor-");


    /**
     * Maximum number of retransmissions. Once this number is reached and if no
     * response is received after {@link #maxWaitInterval} milliseconds the
     * request is considered unanswered.
     */
    public int maxRetransmissions = DEFAULT_MAX_RETRANSMISSIONS;

    /**
     * The number of milliseconds to wait before the first retransmission of the
     * request.
     */
    public int originalWaitInterval = DEFAULT_ORIGINAL_WAIT_INTERVAL;

    /**
     * The maximum wait interval. Once this interval is reached we should stop
     * doubling its value.
     */
    public int maxWaitInterval = DEFAULT_MAX_WAIT_INTERVAL;

    /**
     * The <tt>StunStack</tt> that created us.
     */
    private final StunStack stackCallback;

    /**
     * The request that we are retransmitting.
     */
    private final Request request;

    /**
     * The destination of the request.
     */
    private final TransportAddress requestDestination;

    /**
     * The id of the transaction.
     */
    private final TransactionID transactionID;

    /**
     * The <tt>TransportAddress</tt> through which the original request was sent
     * and that we are supposed to be retransmitting through.
     */
    private final TransportAddress localAddress;

    /**
     * The instance to notify when a response has been received in the current
     * transaction or when it has timed out.
     */
    private final ResponseCollector responseCollector;

    /**
     * Determines whether the transaction is active or not.
     */
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    /**
     * A transaction request retransmitter
     */
    private final Retransmitter retransmitter = new Retransmitter();

    /**
     * Creates a client transaction.
     *
     * @param stackCallback the stack that created us.
     * @param request the request that we are living for.
     * @param requestDestination the destination of the request.
     * @param localAddress the local <tt>TransportAddress</tt> this transaction
     * will be communication through.
     * @param responseCollector the instance that should receive this request's
     * response retransmit.
     */
    public StunClientTransaction(StunStack         stackCallback,
                                 Request           request,
                                 TransportAddress  requestDestination,
                                 TransportAddress  localAddress,
                                 ResponseCollector responseCollector)
    {
        this(stackCallback,
             request,
             requestDestination,
             localAddress,
             responseCollector,
             TransactionID.createNewTransactionID());
    }

    /**
     * Creates a client transaction.
     *
     * @param stackCallback the stack that created us.
     * @param request the request that we are living for.
     * @param requestDestination the destination of the request.
     * @param localAddress the local <tt>TransportAddress</tt> this transaction
     * will be communication through.
     * @param responseCollector the instance that should receive this request's
     * response retransmit.
     * @param transactionID the ID that we'd like the new transaction to have
     * in case the application created it in order to use it for application
     * data correlation.
     */
    public StunClientTransaction(StunStack         stackCallback,
                                 Request           request,
                                 TransportAddress  requestDestination,
                                 TransportAddress  localAddress,
                                 ResponseCollector responseCollector,
                                 TransactionID     transactionID)
    {
        this.stackCallback      = stackCallback;
        this.request            = request;
        this.localAddress       = localAddress;
        this.responseCollector  = responseCollector;
        this.requestDestination = requestDestination;

        initTransactionConfiguration();

        this.transactionID = transactionID;

        try
        {
            request.setTransactionID(transactionID.getBytes());
        }
        catch (StunException ex)
        {
            // Shouldn't happen so lets just throw a RuntimeException in case
            // something is really messed up.
            throw new IllegalArgumentException(
                    "The TransactionID class generated an invalid transaction"
                        + " ID");
        }
    }

    /**
     * Sends the request and schedules the first retransmission for after
     * {@link #originalWaitInterval} and thus starts the retransmission
     * algorithm.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed
     *
     */
    void sendRequest()
        throws IllegalArgumentException, IOException
    {
        logger.fine(
                "sending STUN " + " tid " + transactionID + " from "
                    + localAddress + " to " + requestDestination);
        sendRequest0();

        this.retransmitter.schedule();
    }

    /**
     * Simply calls the sendMessage method of the accessmanager.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     */
    private void sendRequest0()
        throws IllegalArgumentException, IOException
    {
        if (cancelled.get())
        {
            logger.finer("Trying to resend a cancelled transaction.");
        }
        else
        {
            stackCallback.getNetAccessManager().sendMessage(
                    this.request,
                    localAddress,
                    requestDestination);
        }
    }

    /**
     * Returns the request that was the reason for creating this transaction.
     *
     * @return the request that was the reason for creating this transaction.
     */
    Request getRequest()
    {
        return this.request;
    }

    /**
     * Cancels the transaction. Once this method is called the transaction is
     * considered terminated and will stop retransmissions.
     */
    void cancel()
    {
        // The cancelled field is initialized to false and then the one and
        // only write access to it is here to set it to true. The rest of the
        // code just checks whether it has become true.
        cancelled.set(true);

        this.retransmitter.cancel();
    }

    /**
     * Dispatches the response then cancels itself and notifies the StunStack
     * for its termination.
     *
     * @param evt the event that contains the newly received message
     */
    public void handleResponse(StunMessageEvent evt)
    {
        TransactionID transactionID = getTransactionID();

        logger.fine("handleResponse tid " + transactionID);
        if(!Boolean.getBoolean(StackProperties.KEEP_CRANS_AFTER_A_RESPONSE))
        {
            cancel();
        }

        responseCollector.processResponse(
            new StunResponseEvent(
                stackCallback,
                evt.getRawMessage(),
                (Response) evt.getMessage(),
                request,
                transactionID));
    }

    /**
     * Returns the ID of the current transaction.
     *
     * @return the ID of the transaction.
     */
    TransactionID getTransactionID()
    {
        return this.transactionID;
    }

    /**
     * Init transaction duration/retransmission parameters. (Mostly contributed
     * by Pascal Maugeri.)
     */
    private void initTransactionConfiguration()
    {
        //Max Retransmissions
        String maxRetransmissionsStr
            = System.getProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);

        if(maxRetransmissionsStr != null
                && maxRetransmissionsStr.trim().length() > 0)
        {
            try
            {
                maxRetransmissions = Integer.parseInt(maxRetransmissionsStr);
            }
            catch (NumberFormatException e)
            {
                logger.log(Level.FINE,
                           "Failed to parse MAX_RETRANSMISSIONS",
                           e);
                maxRetransmissions = DEFAULT_MAX_RETRANSMISSIONS;
            }
        }

        //Original Wait Interval
        String originalWaitIntervalStr
            = System.getProperty(StackProperties.FIRST_CTRAN_RETRANS_AFTER);

        if(originalWaitIntervalStr != null
                && originalWaitIntervalStr.trim().length() > 0)
        {
            try
            {
                originalWaitInterval
                    = Integer.parseInt(originalWaitIntervalStr);
            }
            catch (NumberFormatException e)
            {
                logger.log(Level.FINE,
                           "Failed to parse ORIGINAL_WAIT_INTERVAL",
                           e);
                originalWaitInterval = DEFAULT_ORIGINAL_WAIT_INTERVAL;
            }
        }

        //Max Wait Interval
        String maxWaitIntervalStr
                = System.getProperty(StackProperties.MAX_CTRAN_RETRANS_TIMER);

        if(maxWaitIntervalStr != null
                && maxWaitIntervalStr.trim().length() > 0)
        {
            try
            {
                maxWaitInterval = Integer.parseInt(maxWaitIntervalStr);
            }
            catch (NumberFormatException e)
            {
                logger.log(Level.FINE, "Failed to parse MAX_WAIT_INTERVAL", e);
                maxWaitInterval = DEFAULT_MAX_WAIT_INTERVAL;
            }
        }
    }

    /**
     * Returns the local <tt>TransportAddress</tt> that this transaction is
     * sending requests from.
     *
     * @return  the local <tt>TransportAddress</tt> that this transaction is
     * sending requests from.
     */
    public TransportAddress getLocalAddress()
    {
        return localAddress;
    }

    /**
     * Returns the remote <tt>TransportAddress</tt> that this transaction is
     * sending requests to.
     *
     * @return the remote <tt>TransportAddress</tt> that this transaction is
     * sending requests to.
     */
    public TransportAddress getRemoteAddress()
    {
        return requestDestination;
    }

    /**
     * Implements the retransmissions algorithm. Retransmits the request
     * starting with an interval of 100ms, doubling every retransmit until the
     * interval reaches 1.6s.  Retransmissions continue with intervals of 1.6s
     * until a response is received, or a total of 7 requests have been sent.
     * If no response is received by 1.6 seconds after the last request has been
     * sent, we consider the transaction to have failed.
     */
    private final class Retransmitter extends PeriodicRunnable
    {
        /**
         * Current number of retransmission attempts
         */
        private int retransmissionCounter = 0;

        /**
         * Delay before attempting next retransmission
         */
        private int nextRetransmissionDelay = originalWaitInterval;

        protected Retransmitter()
        {
            super(retransmissionTimer, retransmissionExecutor);
        }

        @Override
        protected Duration getDelayUntilNextRun()
        {
            return Duration.ofMillis(nextRetransmissionDelay);
        }

        @Override
        protected void run()
        {
            retransmissionCounter++;

            int curWaitInterval = nextRetransmissionDelay;
            nextRetransmissionDelay
                = Math.min(maxWaitInterval, 2 * nextRetransmissionDelay);

            if (retransmissionCounter <= maxRetransmissions)
            {
                try
                {
                    logger.fine(
                        "retrying STUN tid " + transactionID + " from "
                            + localAddress + " to " + requestDestination
                            + " waited " + curWaitInterval + " ms retrans "
                            + retransmissionCounter + " of "
                            + maxRetransmissions);
                    sendRequest0();
                }
                catch (Exception ex)
                {
                    //I wonder whether we should notify anyone that a retransmission
                    // has failed
                    logger.log(
                        Level.INFO,
                        "A client tran retransmission failed",
                        ex);
                }
            }
            else
            {
                stackCallback.removeClientTransaction(
                    StunClientTransaction.this);

                responseCollector.processTimeout(
                    new StunTimeoutEvent(
                        stackCallback,
                        getRequest(), getLocalAddress(), getTransactionID()));

                nextRetransmissionDelay = -1;
            }
        }
    }
}
