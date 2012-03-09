/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.io.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The ClientTransaction class retransmits (what a surprise) requests as
 * specified by rfc 3489.
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
 *
 * @author Emil Ivov.
 * @author Pascal Mogeri (contributed configuration of client transactions).
 */
class StunClientTransaction
    implements Runnable
{
    /**
     * Our class logger.
     */
    private static final Logger logger =
        Logger.getLogger(StunClientTransaction.class.getName());

    /**
     * The number of times to retransmit a request if no explicit value has been
     * specified by org.ice4j.MAX_RETRANSMISSIONS.
     */
    public static final int DEFAULT_MAX_RETRANSMISSIONS = 6;

    /**
     * Maximum number of retransmissions. Once this number is reached and if no
     * response is received after MAX_WAIT_INTERVAL milliseconds the request is
     * considered unanswered.
     */
    public int maxRetransmissions = DEFAULT_MAX_RETRANSMISSIONS;

    /**
     * The number of milliseconds a client should wait before retransmitting,
     * after it has sent a request for the first time.
     */
    public static final int DEFAULT_ORIGINAL_WAIT_INTERVAL = 100;

    /**
     * The number of milliseconds to wait before the first retransmission of the
     * request.
     */
    public int originalWaitInterval = DEFAULT_ORIGINAL_WAIT_INTERVAL;

    /**
     * The maximum number of milliseconds a client should wait between
     * consecutive retransmissions, after it has sent a request for the first
     * time.
     */
    public static final int DEFAULT_MAX_WAIT_INTERVAL = 1600;

    /**
     * The maximum wait interval. Once this interval is reached we should stop
     * doubling its value.
     */
    public int maxWaitInterval = DEFAULT_MAX_WAIT_INTERVAL;

    /**
     * Indicates how many times we have retransmitted so fat.
     */
    private int retransmissionCounter = 0;

    /**
     * How much did we wait after our last retransmission.
     */
    private int nextWaitInterval = originalWaitInterval;

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
    private boolean cancelled = false;

    /**
     * The thread that this transaction runs in.
     */
    private Thread retransmissionsThread = null;

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
        this(stackCallback, request, requestDestination, localAddress,
                   responseCollector, TransactionID.createNewTransactionID());
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
            //Shouldn't happen so lets just through a runtime exception in
            //case anything is real messed up
            throw new IllegalArgumentException("The TransactionID class "
                                      +"generated an invalid transaction ID");
        }

        retransmissionsThread = new Thread(this,
                        "StunClientTransaction@"+hashCode());
        retransmissionsThread.setDaemon(true);
    }

    /**
     * Implements the retransmissions algorithm. Retransmits the request
     * starting with an interval of 100ms, doubling every retransmit until the
     * interval reaches 1.6s.  Retransmissions continue with intervals of 1.6s
     * until a response is received, or a total of 7 requests have been sent.
     * If no response is received by 1.6 seconds after the last request has been
     * sent, we consider the transaction to have failed.
     */
    public void run()
    {
        retransmissionsThread.setName("ice4j.ClientTransaction");
        nextWaitInterval = originalWaitInterval;

        synchronized(this)
        {
            for (retransmissionCounter = 0;
                 retransmissionCounter < maxRetransmissions;
                 retransmissionCounter ++)
            {
                waitFor(nextWaitInterval);

                //did someone tell us to get lost?
                if(cancelled)
                    return;

                if(nextWaitInterval < maxWaitInterval)
                    nextWaitInterval *= 2;

                try
                {
                    logger.fine("retrying transmission of STUN test to " +
                            requestDestination.getHostAddress());
                    sendRequest0();
                }
                catch (Exception ex)
                {
                    //I wonder whether we should notify anyone that a
                    //retransmission has failed
                    logger.log(Level.INFO,
                               "A client tran retransmission failed", ex);
                }
            }

            //before stating that a transaction has timeout-ed we should first
            //wait for a reception of the response
            if(nextWaitInterval < maxWaitInterval)
                    nextWaitInterval *= 2;

            waitFor(nextWaitInterval);

            if(cancelled)
                return;

            stackCallback.removeClientTransaction(this);
            responseCollector.processTimeout(
                    new StunTimeoutEvent(
                            stackCallback,
                            this.request, getLocalAddress(), transactionID));
        }
    }

    /**
     * Sends the request and schedules the first retransmission for after
     * ORIGINAL_WAIT_INTERVAL and thus starts the retransmission algorithm.
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
        sendRequest0();

        retransmissionsThread.start();
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
        if(cancelled)
        {
            logger.finer("Trying to resend a cancelled transaction.");
            return;
        }

        stackCallback.getNetAccessManager().sendMessage(
                this.request,
                localAddress,
                requestDestination);
    }

    /**
     * Returns the request that was the reason for creating this transaction.
     * @return the request that was the reason for creating this transaction.
     */
    Request getRequest()
    {
        return this.request;
    }

    /**
     * Waits until next retransmission is due or until the transaction is
     * cancelled (whichever comes first).
     *
     * @param millis the number of milliseconds to wait for.
     */
    void waitFor(long millis)
    {
        try
        {
            wait(millis);
        }
        catch (InterruptedException ex)
        {
            logger.log(Level.FINE, "Interrupted", ex);
        }
    }

    /**
     * Cancels the transaction. Once this method is called the transaction is
     * considered terminated and will stop retransmissions.
     *
     * @param waitForResponse indicates whether we should wait for the current
     * RTO to expire before ending the transaction or immediately terminate.
     */
    synchronized void cancel(boolean waitForResponse)
    {
        this.cancelled = true;

        if(!waitForResponse)
            notifyAll();
    }

    /**
     * Cancels the transaction. Once this method is called the transaction is
     * considered terminated and will stop retransmissions.
     */
    synchronized void cancel()
    {
        cancel(false);
    }

    /**
     * Dispatches the response then cancels itself and notifies the StunStack
     * for its termination.
     *
     * @param evt the event that contains the newly received message
     */
    synchronized void handleResponse(StunMessageEvent evt)
    {
        if( !Boolean.getBoolean(StackProperties.KEEP_CRANS_AFTER_A_RESPONSE) )
            this.cancel();

        this.responseCollector.processResponse(
                new StunResponseEvent(
                        stackCallback,
                        evt.getRawMessage(),
                        (Response) evt.getMessage(),
                        this.request,
                        getTransactionID()));
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
     * Init transaction duration/retransmission parameters.
     * (Mostly, contributed by Pascal Maugeri).
     */
    private void initTransactionConfiguration()
    {
        //Max Retransmissions
        String maxRetransmissionsStr
            = System.getProperty(StackProperties.MAX_CTRAN_RETRANSMISSIONS);

        if(maxRetransmissionsStr != null
           && maxRetransmissionsStr.trim().length() > 0){
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
           && originalWaitIntervalStr.trim().length() > 0){
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
           && maxWaitIntervalStr.trim().length() > 0){
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
}
