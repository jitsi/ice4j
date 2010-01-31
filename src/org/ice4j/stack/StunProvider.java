/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.io.*;
import java.util.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;

/**
 * The StunProvider class is an implementation of a Stun Transaction Layer. STUN
 * transactions are extremely simple and are only used to correlate requests and
 * responses. In the Stun4J implementation it is the transaction layer that
 * ensures reliable delivery.
 *
 * @author Emil Ivov
 */

public class StunProvider
    implements MessageEventHandler
{
    /**
     * Our class logger.
     */
    private static final Logger logger =
        Logger.getLogger(StunProvider.class.getName());

    /**
     * Stores active client transactions mapped against TransactionID-s.
     */
    private Hashtable<TransactionID, StunClientTransaction> clientTransactions
                        = new Hashtable<TransactionID, StunClientTransaction>();

    /**
     * Currently open server transactions. The vector contains transaction ids
     * for transactions corresponding to all non-answered received requests.
     */
    private Hashtable<TransactionID, StunServerTransaction> serverTransactions
                        = new Hashtable<TransactionID, StunServerTransaction>();

    /**
     * The stack that created us.
     */
    private StunStack stunStack = null;

    /**
     * A dispatcher for incoming requests event;
     */
    private EventDispatcher eventDispatcher = new EventDispatcher();

    //------------------ public interface
    /**
     * Creates the provider.
     * @param stunStack The currently active stack instance.
     */
    StunProvider(StunStack stunStack)
    {
        this.stunStack = stunStack;
    }

    /**
     * Sends the specified request through the specified access point, and
     * registers the specified ResponseCollector for later notification.
     * @param  request     the request to send
     * @param  sendTo      the destination address of the request.
     * @param  sendThrough the local address to use when sending the request
     * @param  collector   the instance to notify when a response arrives or the
     *                     the transaction timeouts
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails,
     *
     */
    public void sendRequest( Request           request,
                             TransportAddress  sendTo,
                             TransportAddress  sendThrough,
                             ResponseCollector collector )
        throws StunException, IOException, IllegalArgumentException
    {
        StunClientTransaction clientTransaction
            = new StunClientTransaction(this, request, sendTo, sendThrough,
                                        collector);

        clientTransactions.put(clientTransaction.getTransactionID(),
                               clientTransaction);

        clientTransaction.sendRequest();
    }

    /**
     * Sends the specified response message through the specified access point.
     *
     * @param transactionID the id of the transaction to use when sending the
     * response. Actually we are getting kind of redundant here as we already
     * have the id in the response object, but I am bringing out as an extra
     * parameter as the user might otherwise forget to explicitly set it.
     * @param response      the message to send.
     * @param sendThrough   the local address to use when sending the message.
     * @param sendTo        the destination of the message.
     *
     * @throws IOException  if an error occurs while sending message bytes
     * through the network socket.
     * @throws IllegalArgumentException if the apDescriptor references an
     * access point that had not been installed,
     * @throws StunException if message encoding fails,
     */
    public void sendResponse(byte[]           transactionID,
                             Response         response,
                             TransportAddress sendThrough,
                             TransportAddress sendTo)
        throws StunException,
               IOException,
               IllegalArgumentException
    {
        TransactionID tid = TransactionID.createTransactionID(transactionID);
        StunServerTransaction sTran =
            serverTransactions.get(tid);

        if(sTran == null || sTran.isReransmitting())
        {
            throw new StunException(StunException.TRANSACTION_DOES_NOT_EXIST,
                                    "The transaction specified in the response "
                                    + "object does not exist or has already "
                                    + "transmitted a response.");
        }
        else
        {
            sTran.sendResponse(response, sendThrough, sendTo);
        }



    }

    /**
     * Sets the listener that should be notified when a new Request is received.
     * @param requestListener the listener interested in incoming requests.
     */
    public  void addRequestListener(RequestListener requestListener)
    {
        this.eventDispatcher.addRequestListener( requestListener );
    }

    /**
     * Removes the specified listener from the local listener list. (If any
     * instances of this listener have been registered for a particular
     * access point, they will not be removed).
     * @param listener the RequestListener listener to unregister
     */
    public void removeRequestListener(RequestListener listener)
    {
        this.eventDispatcher.removeRequestListener(listener);
    }

    /**
     * Add a RequestListener for requests coming from a specific NetAccessPoint.
     * The listener will be invoked only when a request event is received on
     * that specific property.
     *
     * @param localAddress The local <tt>TransportAddress</tt> that we would
     * like to listen on.
     * @param listener The ConfigurationChangeListener to be added
     */

    public void addRequestListener( TransportAddress localAddress,
                                    RequestListener  listener)
    {
        synchronized(eventDispatcher)
        {
            eventDispatcher.addRequestListener(localAddress, listener);
        }
    }

//------------- stack internals ------------------------------------------------
    /**
     * Returns the currently active instance of NetAccessManager. Used by client
     * transactions when sending messages.
     * @return the currently active instance of NetAccessManager.
     */
    NetAccessManager getNetAccessManager()
    {
        return stunStack.getNetAccessManager();
    }

    /**
     * Removes a client transaction from this providers client transactions list.
     * Method is used by StunClientTransaction-s themselves when a timeout occurs.
     * @param tran the transaction to remove.
     */
    synchronized void removeClientTransaction(StunClientTransaction tran)
    {
        clientTransactions.remove(tran.getTransactionID());
    }

    /**
     * Removes a server transaction from this provider's server transactions
     * list.
     * Method is used by StunServerTransaction-s themselves when they expire.
     * @param tran the transaction to remove.
     */
    synchronized void removeServerTransaction(StunServerTransaction tran)
    {
        serverTransactions.remove(tran.getTransactionID());
    }

    /**
     * Called to notify this provider for an incoming message.
     *
     * @param event the event object that contains the new message.
     */
    public void handleMessageEvent(StunMessageEvent event)
    {
        Message msg = event.getMessage();

        if(logger.isLoggable(Level.FINEST))
            logger.finest("Received a message on NetAP"
                        + event.getLocalAddress()
                        + " of type:"
                        + (int)msg.getMessageType());

        //request
        if(msg instanceof Request)
        {
            logger.finest("parsing request");
            TransactionID serverTid = TransactionID.
                                    createTransactionID(msg.getTransactionID());

            StunServerTransaction sTran  = serverTransactions.get(serverTid);
            if( sTran != null)
            {

                //requests from this transaction have already been seen
                //retransmit the response if there was any
                logger.finest("found an existing transaction");

                try
                {
                    sTran.retransmitResponse();
                    logger.finest("Response retransmitted");
                }
                catch (Exception ex)
                {
                    //we couldn't really do anything here .. apart from logging
                    logger.log(Level.WARNING,
                               "Failed to retransmit a stun response", ex);
                }

                String propagate = System.getProperty(
                    "org.ice4j.PROPAGATE_RECEIVED_RETRANSMISSIONS");
                if(propagate == null
                    || !propagate.trim().equalsIgnoreCase("true"))
                {
                    return;
                }
            }
            else
            {
                logger.finest("exising transaction not found");
                sTran =
                    new StunServerTransaction(this, serverTid);

                serverTransactions.put(serverTid, sTran);
                sTran.start();
            }

            eventDispatcher.fireMessageEvent(event);
        }
        //response
        else if(msg instanceof Response)
        {
            TransactionID tid
                = TransactionID.createTransactionID(msg.getTransactionID());

            StunClientTransaction tran =
                clientTransactions.remove(tid);

            if(tran != null)
            {
                tran.handleResponse(event);
            }
            else
            {
                //do nothing - just drop the phantom response.
                logger.fine("Dropped response - "
                                            + "no matching client tran found.");
                logger.fine("response tid was - " + tid.toString());
                logger.fine("all tids in stock were"
                                            + clientTransactions.toString());
            }
        }

    }

    /**
     * Cancels all running transactions and prepares for garbage collection
     */
    void shutDown()
    {
        eventDispatcher.removeAllListeners();

        Enumeration<TransactionID> tids = clientTransactions.keys();
        while (tids.hasMoreElements())
        {
            TransactionID item = (TransactionID)tids.nextElement();
            StunClientTransaction tran = clientTransactions.remove(item);
            if(tran != null)
                tran.cancel();

        }

        tids = serverTransactions.keys();
        while (tids.hasMoreElements())
        {
            TransactionID item = (TransactionID)tids.nextElement();
            StunServerTransaction tran = serverTransactions.remove(item);
            if(tran != null)
                tran.expire();

        }
    }

}
