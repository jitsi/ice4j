package org.ice4j.stunclient;

import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;
import org.ice4j.stunclient.*;


/**
 * The interface given to the ICE agent to send STUN requests
 * and receive responses
 *
 * @author Namal Senarathne
 */
public class StunClient
    implements ResponseCollector
{

    private final Logger logger =
        Logger.getLogger(StunClient.class.getName());

    /**
    * The STUN stack
    */
    private StunStack stunStack = null;

    /**
    * The Stun Provider from the stack
    */
    private StunProvider stunProvider = null;

    /**
    * The HashMap used to store the sent requests and correlate between
    * the responses and the requests.
    * This data structure is used only when sendStunRequest message is invoked
    */
    private HashMap<byte[], Request> requestMap = new HashMap<byte[], Request>();

    /**
     * Creates a new Instance of the ST
     * @param stunStack
     */
    public StunClient(StunStack stunStack)
    {
        this.stunStack = stunStack;

        stunProvider = stunStack.getProvider();
    }

    //------------------ Implemented methods of the ResponseCollector interface -------------
    /**
    * This callBack method is called in a separate thread to process
    * incomming response
    */
    public void processResponse(StunMessageEvent response) {
        // TODO Auto-generated method stub

        Message responseMsg = response.getMessage();     /* retrieving the response message */

        byte[] tid = responseMsg.getTransactionID();    /* retrieving the Transaction ID */

        synchronized(requestMap)
        {
            if(requestMap.containsKey(tid))
            {
                // TODO : process the response
                requestMap.remove(tid);
                // TODO : additional processing ; set done status for the candidate pair
            }
        }

        MappedAddressAttribute mappedAttribute =
            (MappedAddressAttribute)responseMsg.getAttribute(Attribute.MAPPED_ADDRESS);

        if(mappedAttribute != null)
        {
      TransportAddress mappedAddr = mappedAttribute.getAddress();
            System.out.println("The mapped address : " + mappedAddr.getHostAddress() +
                                " : " + (int)mappedAddr.getPort());
        }
    }

    /**
    *
    */
    public void processTimeout() {
        // TODO Auto-generated method stub
        // How can you recognize which request (TransactionID) timed-out
        // ignore it at the moment
    }


    //-------------------- Public interface ---------------------------------------

    // TODO : move them up
    private boolean ended = false;
    private Object  sendLock = new Object();

    /**
    * Determines the public IP of the specified Transport address in a blocking manner
    */
    public TransportAddress determineAddress(TransportAddress localAddress,
                                        TransportAddress serverAddress)
        throws StunException, IOException
    {
        NetAccessPointDescriptor apDescriptor
            = new NetAccessPointDescriptor(localAddress);
        Request request = MessageFactory.createBindingRequest();

        stunStack.installNetAccessPoint(apDescriptor);

        synchronized (sendLock)
        {
        try
        {
            stunProvider.sendRequest(request, serverAddress,
                            apDescriptor, this);
        }
        catch(Exception e)
        {
          logger.warning("Cannot determine mapped address for " + localAddress);
        }
        }

        ended = false;

        return null;
    }

    /**
    * Determines the NAT type
    */
    public TransportAddress determineAddress(NetAccessPointDescriptor apDescriptor,
                                        TransportAddress serverAddress)
    {
        return null;
    }

    /**
    * TODO : modify the signature of the method
    *
    * @param    request             The stun Request object
    * @param    sendTo              The address of the server
    * @param    apDescriptor        The NetAccessPointDescriptor
    * @param    collector           The response collector
    */
    public void sendStunRequest(Request request,
                                TransportAddress sendTo,
                                NetAccessPointDescriptor apDescriptor, // apDescriptor must be installed in the stack
                                ResponseCollector collector)
        throws StunException, IOException, IllegalArgumentException
    {
        logger.log(Level.INFO, "Sending the request ... ");
        try
        {
            stunProvider.sendRequest(request, sendTo, apDescriptor, collector);
            synchronized (requestMap) {
                requestMap.put(request.getTransactionID(), request);
            }
        }
        catch(StunException ex)
        {
            logger.log(Level.SEVERE, "StunException occurred..", ex);
            throw new StunException();
        }
        catch(IOException ex)
        {
            logger.log(Level.SEVERE, "IOException occurred", ex);
            throw new StunException();
        }
        catch(IllegalArgumentException ex)
        {
            logger.log(Level.SEVERE, "IllegalArgumentException occurred", ex);
            throw new StunException();
        }

    }

    /*public static void main(String[] args) throws IOException, IllegalArgumentException, StunException
    {
        StunStack stunStack = StunStack.getInstance();

        NetAccessPointDescriptor apDescriptor =
            new NetAccessPointDescriptor(new TransportAddress("localhost", 5009));

        stunStack.installNetAccessPoint(apDescriptor);

        StunClient stunClient = new StunClient(stunStack);

        // create the Stun Request message
        Request request = MessageFactory.createBindingRequest();

        TransportAddress serverAddress = new TransportAddress("localhost", 4006);

        stunClient.sendStunRequest(request, serverAddress, apDescriptor, stunClient);


    }*/
}
