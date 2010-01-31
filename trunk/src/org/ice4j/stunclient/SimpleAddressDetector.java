/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.stunclient;

import java.io.*;
import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;

/**
 * The class provides basic means of discovering a public IP address. All it
 * does is send a binding request through a specified port and return the
 * mapped address it got back or <tt>null</tt> if there was no reponse.
 *
 * @author Emil Ivov
 */

public class SimpleAddressDetector
{
    /**
     * Our class logger.
     */
    private static final Logger logger
        = Logger.getLogger(SimpleAddressDetector.class.getName());

    /**
     * The stack to use for STUN communication.
     */
    private StunStack stunStack = null;

    /**
     * The provider to send our messages through
     */
    private StunProvider stunProvider = null;

    /**
     * The address of the stun server
     */
    private TransportAddress serverAddress = null;

    /**
     * A utility used to flatten the multi-threaded architecture of the Stack
     * and execute the discovery process in a synchronized manner
     */
    private BlockingRequestSender requestSender = null;

    /**
     * Creates a StunAddressDiscoverer. In order to use it one must start the
     * discoverer.
     * @param serverAddress the address of the server to interrogate.
     */
    public SimpleAddressDetector(TransportAddress serverAddress)
    {
        this.serverAddress = serverAddress;
    }

    /**
     * Returns the server address that this detector is using to run stun
     * queries.
     *
     * @return StunAddress the address of the stun server that we are running
     * stun queries against.
     */
    public TransportAddress getServerAddress()
    {
        return serverAddress;
    }

    /**
     * Shuts down the underlying stack and prepares the object for garbage
     * collection.
     */
    public void shutDown()
    {
        stunStack = null;
        stunProvider = null;
        requestSender = null;
    }

    /**
     * Puts the discoverer into an operational state.
     */
    public void start()
    {
        stunStack = StunStack.getInstance();

        stunProvider = stunStack.getProvider();
    }


    /**
     * Creates a listening point from the following address and attempts to
     * discover how it is mapped so that using inside the application is
     * possible.
     *
     * @param address the [address]:[port] pair where ther request should be
     * sent from.
     *
     * @return a StunAddress object containing the mapped address or null if
     * discovery failed.
     * @throws IOException if <tt>address</tt> is already bound.
     */
    public TransportAddress getMappingFor(TransportAddress address)
        throws IOException
    {
        NetAccessPointDescriptor apDesc = new NetAccessPointDescriptor(address);

        stunStack.installNetAccessPoint(apDesc);

        requestSender = new BlockingRequestSender(stunProvider, apDesc);
        StunMessageEvent evt = null;
        try
        {
            try
            {
                evt = requestSender.sendRequestAndWaitForResponse(
                    MessageFactory.createBindingRequest(), serverAddress);
            }
            catch (StunException ex)
            {
                //a stun exception is thrown if there is a problem with
                //the message. The message here is constructed by ourselves
                //so we don't need to tell the user ... just log and throw
                //a runtime exception
                logger.log(  Level.SEVERE,
                             "Internal Error. Apparently we did not properly "
                              +"construct a message",
                              ex);
            }
        }
        finally
        {
            //free the port to allow the application to use it.
            stunStack.removeNetAccessPoint(apDesc);
        }

        if(evt != null)
        {
            Response res = (Response)evt.getMessage();

            /* in classic STUN, the response contains a MAPPED-ADDRESS */
            MappedAddressAttribute maAtt =
                        (MappedAddressAttribute)
                                res.getAttribute(Attribute.MAPPED_ADDRESS);
            if(maAtt != null)
            {
                return maAtt.getAddress();
            }

            /* in STUN bis, the response contains a XOR-MAPPED-ADDRESS */
            XorMappedAddressAttribute xorAtt = (XorMappedAddressAttribute)res
                .getAttribute(Attribute.XOR_MAPPED_ADDRESS);

            if(xorAtt != null)
            {
              byte xoring[] = new byte[16];

              System.arraycopy(Message.MAGIC_COOKIE, 0,  xoring, 0, 4);
              System.arraycopy(res.getTransactionID(), 0, xoring, 4, 12);

              return xorAtt.applyXor(xoring);
            }
        }

        return null;
    }

    /**
    * Creates a listening point for the specified socket and attempts to
    * discover how its local address is NAT mapped.
    * @param socket the socket whose address needs to be resolved.
    * @return a StunAddress object containing the mapped address or null if
    * discovery failed.
    *
    * @throws IOException if something fails along the way.
    * @throws BindException if we cannot bind the socket.
    */
   public TransportAddress getMappingFor(DatagramSocket socket)
       throws IOException, BindException
   {
        NetAccessPointDescriptor apDesc
            = stunStack.installNetAccessPoint(socket);

        requestSender = new BlockingRequestSender(stunProvider, apDesc);
        StunMessageEvent evt = null;
        try
        {
            evt = requestSender.sendRequestAndWaitForResponse(
                MessageFactory.createBindingRequest(), serverAddress);
        }
        catch(StunException exc)
        {
            //this shouldn't be happening since we are the one that constructed
            //the request, so let's catch it here and not oblige users to handle
            //exception they are not responsible for.
            logger.log(Level.SEVERE, "Internal Error. We apparently "
                       +"constructed a faulty request.", exc);
            return null;
        }
        finally
        {
            stunStack.removeNetAccessPoint(apDesc);
        }

       if(evt != null)
       {
           Response res = (Response)evt.getMessage();

            /* in classic STUN, the response contains a MAPPED-ADDRESS */
            MappedAddressAttribute maAtt =
                        (MappedAddressAttribute)
                                res.getAttribute(Attribute.MAPPED_ADDRESS);
            if(maAtt != null)
            {
                return maAtt.getAddress();
            }

            /* in STUN bis, the response contains a XOR-MAPPED-ADDRESS */
            XorMappedAddressAttribute xorAtt = (XorMappedAddressAttribute)res
                .getAttribute(Attribute.XOR_MAPPED_ADDRESS);
            if(xorAtt != null)
            {
              byte xoring[] = new byte[16];

              System.arraycopy(Message.MAGIC_COOKIE, 0, xoring, 0, 4);
              System.arraycopy(res.getTransactionID(), 0, xoring, 4, 12);

              return xorAtt.applyXor(xoring);
            }
       }

       return null;
   }


    /**
     * Creates a listening point from the specified port and attempts to
     * discover how it is being mapped.
     *
     * @param port the local port where to send the request from.
     * @return a StunAddress object containing the mapped address or null if
     * discovery failed.
     *
     * @throws IOException if the <tt>port</tt> is already bound.
     */
    public TransportAddress getMappingFor(int port)
        throws IOException
    {
        return getMappingFor(new TransportAddress(port));
    }
}
