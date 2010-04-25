/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.ice;

import java.net.*;
import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.message.*;
import org.ice4j.socket.*;
import org.ice4j.stack.*;

/**
 * @author Emil Ivov
 */
public class ConnectivityCheckClient
    implements ResponseCollector
{
    /**
     * The <tt>Logger</tt> used by the <tt>ConnectivityCheckClient</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger = Logger
                    .getLogger(ConnectivityCheckClient.class.getName());

    /**
     * The <tt>DatagramPacketFilter</tt> that only accepts STUN messages.
     */
    private DatagramPacketFilter stunDatagramPacketFilter;

    private final CheckList checkList;

    public ConnectivityCheckClient(CheckList list)
    {
        this.checkList = list;
    }

    public void startChecks()
    {
        for(CandidatePair pair : checkList)
        {
            startCheckForPair(pair);
        }
    }

    private void startCheckForPair(CandidatePair pair)
    {
        //we don't need to do a canReach() verification here as it has been
        //already verified during the gathering process.
        DatagramSocket stunSocket = ((HostCandidate)pair.getLocalCandidate())
            .getStunSocket(pair.getRemoteCandidate().getTransportAddress());

        StunStack.getInstance().addSocket(stunSocket);

        Request request = MessageFactory.createBindingRequest();

        TransactionID tran;

        try
        {
            tran = StunStack.getInstance().sendRequest(
                    request, pair.getRemoteCandidate().getTransportAddress(),
                    stunSocket,
                    this);
        }
        catch (Exception exception)
        {
            logger.log(
                    Level.INFO,
                    "Failed to send " + request + " through "
                        + stunSocket.getLocalSocketAddress(),
                    exception);
            return;
        }
    }

    public void processResponse(StunMessageEvent response)
    {
        System.out.println("stun response=" + response);
    }

    public void processTimeout(StunTimeoutEvent event)
    {
        System.out.println("timeout event=" + event);
    }

    public void processUnreachable(StunFailureEvent event)
    {
        System.out.println("failure event=" + event);

    }
}
