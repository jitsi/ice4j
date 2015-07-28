/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the SIP Communicator community (http://sip-communicator.org).
 *
 * Distributable under LGPL license. See terms of license at gnu.org.
 */
package org.ice4j.stack;

import java.net.*;
import java.io.IOException;

public class DatagramCollector
    implements Runnable
{
    DatagramPacket receivedPacket = null;
    DatagramSocket sock           = null;

    boolean packetReceived = false;

    public DatagramCollector()
    {
    }

    public void run()
    {
        try
        {

            sock.receive(receivedPacket);

            synchronized (this)
            {
                packetReceived = true;
                notifyAll();
            }

        }
        catch (IOException ex)
        {
            receivedPacket = null;
        }

    }

    public void startListening(DatagramSocket sock)
    {
        this.sock = sock;
        receivedPacket = new DatagramPacket(new byte[4096], 4096);

        new Thread(this).start();
    }

    public void waitForPacket()
    {
        synchronized(this)
        {
            if(packetReceived)
                return;

            try
            {
                wait(50);
            }
            catch (InterruptedException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    public DatagramPacket collectPacket()
    {
        //recycle
        DatagramPacket returnValue = receivedPacket;
        receivedPacket = null;
        sock           = null;
        packetReceived = false;

        //return
        return returnValue;
    }
}
