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
            // The 'receive' method synchronized the packet, hence the 'getData()' (also synchronized) will block
            // on this anyway even after 'waitForPacket' and 'collectPacket' calls.
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
