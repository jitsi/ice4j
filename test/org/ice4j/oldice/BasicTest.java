/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.oldice;

import java.net.*;
import java.io.IOException;
import java.net.SocketAddress;
import java.util.logging.*;

/**
 * <p>Title: Stun4J.</p>
 * <p>Description: Simple Traversal of UDP Through NAT.</p>
 * <p>Copyright: Copyright (c) 2003.</p>
 * <p>Organisation: ULP.</p>
 * @author Emil Ivov
 * @version 0.1
 */
public class BasicTest
{
    private static final Logger logger =
        Logger.getLogger(BasicTest.class.getName());
//    String stunSerAddrStr =  "larry.gloo.net";
/*    String stunSerAddrStr =  "stun01.sipphone.com"; */
    String stunSerAddrStr = "130.79.91.216";
    DatagramSocket sock   =  null;
    private byte[] bindingRequest =
        {
          //STUN Msg Type  |  Msg Length
            0x00, 0x01,      0x00, 0x08,
          // Transaction ID
            0x21, 0x12, (byte)0xA4, 0x42,
            0x05, 0x06,      0x07, 0x08,
            0x09, 0x10,      0x11, 0x12,
            0x13, 0x14,      0x15, 0x16,
          //ATTRIBUTES,
          //Change Request
            0x00, 0x03,      0x00, 0x04,
            0x00, 0x00,      0x00, 0x00
        };

    private byte[] bindingRequest2 = 
    {
          //STUN Msg Type  |  Msg Length
            0x00, 0x01,      0x00, 0x00,
          // Transaction ID
            0x21, 0x12, (byte)0xA4, 0x42,
            0x05, 0x06,      0x07, 0x08,
            0x09, 0x10,      0x11, 0x12,
            0x13, 0x14,      0x15, 0x16,
    };

    private byte[] wrongBindingRequest =
        {
            //STUN Msg Type  |  Msg Length
            0x00, 0x01,      0x00, 0x07,
            // Transaction ID
            0x21, 0x12, (byte)0xA4, 0x42,
            0x05, 0x06,      0x07, 0x08,
            0x09, 0x10,      0x11, 0x12,
            0x13, 0x14,      0x15, 0x16,
            //ATTRIBUTES,
            //Change Request
            0x00, 0x03,      0x00, 0x04,
            0x00, 0x00,      0x00, 0x06
        };


    public BasicTest()
    {
    }

    public void sendBindingRequest()
    {
        try
        {
            SocketAddress stunSerAddr = new InetSocketAddress(stunSerAddrStr, 3478);


            DatagramPacket packet = new DatagramPacket(bindingRequest, 28, stunSerAddr);
            sock = new DatagramSocket();

            sock.send(packet);
        }
        catch (SocketException ex)
        {
            logger.log(Level.WARNING,
                       "Failed to open a socket to " + stunSerAddrStr + ". ",
                       ex );
        }
        catch (IOException ex)
        {
            logger.log(Level.WARNING,
                       "Failed to send the binding request to "
                       + stunSerAddrStr + ". ",
                        ex);
        }
    }

    
    /**
     * Send a Binding Request without attribute to have a response from
     * RFC3489bis STUN server.
     */
    public void sendBindingRequest2()
    {
        try
        {
            SocketAddress stunSerAddr = new InetSocketAddress(stunSerAddrStr, 3478);


            DatagramPacket packet = new DatagramPacket(bindingRequest2, 20, stunSerAddr);
            sock = new DatagramSocket();

            sock.send(packet);
        }
        catch (SocketException ex)
        {
            logger.log(Level.WARNING,
                       "Failed to open a socket to " + stunSerAddrStr + ". ",
                       ex );
        }
        catch (IOException ex)
        {
            logger.log(Level.WARNING,
                       "Failed to send the binding request to "
                       + stunSerAddrStr + ". ",
                        ex);
        }
    }

    public void sendWrongBindingRequest()
    {
        try
        {
            SocketAddress stunSerAddr = new InetSocketAddress(stunSerAddrStr, 3478);


            DatagramPacket packet = new DatagramPacket(wrongBindingRequest, 28, stunSerAddr);
            sock = new DatagramSocket();

            sock.send(packet);
        }
        catch (SocketException ex)
        {
            logger.log(Level.WARNING,
                       "Failed to open a socket to " + stunSerAddrStr +  ". ",
                       ex);
        }
        catch (IOException ex)
        {
            logger.log(Level.WARNING,
                       "Failed to send the binding request to "
                       + stunSerAddrStr + ". ",
                       ex);
        }
    }


    public void receiveBindingResponse()
    {
        byte responseData[] = new byte[512];
        DatagramPacket responsePacket = new DatagramPacket(responseData, 512);
        try
        {
            sock.receive(responsePacket);
        }
        catch (IOException ex)
        {
            System.err.println("Failed to receive a packet! " + ex.getMessage());
        }

        //decode
        //for(int i = 0; i < responsePacket.getLength(); i++)
        //    System.out.print("0x" + byteToHex(responseData[i]) + " ");
        System.out.println("====================== Stun Header =============================");
        System.out.println("STUN Message Type: 0x" + byteToHex(responseData[0]) + byteToHex(responseData[1]));
        System.out.println("Message Length:    0x" + byteToHex(responseData[2]) + byteToHex(responseData[3]));
        System.out.println("Transaction ID:    0x" + byteToHex(responseData[4]) + byteToHex(responseData[5])
                                                   + byteToHex(responseData[6]) + byteToHex(responseData[7])
                                                   + byteToHex(responseData[8]) + byteToHex(responseData[9])
                                                   + byteToHex(responseData[10]) + byteToHex(responseData[11])
                                                   + byteToHex(responseData[12]) + byteToHex(responseData[13])
                                                   + byteToHex(responseData[14]) + byteToHex(responseData[15])
                                                   + byteToHex(responseData[16]) + byteToHex(responseData[17])
                                                   + byteToHex(responseData[18]) + byteToHex(responseData[19])
                                                   );
        System.out.println("====================== Attributes ==============================");
        for (int i = 20; i < responsePacket.getLength(); )
        {
            byte attLen1 = 0;
            byte attLen2 = 0;
            System.out.println("Attribute Type:   0x" + byteToHex(responseData[i++]) + byteToHex(responseData[i++]));
            System.out.println("Attribute Length: 0x" + byteToHex(attLen2=responseData[i++]) + byteToHex(attLen2=responseData[i++]));
            int attLen = (((int)attLen1)<<8) + attLen2;
            for (int j = 0; j < attLen; j++)
            {
                System.out.println("    data["+j+"]="+(responseData[j+i]&0xFF));
            }
            i+=attLen;

            /* must be a multiple of 4 */
            if((attLen % 4) > 0)
            {
              i+= (4 - (attLen % 4));
            }
        }
    }

    private String byteToHex(byte b)
    {
        return (b<0xF?"0":"") + Integer.toHexString(b&0xff).toUpperCase();
    }

    public static void main(String[] args)
    {
        BasicTest basicTest = new BasicTest();
        basicTest.sendBindingRequest();
        basicTest.receiveBindingResponse();
        basicTest.sendBindingRequest2();
        basicTest.receiveBindingResponse();
/*        basicTest.sendWrongBindingRequest();
        basicTest.receiveBindingResponse();
*/
    }

}
