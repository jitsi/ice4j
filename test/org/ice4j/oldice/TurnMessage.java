/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package org.ice4j.oldice;

import java.io.*;
import java.net.*;

import java.util.logging.*;

import org.ice4j.*;
import org.ice4j.attribute.*;
import org.ice4j.message.*;
import org.ice4j.stack.*;
import org.ice4j.stunclient.*;


/**
 * Send TURN messages over the network to
 * see if there are well-formated.
 *
 * @author Sebastien Vincent
 * @version 0.1
 */
public class TurnMessage
{
  /**
   * The logger.
   */
  private static final Logger logger = Logger.getLogger(TurnMessage.class.getName());

  /**
   * Entry point of the program.
   * @param argv Number of argument
   */
  public static void main(String argv[]) throws Exception
  {
    Request req = null;
    TransportAddress serverAddress = new TransportAddress("localhost", 3478);
    byte data[] = new byte[] { 'p', 'l', 'o', 'p'};
    byte tran[] = new byte[16];
    
    System.arraycopy(Message.MAGIC_COOKIE, 0, tran, 0, 4);

    req = MessageFactory.createAllocateRequest();
    req.setTransactionID(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12});
    byte msg[] = req.encode();

    DatagramSocket sock = new DatagramSocket();
    DatagramPacket packet = new DatagramPacket(msg, msg.length, serverAddress.getSocketAddress());
    sock.send(packet);

    packet = null;

    req = MessageFactory.createAllocateRequest((byte)17, false, false, false);
    req.setTransactionID(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12});
    msg = req.encode();

    packet = new DatagramPacket(msg, msg.length, serverAddress.getSocketAddress());
    sock.send(packet);

    packet = null;

    MessageFactory.addLongTermAuthentifcationAttribute(req, new String("username").getBytes(), new String("domain.org").getBytes(), new String("dfdsfqsddfsf").getBytes());

    msg = req.encode();
    packet = new DatagramPacket(msg, msg.length, serverAddress.getSocketAddress());
    sock.send(packet);

    req = MessageFactory.createRefreshRequest(89);
    req.setTransactionID(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12});
    MessageFactory.addLongTermAuthentifcationAttribute(req, new String("username").getBytes(), new String("domain.org").getBytes(), new String("dfdsfqsddfsf").getBytes());
    msg = req.encode();
    packet = new DatagramPacket(msg, msg.length, serverAddress.getSocketAddress());
    sock.send(packet);

    req = MessageFactory.createChannelBindRequest((char)89, serverAddress);
    req.setTransactionID(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12});
    MessageFactory.addLongTermAuthentifcationAttribute(req, new String("username").getBytes(), new String("domain.org").getBytes(), new String("dfdsfqsddfsf").getBytes());
    System.arraycopy(req.getTransactionID(), 0, tran, 4, 12);
    PeerAddressAttribute xorMapped = (PeerAddressAttribute)req.getAttribute(Attribute.PEER_ADDRESS);
    xorMapped.setAddress(xorMapped.applyXor(tran));
        
    msg = req.encode();
    packet = new DatagramPacket(msg, msg.length, serverAddress.getSocketAddress());
    sock.send(packet);

    Indication indic = MessageFactory.createSendIndication(serverAddress, data);
    indic.setTransactionID(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12});
    System.arraycopy(req.getTransactionID(), 0, tran, 4, 12);
    xorMapped = (PeerAddressAttribute)indic.getAttribute(Attribute.PEER_ADDRESS);
    xorMapped.setAddress(xorMapped.applyXor(tran));
    msg = indic.encode();
    packet = new DatagramPacket(msg, msg.length, serverAddress.getSocketAddress());
    sock.send(packet);
  }
}

