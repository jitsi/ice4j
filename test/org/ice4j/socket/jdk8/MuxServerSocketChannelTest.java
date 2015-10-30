package org.ice4j.socket.jdk8;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.ice4j.socket.DatagramPacketFilter;

import junit.framework.TestCase;

/**
 * @author robertoandrade
 */
public class MuxServerSocketChannelTest extends TestCase {

	public void testOpenAndBindReuseWhenBindingToAllInterfacesFirst() throws IOException 
	{
		SocketAddress allInterfaces = new InetSocketAddress("::", 4443);
		SocketAddress oneInterface = new InetSocketAddress("localhost", 4443);
		
		MuxServerSocketChannel channelForAllInterfaces =
				MuxServerSocketChannel.openAndBind(null, allInterfaces, 0, new DatagramPacketFilter()
		        {
		            @Override
		            public boolean accept(DatagramPacket p)
		            {
		                return false;
		            }
		        });
		
		MuxServerSocketChannel channelForOneInterface = 
				MuxServerSocketChannel.openAndBind(null, oneInterface, 0, new DatagramPacketFilter()
		        {
		            @Override
		            public boolean accept(DatagramPacket p)
		            {
		                return false;
		            }
		        });
		
		assertEquals(channelForAllInterfaces.getFDVal(), channelForOneInterface.getFDVal());
	}
}
