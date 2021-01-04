package org.ice4j.socket.jdk8;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.junit.jupiter.api.*;

public class MuxServerSocketChannelTest
{
    @Disabled
    @Test
    void testOpenAndBindReuseWhenBindingToAllInterfacesFirst()
        throws IOException
    {
        SocketAddress allInterfaces = new InetSocketAddress("::", 4443);
        SocketAddress oneInterface = new InetSocketAddress("localhost", 4443);

        MuxServerSocketChannel channelForAllInterfaces =
            MuxServerSocketChannel
                .openAndBind(null, allInterfaces, 0, p -> false);

        MuxServerSocketChannel channelForOneInterface =
            MuxServerSocketChannel
                .openAndBind(null, oneInterface, 0, p -> false);

        assertEquals(channelForAllInterfaces.getFDVal(),
            channelForOneInterface.getFDVal());
    }
}
