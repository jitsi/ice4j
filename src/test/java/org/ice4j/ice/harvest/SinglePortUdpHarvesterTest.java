/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2018 Atlassian Pty Ltd
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
package org.ice4j.ice.harvest;

import static org.junit.jupiter.api.Assertions.*;

import org.ice4j.*;

import java.net.*;
import org.junit.jupiter.api.*;

/**
 * Various tests that verify the functionality provided by {@link SinglePortUdpHarvester}.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class SinglePortUdpHarvesterTest
{
    /**
     * Verifies that, without closing, the address used by a harvester cannot be re-used.
     *
     * @see <a href="https://github.com/jitsi/ice4j/issues/139">https://github.com/jitsi/ice4j/issues/139</a>
     */
    @Test
    public void testRebindWithoutCloseThrows() throws Exception
    {
        // Setup test fixture.
        final TransportAddress address = new TransportAddress( "127.0.0.1", 10000, Transport.UDP );
        SinglePortUdpHarvester firstHarvester;
        try
        {
            firstHarvester = new SinglePortUdpHarvester( address );
        }
        catch (BindException ex)
        {
            // This is not expected at this stage (the port is likely already in use by another process, voiding this
            // test). Rethrow as a different exception than the BindException, that is expected to be thrown later in
            // this test.
            throw new Exception( "Test fixture is invalid.", ex );
        }

        // Execute system under test.
        SinglePortUdpHarvester secondHarvester = null;
        try
        {
            secondHarvester = new SinglePortUdpHarvester( address );
            fail("expected BindException to be thrown at this point");
        }
        catch (BindException ex)
        {
            //expected, do nothing
        }
        finally
        {
            // Tear down
            firstHarvester.close();
            if (secondHarvester != null)
            {
                secondHarvester.close();
            }
        }
    }

    /**
     * Verifies that, after closing, the address used by a harvester can be re-used.
     *
     * @see <a href="https://github.com/jitsi/ice4j/issues/139">https://github.com/jitsi/ice4j/issues/139</a>
     */
    @Test
    public void testRebindWithClose() throws Exception
    {
        // Setup test fixture.
        final TransportAddress address = new TransportAddress( "127.0.0.1", 10001, Transport.UDP );
        final SinglePortUdpHarvester firstHarvester = new SinglePortUdpHarvester( address );
        firstHarvester.close();
        Thread.sleep( 500 ); // give thread time to close/clean up.

        // Execute system under test.
        SinglePortUdpHarvester secondHarvester = null;

        try
        {
            secondHarvester = new SinglePortUdpHarvester( address );
        }

        // Verify results.
        catch ( BindException ex )
        {
            fail( "A bind exception should not have been thrown, as the original harvester was properly closed.");
        }

        // Tear down.
        finally
        {
            if ( secondHarvester != null )
            {
                secondHarvester.close();
            }
        }
    }

    @Test
    public void testBindWithPortZero() throws Exception
    {
        // Setup test fixture.
        final TransportAddress address = new TransportAddress("127.0.0.1", 0, Transport.UDP);
        SinglePortUdpHarvester harvester;
        try
        {
            harvester = new SinglePortUdpHarvester(address);
        }
        catch (BindException ex)
        {
            // This is not expected at this stage.
            // Rethrow as a different exception than the BindException, that is expected to be thrown later in
            // this test.
            throw new Exception("Test fixture is invalid.", ex);
        }

        assertFalse(harvester.localAddress.getPort() == 0,
                "A random port number not equal to zero should have been chosen by the OS");

        // Tear down
        harvester.close();
    }
}
