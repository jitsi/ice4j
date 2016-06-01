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
package test;

import java.io.*;

import org.ice4j.ice.*;

/**
 * A slightly more complicated ICE use sample. The sample would create an
 * agent, make it print its SDP, then wait for a similar SDP to be fed through
 * standard input. Once this happens, we make our agent start checks against the
 * peer described in the SDP we fed through stdin.
 * <p>
 * This sample is easily used in conjunction with another instance of the same
 * sample application or against our {@link IceLite} sample app.
 *
 * @author Emil Ivov
 */
public class IceDistributed
    extends Ice
{
    /**
     * Runs a test application that allocates streams, generates an SDP, dumps
     * it on stdout, waits for a remote peer SDP on stdin, then feeds that
     * to our local agent and starts ICE processing.
     *
     * @param args none currently handled
     * @throws Throwable every now and then.
     */
    public static void main(String[] args) throws Throwable
    {
        Agent localAgent = createAgent(2020);
        localAgent.setNominationStrategy(
                        NominationStrategy.NOMINATE_HIGHEST_PRIO);

        localAgent.addStateChangeListener(new IceProcessingListener());

        //let them fight ... fights forge character.
        localAgent.setControlling(false);
        String localSDP = SdpUtils.createSDPDescription(localAgent);

        //wait a bit so that the logger can stop dumping stuff:
        Thread.sleep(500);

        System.out.println("=================== feed the following"
                        +" to the remote agent ===================");


        System.out.println(localSDP);

        System.out.println("======================================"
                        +"========================================\n");

        String sdp = readSDP();

        startTime = System.currentTimeMillis();
        SdpUtils.parseSDP(localAgent, sdp);

        localAgent.startConnectivityEstablishment();

        //Give processing enough time to finish. We'll System.exit() anyway
        //as soon as localAgent enters a final state.
        Thread.sleep(60000);
    }

    /**
     * Reads an SDP description from the standard input. We expect descriptions
     * provided to this method to be originating from instances of this
     * application running on remote computers.
     *
     * @return whatever we got on stdin (hopefully an SDP description.
     *
     * @throws Throwable if something goes wrong with console reading.
     */
    static String readSDP() throws Throwable
    {
        System.out.println("Paste remote SDP here. Enter an empty "
                        +"line to proceed:");
        System.out.println("(we don't mind the [java] prefix in SDP intput)");
        BufferedReader reader
            = new BufferedReader(new InputStreamReader(System.in));

        StringBuffer buff = new StringBuffer();
        String line;

        while ( (line = reader.readLine()) != null)
        {
            line = line.replace("[java]", "");
            line = line.trim();
            if(line.length() == 0)
                break;

            buff.append(line);
            buff.append("\r\n");
        }

        return buff.toString();
    }
}
