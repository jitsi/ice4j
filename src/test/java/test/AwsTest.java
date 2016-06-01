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

import java.util.*;
import java.util.logging.*;

import org.ice4j.ice.*;
import org.ice4j.ice.harvest.*;

/**
 * An example of using the AWS Harvester.
 * <p>
 * @author Emil Ivov
 */
public class AwsTest
    extends Ice
{
    /**
     * The <tt>Logger</tt> used by the <tt>TrickleIce</tt>
     * class and its instances for logging output.
     */
    private static final Logger logger
        = Logger.getLogger(TrickleIce.class.getName());

    /**
     * Runs a test application that creates an agent, attaches an AWS harvester
     * as well as a few allocates streams, generates an SDP and dumps
     * it on stdout
     *
     * @param args none currently handled
     * @throws Throwable every now and then.
     */
    public static void main(String[] args) throws Throwable
    {
        if(!AwsCandidateHarvester.smellsLikeAnEC2())
        {
            logger.info("This does not appear to be an EC2 machine");
            return;
        }
        else
        {
            logger.info("Oh nice! Looks like we are on an EC2 machine");

        }
        AwsCandidateHarvester mch = new AwsCandidateHarvester();

        List<CandidateHarvester> harvesters = new ArrayList<>();
        harvesters.add(mch);

        Agent localAgent = createAgent(2020, false, harvesters);
        localAgent.setNominationStrategy(
                        NominationStrategy.NOMINATE_HIGHEST_PRIO);

        String localSDP = SdpUtils.createSDPDescription(localAgent);

        //wait a bit so that the logger can stop dumping stuff:
        Thread.sleep(500);

        logger.info("=================== feed the following"
                    +" to the remote agent ===================");


        logger.info("\n" + localSDP);

        logger.info("======================================"
            + "========================================\n");
    }
}
