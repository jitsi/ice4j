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
package org.ice4j.ice;


/**
 * Contains the nomination strategies currently supported by this
 * implementation's {@link DefaultNominator} class. Applications can either
 * pick one of these strategies or select <tt>NONE</tt> in case they want to
 * handle nominations themselves.
 * <p>
 * Note that NominationStrategies are an ice4j concept and they are not
 * mentioned in RFC 5245.
 *
 * @author Emil Ivov
 */
public enum NominationStrategy
{
    /**
     * Indicates that ice4j's nominator should nominate valid pairs and that
     * the application will be handling this.
     */
    NONE("None"),

    /**
     * The strategy consists in nominating the first candidate pair that's
     * confirmed as valid.
     */
    NOMINATE_FIRST_VALID("NominateFirstValid"),

    /**
     * The strategy consists in nominating the highest priority valid pair.
     * Once a pair is validated, if no higher-priority pairs remain outstanding,
     * it is nominated; otherwise, a timer is armed, and if higher-priority
     * pairs are still outstanding after the timeout, the highest-priority validated
     * pair is nominated.
     */
    NOMINATE_HIGHEST_PRIO("NominateHighestPriority"),

    /**
     * The strategy consists in nominating the first host or server reflexive
     * that's confirmed as valid pair. When a relayed candidate pair is
     * validated first, a timer is armed and only if no host or server
     * reflexive pair gets validated prior to timeout, the relayed ones
     * gets nominated.
     */
    NOMINATE_FIRST_HOST_OR_REFLEXIVE_VALID("NominateFirstHostOrReflexiveValid"),

    /**
     * The strategy consists in nominating the pair that showed the best
     * shortest round trip time once all checks in a list completed.
     */
    NOMINATE_BEST_RTT("NominateBestRTT");

    /**
     * The name of this strategy.
     */
    private final String strategyName;

    /**
     * Creates a <tt>NominationStrategy</tt> instance with the specified name.
     *
     * @param name the name of the <tt>NominationStrategy</tt> that we'd like
     * to create.
     */
    private NominationStrategy(String name)
    {
        this.strategyName = name;
    }

    /**
     * Returns the name of this <tt>NominationStrategy</tt>.
     *
     * @return the name of this <tt>NominationStrategy</tt>.
     */
    @Override
    public String toString()
    {
        return strategyName;
    }

    /**
     * @return the {@link NominationStrategy} with name equal to the given
     * string, or {@code null} if there is no such strategy.
     * @param string the name of the strategy.
     */
    public static NominationStrategy fromString(String string)
    {
        for (NominationStrategy strategy : NominationStrategy.values())
        {
            if (strategy.strategyName.equals(string))
                return strategy;
        }
        return null;
    }
}
