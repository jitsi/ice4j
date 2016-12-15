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
 * An enumeration of strategies for selecting which candidate pairs to
 * keep alive.
 */
public enum KeepAliveStrategy
{
    /**
     * Only keep alive the selected pair.
     */
    SELECTED_ONLY("selected_only"),

    /**
     * Keep alive the selected pair and any TCP pairs.
     */
    SELECTED_AND_TCP("selected_and_tcp"),

    /**
     * Keep alive all succeeded pairs.
     */
    ALL_SUCCEEDED("all_succeeded");

    private String name;

    KeepAliveStrategy(String name)
    {
        this.name = name;
    }

    /**
     * @return the {@link KeepAliveStrategy} with name equal to the given
     * string, or {@code null} if there is no such strategy.
     * @param string the name of the strategy.
     */
    public static KeepAliveStrategy fromString(String string)
    {
        for (KeepAliveStrategy strategy : KeepAliveStrategy.values())
        {
            if (strategy.name.equals(string))
                return strategy;
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return name;
    }
}
