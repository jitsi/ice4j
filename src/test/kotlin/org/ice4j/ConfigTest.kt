/*
 * Copyright @ 2020 - present 8x8, Inc.
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

package org.ice4j

import io.kotest.core.spec.IsolationMode
import io.kotest.core.spec.Spec
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.extensions.system.withSystemProperties
import org.jitsi.config.withNewConfig
import org.jitsi.metaconfig.MetaconfigSettings

/**
 * A helper class for testing configuration properties
 */
abstract class ConfigTest : ShouldSpec() {
    override fun isolationMode(): IsolationMode? = IsolationMode.InstancePerLeaf

    override suspend fun beforeSpec(spec: Spec) {
        super.beforeSpec(spec)
        MetaconfigSettings.cacheEnabled = false
    }

    inline fun withNewConfig(config: String, block: () -> Unit) {
        withNewConfig(config, "new-${this::class.simpleName}", true, block)
    }

    fun withLegacyConfig(config: Map<String, String?>, block: () -> Unit) = withSystemProperties(config) { block }
}
