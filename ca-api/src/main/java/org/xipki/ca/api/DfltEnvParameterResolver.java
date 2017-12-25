/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.api;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DfltEnvParameterResolver implements EnvParameterResolver {

    private final Map<String, String> envParameters = new ConcurrentHashMap<>();

    public DfltEnvParameterResolver() {
    }

    @Override
    public String parameter(final String parameterName) {
        ParamUtil.requireNonNull("parameterName", parameterName);
        return envParameters.get(parameterName);
    }

    @Override
    public Set<String> allParameterNames() {
        return envParameters.keySet();
    }

    public void addParameter(final String name, final String value) {
        ParamUtil.requireNonNull("name", name);
        envParameters.put(name, value);
    }

    public String removeParamater(final String name) {
        ParamUtil.requireNonNull("name", name);
        return envParameters.remove(name);
    }

    public void clear() {
        envParameters.clear();
    }

}
