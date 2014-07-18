/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.certprofile;

import java.util.ArrayList;
import java.util.List;

import org.xipki.ca.server.certprofile.jaxb.ConditionType;
import org.xipki.ca.server.certprofile.jaxb.EnvParamType;
import org.xipki.ca.server.certprofile.jaxb.OperatorType;
import org.xipki.security.common.EnvironmentParameterResolver;

/**
 * @author Lijun Liao
 */

class Condition
{
    private static class EnvParamConditionEntry
    {
        private final String name;
        private final String value;

        EnvParamConditionEntry(String name, String value)
        {
            this.name = name;
            this.value = value;
        }
    }

    private final OperatorType operator;
    private final List<EnvParamConditionEntry> entries;

    Condition(ConditionType type)
    {
        operator = type.getOperator() == null ? OperatorType.AND : type.getOperator();
        List<EnvParamType> envParams = type.getEnvParam();
        entries = new ArrayList<>(envParams.size());

        for(EnvParamType envParam : envParams)
        {
            entries.add(new EnvParamConditionEntry(envParam.getName(), envParam.getValue()));
        }
    }

    boolean satisfy(EnvironmentParameterResolver pr)
    {
        if(pr == null)
        {
            return false;
        }

        if(operator == OperatorType.OR || operator == null)
        {
            for(EnvParamConditionEntry e : entries)
            {
                String value = pr.getParameterValue(e.name);
                if(value.equalsIgnoreCase(e.value))
                {
                    return true;
                }
            }
            return false;
        }
        else if(operator == OperatorType.AND)
        {
            for(EnvParamConditionEntry e : entries)
            {
                String value = pr.getParameterValue(e.name);
                if(value.equalsIgnoreCase(e.value) == false)
                {
                    return false;
                }
            }
            return true;
        }
        else
        {
            throw new RuntimeException("should not reach here");
        }
    }
}
