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

import java.util.Set;

import org.xipki.ca.api.profile.KeyUsage;

/**
 * @author Lijun Liao
 */

class KeyUsageOption
{
    private final Condition condition;
    private final Set<KeyUsage> keyusages;

    public KeyUsageOption(Condition condition, Set<KeyUsage> keyusages)
    {
        this.condition = condition;
        this.keyusages = keyusages;
    }

    public Condition getCondition()
    {
        return condition;
    }

    public Set<KeyUsage> getKeyusages()
    {
        return keyusages;
    }

}
