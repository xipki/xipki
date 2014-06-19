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

package org.xipki.ca.api.profile;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Lijun Liao
 */

public abstract class AbstractCACertProfile extends AbstractCertProfile
{
    protected Set<KeyUsage> keyUsages;

    public AbstractCACertProfile()
    {
        Set<KeyUsage> keyUsages = new HashSet<>();
        keyUsages.add(KeyUsage.keyCertSign);
        keyUsages.add(KeyUsage.cRLSign);
        this.keyUsages = Collections.unmodifiableSet(keyUsages);
    }

    @Override
    protected boolean isCa()
    {
        return true;
    }

    @Override
    protected Set<KeyUsage> getKeyUsage()
    {
        return keyUsages;
    }

    @Override
    public ExtensionOccurrence getOccurenceOfAuthorityKeyIdentifier()
    {
        return ExtensionOccurrence.NONCRITICAL_REQUIRED;
    }

}
