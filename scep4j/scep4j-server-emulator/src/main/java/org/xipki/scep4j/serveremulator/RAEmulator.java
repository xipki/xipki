/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.serveremulator;

import java.security.PrivateKey;

import org.bouncycastle.asn1.x509.Certificate;

/**
 * @author Lijun Liao
 */

public class RAEmulator
{
    private final PrivateKey rAKey;
    private final Certificate rACert;

    public RAEmulator(
            final PrivateKey rAKey,
            final Certificate rACert)
    {
        this.rAKey = rAKey;
        this.rACert = rACert;
    }

    public PrivateKey getRAKey()
    {
        return rAKey;
    }

    public Certificate getRACert()
    {
        return rACert;
    }

}
