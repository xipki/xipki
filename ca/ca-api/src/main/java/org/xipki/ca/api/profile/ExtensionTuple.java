/*
 * Copyright 2014 xipki.org
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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.common.ParamChecker;

public class ExtensionTuple {
    private final ASN1ObjectIdentifier type;
    private final boolean critical;
    private final ASN1Encodable value;

    public ExtensionTuple(ASN1ObjectIdentifier type, boolean critical, ASN1Encodable value)
    {
        ParamChecker.assertNotNull("type", type);
        ParamChecker.assertNotNull("value", value);

        this.type = type;
        this.critical = critical;
        this.value = value;
    }

    public ASN1ObjectIdentifier getType() {
        return type;
    }

    public boolean isCritical() {
        return critical;
    }

    public ASN1Encodable getValue() {
        return value;
    }
}
