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

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionValue {

    private final boolean critical;

    private final ASN1Encodable value;

    public ExtensionValue(boolean critical, ASN1Encodable value) {
        this.critical = critical;
        this.value = ParamUtil.requireNonNull("value", value);
    }

    public boolean isCritical() {
        return critical;
    }

    public ASN1Encodable value() {
        return value;
    }

}
