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

import java.util.Collections;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class GeneralNameMode {

    private final GeneralNameTag tag;

    // not applied to all tags, currently only for tag otherName
    private final Set<ASN1ObjectIdentifier> allowedTypes;

    public GeneralNameMode(final GeneralNameTag tag) {
        this.tag = ParamUtil.requireNonNull("tag", tag);
        this.allowedTypes = null;
    }

    public GeneralNameMode(final GeneralNameTag tag, final Set<ASN1ObjectIdentifier> allowedTypes) {
        this.tag = ParamUtil.requireNonNull("tag", tag);
        this.allowedTypes = CollectionUtil.isEmpty(allowedTypes) ? Collections.emptySet()
                : CollectionUtil.unmodifiableSet(allowedTypes);
    }

    public GeneralNameTag tag() {
        return tag;
    }

    public Set<ASN1ObjectIdentifier> allowedTypes() {
        return allowedTypes;
    }

}
