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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionValues {

    private final Map<ASN1ObjectIdentifier, ExtensionValue> extensions = new HashMap<>();

    public boolean addExtension(ASN1ObjectIdentifier type, boolean critical, ASN1Encodable value) {
        ParamUtil.requireNonNull("type", type);
        ParamUtil.requireNonNull("value", value);

        if (extensions.containsKey(type)) {
            return false;
        }
        extensions.put(type, new ExtensionValue(critical, value));
        return true;
    }

    public boolean addExtension(ASN1ObjectIdentifier type, ExtensionValue value) {
        ParamUtil.requireNonNull("type", type);
        ParamUtil.requireNonNull("value", value);

        if (extensions.containsKey(type)) {
            return false;
        }
        extensions.put(type, value);
        return true;
    }

    public Set<ASN1ObjectIdentifier> extensionTypes() {
        return Collections.unmodifiableSet(extensions.keySet());
    }

    public ExtensionValue getExtensionValue(ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("type", type);
        return extensions.get(type);
    }

    public boolean removeExtensionTuple(ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("type", type);
        return extensions.remove(type) != null;
    }

    public boolean containsExtension(ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("type", type);
        return extensions.containsKey(type);
    }

}
