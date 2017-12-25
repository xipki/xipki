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

package org.xipki.ca.qa.internal;

import java.util.HashSet;
import java.util.Set;

import org.xipki.ca.certprofile.x509.jaxb.IntWithDescType;
import org.xipki.ca.certprofile.x509.jaxb.TlsFeature;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaTlsFeature extends QaExtension {

    private final Set<Integer> features;

    public QaTlsFeature(final TlsFeature jaxb) {
        ParamUtil.requireNonNull("jaxb", jaxb);
        this.features = new HashSet<>();
        for (IntWithDescType m : jaxb.getFeature()) {
            features.add(m.getValue());
        }
    }

    public Set<Integer> features() {
        return features;
    }

}
