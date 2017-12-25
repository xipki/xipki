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

import org.xipki.ca.certprofile.x509.jaxb.InhibitAnyPolicy;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaInhibitAnyPolicy extends QaExtension {

    private final int skipCerts;

    public QaInhibitAnyPolicy(final InhibitAnyPolicy jaxb) {
        ParamUtil.requireNonNull("jaxb", jaxb);
        this.skipCerts = jaxb.getSkipCerts();
    }

    public int skipCerts() {
        return skipCerts;
    }

}
