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

import org.xipki.ca.certprofile.x509.jaxb.GeneralSubtreeBaseType;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QaGeneralSubtree {

    private final GeneralSubtreeBaseType jaxb;

    public QaGeneralSubtree(GeneralSubtreeBaseType jaxb) {
        this.jaxb = ParamUtil.requireNonNull("jaxb", jaxb);
        Integer min = jaxb.getMinimum();
        if (min != null) {
            ParamUtil.requireMin("jaxb.getMinimum()", min.intValue(), 0);
        }

        Integer max = jaxb.getMaximum();
        if (max != null) {
            ParamUtil.requireMin("jaxb.getMaximum()", max.intValue(), 0);
        }
    }

    public String rfc822Name() {
        return jaxb.getRfc822Name();
    }

    public String dnsName() {
        return jaxb.getDnsName();
    }

    public String directoryName() {
        return jaxb.getDirectoryName();
    }

    public String uri() {
        return jaxb.getUri();
    }

    public String ipAddress() {
        return jaxb.getIpAddress();
    }

    public Integer minimum() {
        return jaxb.getMinimum();
    }

    public Integer maximum() {
        return jaxb.getMaximum();
    }

}
