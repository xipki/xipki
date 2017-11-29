/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.client.api;

import org.bouncycastle.asn1.crmf.CertId;
import org.xipki.cmp.PkiStatusInfo;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CertIdOrError {

    private final CertId certId;

    private final PkiStatusInfo error;

    public CertIdOrError(final CertId certId) {
        this.certId = ParamUtil.requireNonNull("certId", certId);
        this.error = null;
    }

    public CertIdOrError(final PkiStatusInfo error) {
        this.certId = null;
        this.error = ParamUtil.requireNonNull("error", error);
    }

    public CertId certId() {
        return certId;
    }

    public PkiStatusInfo error() {
        return error;
    }

}
