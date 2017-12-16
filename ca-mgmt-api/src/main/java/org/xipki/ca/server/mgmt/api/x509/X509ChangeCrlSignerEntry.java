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

package org.xipki.ca.server.mgmt.api.x509;

import org.xipki.common.InvalidConfException;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509ChangeCrlSignerEntry {

    private final String name;

    private String signerType;

    private String signerConf;

    private String base64Cert;

    private String crlControl;

    public X509ChangeCrlSignerEntry(final String name) throws InvalidConfException {
        this.name = ParamUtil.requireNonBlank("name", name).toUpperCase();
    }

    public String name() {
        return name;
    }

    public String signerType() {
        return signerType;
    }

    public void setSignerType(final String signerType) {
        this.signerType = signerType;
    }

    public String signerConf() {
        return signerConf;
    }

    public void setSignerConf(final String signerConf) {
        this.signerConf = signerConf;
    }

    public String base64Cert() {
        return base64Cert;
    }

    public void setBase64Cert(final String base64Cert) {
        this.base64Cert = base64Cert;
    }

    public String crlControl() {
        return crlControl;
    }

    public void setCrlControl(final String crlControl) {
        this.crlControl = crlControl;
    }

}
