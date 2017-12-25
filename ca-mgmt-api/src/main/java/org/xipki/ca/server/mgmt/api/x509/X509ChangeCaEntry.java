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

package org.xipki.ca.server.mgmt.api.x509;

import java.security.cert.X509Certificate;
import java.util.List;

import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaMgmtException;
import org.xipki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509ChangeCaEntry extends ChangeCaEntry {

    private List<String> crlUris;

    private List<String> deltaCrlUris;

    private List<String> ocspUris;

    private List<String> caCertUris;

    private X509Certificate cert;

    private String crlSignerName;

    private Integer numCrls;

    private Integer serialNoBitLen;

    public X509ChangeCaEntry(final NameId ident) throws CaMgmtException {
        super(ident);
    }

    public Integer serialNoBitLen() {
        return serialNoBitLen;
    }

    public void setSerialNoBitLen(final Integer serialNoBitLen) {
        if (serialNoBitLen != null) {
            ParamUtil.requireRange("serialNoBitLen", serialNoBitLen, 63, 159);
        }
        this.serialNoBitLen = serialNoBitLen;
    }

    public List<String> crlUris() {
        return crlUris;
    }

    public void setCrlUris(final List<String> crlUris) {
        this.crlUris = crlUris;
    }

    public List<String> deltaCrlUris() {
        return deltaCrlUris;
    }

    public void setDeltaCrlUris(final List<String> deltaCrlUris) {
        this.deltaCrlUris = deltaCrlUris;
    }

    public List<String> ocspUris() {
        return ocspUris;
    }

    public void setOcspUris(final List<String> ocspUris) {
        this.ocspUris = ocspUris;
    }

    public List<String> caCertUris() {
        return caCertUris;
    }

    public void setCaCertUris(final List<String> caCertUris) {
        this.caCertUris = caCertUris;
    }

    public X509Certificate cert() {
        return cert;
    }

    public void setCert(final X509Certificate cert) {
        this.cert = cert;
    }

    public String crlSignerName() {
        return crlSignerName;
    }

    public void setCrlSignerName(final String crlSignerName) {
        this.crlSignerName = (crlSignerName == null) ? null : crlSignerName.toUpperCase();
    }

    public Integer numCrls() {
        return numCrls;
    }

    public void setNumCrls(final Integer numCrls) {
        this.numCrls = numCrls;
    }

}
