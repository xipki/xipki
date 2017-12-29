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

package org.xipki.ca.server.mgmt.api;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ChangeCaEntry {

    private final NameId ident;

    private CaStatus status;

    private CertValidity maxValidity;

    private String signerType;

    private String signerConf;

    private String cmpControlName;

    private String responderName;

    private Boolean duplicateKeyPermitted;

    private Boolean duplicateSubjectPermitted;

    private Boolean saveRequest;

    private ValidityMode validityMode;

    private Integer permission;

    private Integer keepExpiredCertInDays;

    private Integer expirationPeriod;

    private String extraControl;

    public ChangeCaEntry(NameId ident) throws CaMgmtException {
        this.ident = ParamUtil.requireNonNull("ident", ident);
    }

    public NameId ident() {
        return ident;
    }

    public CaStatus status() {
        return status;
    }

    public void setStatus(CaStatus status) {
        this.status = status;
    }

    public CertValidity maxValidity() {
        return maxValidity;
    }

    public void setMaxValidity(CertValidity maxValidity) {
        this.maxValidity = maxValidity;
    }

    public String signerType() {
        return signerType;
    }

    public void setSignerType(String signerType) {
        this.signerType = signerType;
    }

    public String signerConf() {
        return signerConf;
    }

    public void setSignerConf(String signerConf) {
        this.signerConf = signerConf;
    }

    public String cmpControlName() {
        return cmpControlName;
    }

    public void setCmpControlName(String cmpControlName) {
        this.cmpControlName = (cmpControlName == null) ? null : cmpControlName.toUpperCase();
    }

    public String responderName() {
        return responderName;
    }

    public void setResponderName(String responderName) {
        this.responderName = (responderName == null) ? null : responderName.toUpperCase();
    }

    public Boolean duplicateKeyPermitted() {
        return duplicateKeyPermitted;
    }

    public void setDuplicateKeyPermitted(Boolean duplicateKeyPermitted) {
        this.duplicateKeyPermitted = duplicateKeyPermitted;
    }

    public Boolean duplicateSubjectPermitted() {
        return duplicateSubjectPermitted;
    }

    public void setDuplicateSubjectPermitted(Boolean duplicateSubjectPermitted) {
        this.duplicateSubjectPermitted = duplicateSubjectPermitted;
    }

    public ValidityMode validityMode() {
        return validityMode;
    }

    public void setValidityMode(ValidityMode validityMode) {
        this.validityMode = validityMode;
    }

    public Boolean saveRequest() {
        return saveRequest;
    }

    public void setSaveRequest(Boolean saveRequest) {
        this.saveRequest = saveRequest;
    }

    public Integer permission() {
        return permission;
    }

    public void setPermission(Integer permission) {
        this.permission = permission;
    }

    public Integer expirationPeriod() {
        return expirationPeriod;
    }

    public void setExpirationPeriod(Integer expirationPeriod) {
        this.expirationPeriod = expirationPeriod;
    }

    public Integer keepExpiredCertInDays() {
        return keepExpiredCertInDays;
    }

    public void setKeepExpiredCertInDays(Integer days) {
        this.keepExpiredCertInDays = days;
    }

    public String extraControl() {
        return extraControl;
    }

    public void setExtraControl(String extraControl) {
        this.extraControl = extraControl;
    }

}
