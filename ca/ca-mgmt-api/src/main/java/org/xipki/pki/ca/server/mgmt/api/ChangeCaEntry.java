/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.mgmt.api;

import java.io.Serializable;
import java.util.Set;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.ca.api.profile.CertValidity;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ChangeCaEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;

    private CaStatus status;

    private CertValidity maxValidity;

    private String signerType;

    private String signerConf;

    private String cmpControlName;

    private String responderName;

    private Boolean duplicateKeyPermitted;

    private Boolean duplicateSubjectPermitted;

    private ValidityMode validityMode;

    private Set<Permission> permissions;

    private Integer keepExpiredCertInDays;

    private Integer expirationPeriod;

    public ChangeCaEntry(
            final String name)
    throws CaMgmtException {
        ParamUtil.assertNotBlank("name", name);
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public CaStatus getStatus() {
        return status;
    }

    public void setStatus(
            final CaStatus status) {
        this.status = status;
    }

    public CertValidity getMaxValidity() {
        return maxValidity;
    }

    public void setMaxValidity(
            final CertValidity maxValidity) {
        this.maxValidity = maxValidity;
    }

    public String getSignerType() {
        return signerType;
    }

    public void setSignerType(
            final String signerType) {
        this.signerType = signerType;
    }

    public String getSignerConf() {
        return signerConf;
    }

    public void setSignerConf(
            final String signerConf) {
        this.signerConf = signerConf;
    }

    public String getCmpControlName() {
        return cmpControlName;
    }

    public void setCmpControlName(
            final String cmpControlName) {
        this.cmpControlName = cmpControlName;
    }

    public String getResponderName() {
        return responderName;
    }

    public void setResponderName(
            final String responderName) {
        this.responderName = responderName;
    }

    public Boolean getDuplicateKeyPermitted() {
        return duplicateKeyPermitted;
    }

    public void setDuplicateKeyPermitted(
            final Boolean duplicateKeyPermitted) {
        this.duplicateKeyPermitted = duplicateKeyPermitted;
    }

    public Boolean getDuplicateSubjectPermitted() {
        return duplicateSubjectPermitted;
    }

    public void setDuplicateSubjectPermitted(
            final Boolean duplicateSubjectPermitted) {
        this.duplicateSubjectPermitted = duplicateSubjectPermitted;
    }

    public ValidityMode getValidityMode() {
        return validityMode;
    }

    public void setValidityMode(
            final ValidityMode validityMode) {
        this.validityMode = validityMode;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(
            final Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Integer getExpirationPeriod() {
        return expirationPeriod;
    }

    public void setExpirationPeriod(
            final Integer expirationPeriod) {
        this.expirationPeriod = expirationPeriod;
    }

    public Integer getKeepExpiredCertInDays() {
        return keepExpiredCertInDays;
    }

    public void setKeepExpiredCertInDays(
            final Integer days) {
        this.keepExpiredCertInDays = days;
    }

}
