/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ca.server.mgmt.api.x509;

import java.util.Set;

import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.NameId;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ChangeScepEntry {

    private final String name;

    private NameId caIdent;

    private Boolean active;

    private String responderType;

    private String responderConf;

    private String base64Cert;

    private Set<String> certProfiles;

    private String control;

    public ChangeScepEntry(final String name) {
        this.name = ParamUtil.requireNonBlank("name", name).toUpperCase();
    }

    public String name() {
        return name;
    }

    public void setCa(final NameId caIdent) {
        this.caIdent = caIdent;
    }

    public NameId caIdent() {
        return caIdent;
    }

    public Boolean isActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public String responderType() {
        return responderType;
    }

    public void setResponderType(final String responderType) {
        this.responderType = responderType;
    }

    public String responderConf() {
        return responderConf;
    }

    public void setResponderConf(final String responderConf) {
        this.responderConf = responderConf;
    }

    public String base64Cert() {
        return base64Cert;
    }

    public void setBase64Cert(final String base64Cert) {
        this.base64Cert = base64Cert;
    }

    public Set<String> certProfiles() {
        return certProfiles;
    }

    public void setCertProfiles(Set<String> certProfiles) {
        if (certProfiles == null) {
            this.certProfiles = null;
        } else {
            this.certProfiles = CollectionUtil.unmodifiableSet(
                    CollectionUtil.toUpperCaseSet(certProfiles));
        }
    }

    public String control() {
        return control;
    }

    public void setControl(final String control) {
        this.control = control;
    }

}
