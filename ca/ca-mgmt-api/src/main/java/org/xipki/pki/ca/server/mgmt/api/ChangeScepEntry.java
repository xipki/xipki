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

import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ChangeScepEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String caName;

    private String responderType;

    private String responderConf;

    private String base64Cert;

    private String control;

    public ChangeScepEntry(
            final String caName)
    throws InvalidConfException {
        ParamUtil.assertNotBlank("caName", caName);
        this.caName = caName.toUpperCase();
    }

    public String getCaName() {
        return caName;
    }

    public String getResponderType() {
        return responderType;
    }

    public void setResponderType(
            final String responderType) {
        this.responderType = responderType;
    }

    public String getResponderConf() {
        return responderConf;
    }

    public void setResponderConf(
            final String responderConf) {
        this.responderConf = responderConf;
    }

    public String getBase64Cert() {
        return base64Cert;
    }

    public void setBase64Cert(
            final String base64Cert) {
        this.base64Cert = base64Cert;
    }

    public String getControl() {
        return control;
    }

    public void setControl(
            final String control) {
        this.control = control;
    }

}
