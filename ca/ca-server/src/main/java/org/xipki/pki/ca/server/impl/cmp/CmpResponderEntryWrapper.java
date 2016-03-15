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

package org.xipki.pki.ca.server.impl.cmp;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.XiSecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpResponderEntryWrapper {

    private CmpResponderEntry dbEntry;

    private ConcurrentContentSigner signer;

    private X500Name subjectAsX500Name;

    private GeneralName subjectAsGeneralName;

    public CmpResponderEntryWrapper() {
    }

    public void setDbEntry(
            final CmpResponderEntry dbEntry) {
        this.dbEntry = ParamUtil.requireNonNull("dbEntry", dbEntry);
        signer = null;
        if (dbEntry.getCertificate() != null) {
            subjectAsX500Name = X500Name.getInstance(
                    dbEntry.getCertificate().getSubjectX500Principal().getEncoded());
            subjectAsGeneralName = new GeneralName(subjectAsX500Name);
        }
    }

    public ConcurrentContentSigner getSigner() {
        return signer;
    }

    public void initSigner(
            final SecurityFactory securityFactory)
    throws XiSecurityException {
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        if (signer != null) {
            return;
        }

        if (dbEntry == null) {
            throw new XiSecurityException("dbEntry is null");
        }

        X509Certificate responderCert = dbEntry.getCertificate();
        dbEntry.setConfFaulty(true);
        signer = securityFactory.createSigner(
                dbEntry.getType(), dbEntry.getConf(), responderCert);
        if (signer.getCertificate() == null) {
            throw new XiSecurityException("signer without certificate is not allowed");
        }
        dbEntry.setConfFaulty(false);

        if (dbEntry.getBase64Cert() == null) {
            dbEntry.setCertificate(signer.getCertificate());
            subjectAsX500Name = X500Name.getInstance(
                    signer.getCertificateAsBcObject().getSubject());
            subjectAsGeneralName = new GeneralName(subjectAsX500Name);
        }
    } // method initSigner

    public CmpResponderEntry getDbEntry() {
        return dbEntry;
    }

    public boolean isHealthy() {
        return (signer == null)
                ? false
                : signer.isHealthy();
    }

    public GeneralName getSubjectAsGeneralName() {
        return subjectAsGeneralName;
    }

    public X500Name getSubjectAsX500Name() {
        return subjectAsX500Name;
    }

}
