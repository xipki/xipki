/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.pki.ca.server.impl;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.commons.common.InvalidConfException;
import org.xipki.commons.common.ObjectCreationException;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.KeyUsage;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.SignerConf;
import org.xipki.commons.security.api.exception.SecurityException;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.OperationException;
import org.xipki.pki.ca.api.OperationException.ErrorCode;
import org.xipki.pki.ca.server.mgmt.api.CrlControl;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class X509CrlSignerEntryWrapper {

    private X509CrlSignerEntry dbEntry;

    private CrlControl crlControl;

    private ConcurrentContentSigner signer;

    private byte[] subjectKeyIdentifier;

    X509CrlSignerEntryWrapper() {
    }

    public void setDbEntry(
            final X509CrlSignerEntry dbEntry)
    throws InvalidConfException {
        this.dbEntry = dbEntry;
        this.crlControl = new CrlControl(dbEntry.getCrlControl());
    }

    public CrlControl getCrlControl() {
        return crlControl;
    }

    public void initSigner(
            final SecurityFactory securityFactory)
    throws SecurityException, OperationException, InvalidConfException {
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        if (signer != null) {
            return;
        }

        if (dbEntry == null) {
            throw new SecurityException("dbEntry is null");
        }

        if ("CA".equals(dbEntry.getType())) {
            return;
        }

        dbEntry.setConfFaulty(true);

        X509Certificate responderCert = dbEntry.getCertificate();
        try {
            signer = securityFactory.createSigner(dbEntry.getType(),
                    new SignerConf(dbEntry.getConf()), responderCert);
        } catch (ObjectCreationException ex1) {
            throw new SecurityException("signer without certificate is not allowed");
        }

        X509Certificate signerCert = signer.getCertificate();
        if (signerCert == null) {
            throw new SecurityException("signer without certificate is not allowed");
        }

        if (dbEntry.getBase64Cert() == null) {
            dbEntry.setCertificate(signerCert);
        }

        byte[] encodedSkiValue = signerCert.getExtensionValue(
                Extension.subjectKeyIdentifier.getId());
        if (encodedSkiValue == null) {
            throw new OperationException(ErrorCode.INVALID_EXTENSION,
                    "CA certificate does not have required extension SubjectKeyIdentifier");
        }

        ASN1OctetString ski;
        try {
            ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedSkiValue);
        } catch (IOException ex) {
            throw new OperationException(ErrorCode.INVALID_EXTENSION, ex.getMessage());
        }
        this.subjectKeyIdentifier = ski.getOctets();

        if (!X509Util.hasKeyusage(signerCert, KeyUsage.cRLSign)) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "CRL signer does not have keyusage cRLSign");
        }
        dbEntry.setConfFaulty(false);
    } // method initSigner

    public X509CrlSignerEntry getDbEntry() {
        return dbEntry;
    }

    public X509Certificate getCert() {
        if (signer == null) {
            return dbEntry.getCertificate();
        } else {
            return signer.getCertificate();
        }
    }

    public byte[] getSubjectKeyIdentifier() {
        return (subjectKeyIdentifier == null)
                ? null
                : Arrays.clone(subjectKeyIdentifier);
    }

    public ConcurrentContentSigner getSigner() {
        return signer;
    }

}
