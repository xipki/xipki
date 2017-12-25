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

package org.xipki.ca.server.impl;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.server.mgmt.api.x509.CrlControl;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.common.InvalidConfException;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.KeyUsage;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.X509Util;

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

    public void setDbEntry(final X509CrlSignerEntry dbEntry) throws InvalidConfException {
        this.dbEntry = dbEntry;
        this.crlControl = new CrlControl(dbEntry.crlControl());
    }

    public CrlControl crlControl() {
        return crlControl;
    }

    public void initSigner(final SecurityFactory securityFactory)
            throws XiSecurityException, OperationException, InvalidConfException {
        ParamUtil.requireNonNull("securityFactory", securityFactory);
        if (signer != null) {
            return;
        }

        if (dbEntry == null) {
            throw new XiSecurityException("dbEntry is null");
        }

        if ("CA".equals(dbEntry.type())) {
            return;
        }

        dbEntry.setConfFaulty(true);

        X509Certificate responderCert = dbEntry.certificate();
        try {
            signer = securityFactory.createSigner(dbEntry.type(),
                    new SignerConf(dbEntry.conf()), responderCert);
        } catch (ObjectCreationException ex1) {
            throw new XiSecurityException("signer without certificate is not allowed");
        }

        X509Certificate signerCert = signer.getCertificate();
        if (signerCert == null) {
            throw new XiSecurityException("signer without certificate is not allowed");
        }

        if (dbEntry.base64Cert() == null) {
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
            throw new OperationException(ErrorCode.INVALID_EXTENSION, ex);
        }
        this.subjectKeyIdentifier = ski.getOctets();

        if (!X509Util.hasKeyusage(signerCert, KeyUsage.cRLSign)) {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "CRL signer does not have keyusage cRLSign");
        }
        dbEntry.setConfFaulty(false);
    } // method initSigner

    public X509CrlSignerEntry dbEntry() {
        return dbEntry;
    }

    public X509Certificate cert() {
        return (signer == null) ? dbEntry.certificate() : signer.getCertificate();
    }

    public byte[] subjectKeyIdentifier() {
        return (subjectKeyIdentifier == null) ? null
                : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);
    }

    public ConcurrentContentSigner signer() {
        return signer;
    }

}
