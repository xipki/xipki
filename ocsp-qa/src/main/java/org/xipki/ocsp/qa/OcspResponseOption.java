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

package org.xipki.ocsp.qa;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.common.util.StringUtil;
import org.xipki.security.util.AlgorithmUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspResponseOption {

    private X509Certificate respIssuer;

    private Occurrence nonceOccurrence;

    private Occurrence certhashOccurrence;

    private Occurrence nextUpdateOccurrence;

    private ASN1ObjectIdentifier certhashAlgId;

    private String signatureAlgName;

    public OcspResponseOption() {
    }

    public X509Certificate respIssuer() {
        return respIssuer;
    }

    public void setRespIssuer(final X509Certificate respIssuer) {
        this.respIssuer = respIssuer;
    }

    public Occurrence nonceOccurrence() {
        return nonceOccurrence;
    }

    public void setNonceOccurrence(final Occurrence nonceOccurrence) {
        this.nonceOccurrence = nonceOccurrence;
    }

    public Occurrence certhashOccurrence() {
        return certhashOccurrence;
    }

    public void setCerthashOccurrence(final Occurrence certhashOccurrence) {
        this.certhashOccurrence = certhashOccurrence;
    }

    public Occurrence nextUpdateOccurrence() {
        return nextUpdateOccurrence;
    }

    public void setNextUpdateOccurrence(final Occurrence nextUpdateOccurrence) {
        this.nextUpdateOccurrence = nextUpdateOccurrence;
    }

    public ASN1ObjectIdentifier certhashAlgId() {
        return certhashAlgId;
    }

    public void setCerthashAlgId(final ASN1ObjectIdentifier certhashAlgId) {
        this.certhashAlgId = certhashAlgId;
    }

    public String signatureAlgName() {
        return signatureAlgName;
    }

    public void setSignatureAlgName(final String signatureAlgName) throws NoSuchAlgorithmException {
        this.signatureAlgName = StringUtil.isBlank(signatureAlgName) ? null
                : AlgorithmUtil.canonicalizeSignatureAlgo(signatureAlgName);
    }

}
