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

package org.xipki.ca.client.api.dto;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class RevokeCertRequestEntry extends IssuerSerialEntry {

    private final int reason;

    private final Date invalidityDate;

    private byte[] authorityKeyIdentifier;

    public RevokeCertRequestEntry(final String id, final X509Certificate cert, final int reason,
            final Date invalidityDate) {
        this(id, X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
                cert.getSerialNumber(), reason, invalidityDate);
    }

    public RevokeCertRequestEntry(final String id, final X500Name issuer,
            final BigInteger serialNumber, final int reason, final Date invalidityDate) {
        super(id, issuer, serialNumber);

        if (!(reason >= 0 && reason <= 10 && reason != 7)) {
            throw new IllegalArgumentException("invalid reason: " + reason);
        }

        this.reason = reason;
        this.invalidityDate = invalidityDate;
    }

    public int reason() {
        return reason;
    }

    public Date invalidityDate() {
        return invalidityDate;
    }

    public byte[] authorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    public void setAuthorityKeyIdentifier(final byte[] authorityKeyIdentifier) {
        this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

}
