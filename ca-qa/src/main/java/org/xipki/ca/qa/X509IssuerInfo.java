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

package org.xipki.ca.qa;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509IssuerInfo {

    private final Set<String> caIssuerUrls;

    private final Set<String> ocspUrls;

    private final Set<String> crlUrls;

    private final Set<String> deltaCrlUrls;

    private final X509Certificate cert;

    private final Certificate bcCert;

    private final boolean cutoffNotAfter;

    private final Date caNotBefore;

    private final Date caNotAfter;

    private final byte[] ski;

    public X509IssuerInfo(List<String> caIssuerUrls, List<String> ocspUrls, List<String> crlUrls,
            List<String> deltaCrlUrls, byte[] certBytes, boolean cutoffNotAfter)
            throws CertificateException {
        ParamUtil.requireNonNull("certBytes", certBytes);

        this.cutoffNotAfter = cutoffNotAfter;

        if (CollectionUtil.isEmpty(caIssuerUrls)) {
            this.caIssuerUrls = null;
        } else {
            Set<String> set = new HashSet<>();
            set.addAll(caIssuerUrls);
            this.caIssuerUrls = Collections.unmodifiableSet(set);
        }

        if (CollectionUtil.isEmpty(ocspUrls)) {
            this.ocspUrls = null;
        } else {
            Set<String> set = new HashSet<>();
            set.addAll(ocspUrls);
            this.ocspUrls = Collections.unmodifiableSet(set);
        }

        if (CollectionUtil.isEmpty(crlUrls)) {
            this.crlUrls = null;
        } else {
            Set<String> set = new HashSet<>();
            set.addAll(crlUrls);
            this.crlUrls = Collections.unmodifiableSet(set);
        }

        if (CollectionUtil.isEmpty(deltaCrlUrls)) {
            this.deltaCrlUrls = null;
        } else {
            Set<String> set = new HashSet<>();
            set.addAll(deltaCrlUrls);
            this.deltaCrlUrls = Collections.unmodifiableSet(set);
        }

        this.cert = X509Util.parseCert(certBytes);
        this.bcCert = Certificate.getInstance(certBytes);
        this.ski = X509Util.extractSki(cert);
        this.caNotBefore = this.cert.getNotBefore();
        this.caNotAfter = this.cert.getNotAfter();
    } // constructor

    public Set<String> caIssuerUrls() {
        return caIssuerUrls;
    }

    public Set<String> ocspUrls() {
        return ocspUrls;
    }

    public Set<String> crlUrls() {
        return crlUrls;
    }

    public Set<String> deltaCrlUrls() {
        return deltaCrlUrls;
    }

    public X509Certificate cert() {
        return cert;
    }

    public byte[] subjectKeyIdentifier() {
        return Arrays.copyOf(ski, ski.length);
    }

    public Certificate bcCert() {
        return bcCert;
    }

    public boolean isCutoffNotAfter() {
        return cutoffNotAfter;
    }

    public Date caNotBefore() {
        return caNotBefore;
    }

    public Date caNotAfter() {
        return caNotAfter;
    }

}
