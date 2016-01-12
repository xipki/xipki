/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.client.impl;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.pki.ca.client.api.CertprofileInfo;

/**
 * @author Lijun Liao
 */

class CAConf {

    private final String name;

    private final String url;

    private final String healthUrl;

    private final String requestorName;

    private X509CmpRequestor requestor;

    private boolean certAutoconf;

    private boolean certprofilesAutoconf;

    private X509Certificate cert;

    private final X509Certificate responder;

    private X500Name subject;

    private Map<String, CertprofileInfo> profiles = Collections.emptyMap();

    CAConf(
            final String name,
            final String url,
            final String healthUrl,
            final String requestorName,
            final X509Certificate responder) {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotBlank("url", url);
        ParamUtil.assertNotNull("requestorName", requestorName);
        ParamUtil.assertNotNull("responder", responder);

        this.name = name;
        this.url = url;
        this.requestorName = requestorName;
        this.responder = responder;
        if (StringUtil.isBlank(healthUrl)) {
            this.healthUrl = url.replace("cmp", "health");
        } else {
            this.healthUrl = healthUrl;
        }
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public String getHealthUrl() {
        return healthUrl;
    }

    public void setCert(
            final X509Certificate cert) {
        this.cert = cert;
        if (cert != null) {
            this.subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        } else {
            this.subject = null;
        }
    }

    public void setCertprofiles(
            final Set<CertprofileInfo> profiles) {
        if (profiles == null) {
            this.profiles = Collections.emptyMap();
        } else {
            this.profiles = new HashMap<>();
            for (CertprofileInfo m : profiles) {
                this.profiles.put(m.getName(), m);
            }
        }
    }

    public X509Certificate getCert() {
        return cert;
    }

    public X500Name getSubject() {
        return subject;
    }

    public Set<String> getProfileNames() {
        return profiles.keySet();
    }

    public boolean supportsProfile(
            final String profileName) {
        return profiles.containsKey(profileName);
    }

    public CertprofileInfo getProfile(
            final String profileName) {
        return profiles.get(profileName);
    }

    public boolean isCAInfoConfigured() {
        return cert != null;
    }

    public X509Certificate getResponder() {
        return responder;
    }

    public boolean isCertAutoconf() {
        return certAutoconf;
    }

    public void setCertAutoconf(
            final boolean autoconf) {
        this.certAutoconf = autoconf;
    }

    public boolean isCertprofilesAutoconf() {
        return certprofilesAutoconf;
    }

    public void setCertprofilesAutoconf(
            final boolean autoconf) {
        this.certprofilesAutoconf = autoconf;
    }

    public void setRequestor(
            final X509CmpRequestor requestor) {
        this.requestor = requestor;
    }

    public String getRequestorName() {
        return requestorName;
    }

    public X509CmpRequestor getRequestor() {
        return requestor;
    }

}
