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

package org.xipki.pki.ca.client.impl;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.pki.ca.client.api.CertprofileInfo;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaConf {

    private final String name;

    private final String url;

    private final String healthUrl;

    private final String requestorName;

    private final CmpResponder responder;

    private X509CmpRequestor requestor;

    private boolean certAutoconf;

    private boolean certprofilesAutoconf;

    private boolean cmpControlAutoconf;

    private X509Certificate cert;

    private X500Name subject;

    private byte[] subjectKeyIdentifier;

    private ClientCmpControl cmpControl;

    private Map<String, CertprofileInfo> profiles = Collections.emptyMap();

    CaConf(final String name, final String url, final String healthUrl, final String requestorName,
            final CmpResponder responder) {
        this.name = ParamUtil.requireNonBlank("name", name);
        this.url = ParamUtil.requireNonBlank("url", url);
        this.requestorName = ParamUtil.requireNonNull("requestorName", requestorName);
        this.responder = ParamUtil.requireNonNull("responder", responder);
        this.healthUrl = StringUtil.isBlank(healthUrl) ? url.replace("cmp", "health") : healthUrl;
    }

    public String name() {
        return name;
    }

    public String url() {
        return url;
    }

    public String healthUrl() {
        return healthUrl;
    }

    public void setCert(final X509Certificate cert) throws CertificateEncodingException {
        this.cert = cert;
        this.subject = (cert == null) ? null
                : X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        this.subjectKeyIdentifier = X509Util.extractSki(cert);
    }

    public void setCertprofiles(final Set<CertprofileInfo> certProfiles) {
        if (profiles == null) {
            this.profiles = Collections.emptyMap();
        } else {
            this.profiles = new HashMap<>();
            for (CertprofileInfo m : certProfiles) {
                this.profiles.put(m.name(), m);
            }
        }
    }

    public X509Certificate cert() {
        return cert;
    }

    public X500Name subject() {
        return subject;
    }

    public Set<String> profileNames() {
        return profiles.keySet();
    }

    public boolean supportsProfile(final String profileName) {
        ParamUtil.requireNonNull("profileName", profileName);
        return profiles.containsKey(profileName.toUpperCase());
    }

    public CertprofileInfo profile(final String profileName) {
        ParamUtil.requireNonNull("profileName", profileName);
        return profiles.get(profileName);
    }

    public boolean isCaInfoConfigured() {
        return cert != null;
    }

    public CmpResponder responder() {
        return responder;
    }

    public boolean isCertAutoconf() {
        return certAutoconf;
    }

    public void setCertAutoconf(final boolean autoconf) {
        this.certAutoconf = autoconf;
    }

    public boolean isCertprofilesAutoconf() {
        return certprofilesAutoconf;
    }

    public void setCertprofilesAutoconf(final boolean autoconf) {
        this.certprofilesAutoconf = autoconf;
    }

    public void setRequestor(final X509CmpRequestor requestor) {
        this.requestor = requestor;
    }

    public String requestorName() {
        return requestorName;
    }

    public X509CmpRequestor requestor() {
        return requestor;
    }

    public void setCmpControlAutoconf(final boolean autoconf) {
        this.cmpControlAutoconf = autoconf;
    }

    public boolean isCmpControlAutoconf() {
        return cmpControlAutoconf;
    }

    public void setCmpControl(final ClientCmpControl cmpControl) {
        this.cmpControl = cmpControl;
    }

    public ClientCmpControl cmpControl() {
        return cmpControl;
    }

    public byte[] subjectKeyIdentifier() {
        return (subjectKeyIdentifier == null) ? null
                : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);
    }

}
