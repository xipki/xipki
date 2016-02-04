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

package org.xipki.commons.security;

import java.security.Principal;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HttpsHostnameVerifier implements HostnameVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(HttpsHostnameVerifier.class);

    private boolean enabled = false;

    private boolean trustAll = false;

    private Map<String, Set<String>> hostnameMap = new ConcurrentHashMap<>();

    private HostnameVerifier oldHostnameVerifier = null;

    private boolean meAsDefaultHostnameVerifier = false;

    public void init() {
        LOG.info("enabled: {}", enabled);
        LOG.info("trustAll: {}", trustAll);
        if (enabled) {
            oldHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
            LOG.info("Register me as DefaulHostnameVerifier, and backup the old one {}",
                    oldHostnameVerifier);
            HttpsURLConnection.setDefaultHostnameVerifier(this);
            meAsDefaultHostnameVerifier = true;
        }
    }

    public void shutdown() {
        if (meAsDefaultHostnameVerifier
                && HttpsURLConnection.getDefaultHostnameVerifier() == this) {
            LOG.info("Unregister me as DefaultHostnameVerifier, and reuse the old one {}",
                    oldHostnameVerifier);
            HttpsURLConnection.setDefaultHostnameVerifier(oldHostnameVerifier);
            meAsDefaultHostnameVerifier = false;
        }
    }

    /**
     * Verify that the host name is an acceptable match with
     * the server's authentication scheme.
     *
     * @param hostname the host name
     * @param session SSLSession used on the connection to host
     * @return true if the host name is acceptable
     */
    @Override
    public boolean verify(
            final String hostname,
            final SSLSession session) {
        if (trustAll) {
            return true;
        }

        LOG.info("hostname: {}", hostname);
        String commonName = null;
        try {
            Principal peerPrincipal = session.getPeerPrincipal();
            if (peerPrincipal == null) {
                return false;
            }
            commonName = X509Util.getCommonName(new X500Name(peerPrincipal.getName()));
            LOG.info("commonName: {}", commonName);
        } catch (Exception e) {
            LOG.error("Error: {}", e.getMessage());
            return false;
        }

        Set<String> hostnames = hostnameMap.get(commonName);
        return (hostnames == null)
                ? false
                : hostnames.contains(hostname);
    }

    public void setCommonnameHostMap(
            final String commonnameHostMap) {
        hostnameMap.clear();
        if (StringUtil.isBlank(commonnameHostMap)) {
            return;
        }

        ConfPairs pairs = new ConfPairs(commonnameHostMap);
        Set<String> commonNames = pairs.getNames();
        for (String commonName :commonNames) {
            String v = pairs.getValue(commonName);
            Set<String> hosts = StringUtil.splitAsSet(v, ",; \t");
            hostnameMap.put(commonName, hosts);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(
            final boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isTrustAll() {
        return trustAll;
    }

    public void setTrustAll(
            final boolean trustAll) {
        this.trustAll = trustAll;
    }

}
