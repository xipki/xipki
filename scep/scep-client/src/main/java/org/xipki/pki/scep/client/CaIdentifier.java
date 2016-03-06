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

package org.xipki.pki.scep.client;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.pki.scep.transaction.Operation;
import org.xipki.pki.scep.transaction.TransactionException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaIdentifier {

    private final String url;

    private final String profile;

    public CaIdentifier(
            final String serverUrl,
            final String profile)
    throws MalformedURLException {
        ParamUtil.requireNonBlank("serverUrl", serverUrl);
        URL tmpUrl = new URL(serverUrl);
        final String protocol = tmpUrl.getProtocol();
        if (!"http".equalsIgnoreCase(protocol)
                && !"https".equalsIgnoreCase(protocol)) {
            throw new IllegalArgumentException(
                    "URL protocol should be HTTP or HTTPS, but not '" + protocol + "'");
        }

        if (tmpUrl.getQuery() != null) {
            throw new IllegalArgumentException("URL should contain no query string");
        }

        this.url = serverUrl;
        this.profile = profile;
    }

    public String getUrl() {
        return url;
    }

    public String getProfile() {
        return profile;
    }

    public String buildGetUrl(
            final Operation operation)
    throws TransactionException {
        return buildGetUrl(operation, null);
    }

    @SuppressWarnings("deprecation")
    public String buildGetUrl(
            final Operation operation,
            final String message) {
        ParamUtil.requireNonNull("operation", operation);
        StringBuilder ub = new StringBuilder(url);
        ub.append('?').append("operation=").append(operation.getCode());
        if (!StringUtil.isBlank(message)) {
            String urlMessage;
            try {
                urlMessage = URLEncoder.encode(message, "UTF-8");
            } catch (UnsupportedEncodingException ex) {
                urlMessage = URLEncoder.encode(message);
            }
            ub.append("&message=").append(urlMessage);
        }
        return ub.toString();
    }

    public String buildPostUrl(
            final Operation operation) {
        ParamUtil.requireNonNull("operation", operation);
        StringBuilder ub = new StringBuilder(url);
        ub.append('?').append("operation=").append(operation.getCode());
        return ub.toString();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("URL: ").append(url);
        if (StringUtil.isNotBlank(profile)) {
            sb.append(", CA-Ident: ").append(profile);
        }
        return sb.toString();
    }

    @Override
    public boolean equals(
            final Object object) {
        if (object instanceof CaIdentifier) {
            CaIdentifier objB = (CaIdentifier) object;
            return url == objB.url && profile == objB.profile;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

}
