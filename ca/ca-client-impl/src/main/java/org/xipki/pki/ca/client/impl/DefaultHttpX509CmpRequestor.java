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

package org.xipki.pki.ca.client.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.ConcurrentContentSigner;
import org.xipki.commons.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class DefaultHttpX509CmpRequestor extends X509CmpRequestor {

    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private final URL serverUrl;

    DefaultHttpX509CmpRequestor(
            final X509Certificate requestorCert,
            final X509Certificate responderCert,
            final String serverUrl,
            final SecurityFactory securityFactory) {
        super(requestorCert, responderCert, securityFactory);
        ParamUtil.assertNotBlank("serverUrl", serverUrl);

        try {
            this.serverUrl = new URL(serverUrl);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("invalid url: " + serverUrl);
        }
    }

    DefaultHttpX509CmpRequestor(
            final ConcurrentContentSigner requestor,
            final X509Certificate responderCert,
            final String serverUrl,
            final SecurityFactory securityFactory,
            final boolean signRequest) {
        super(requestor, responderCert, securityFactory, signRequest);
        ParamUtil.assertNotBlank("serverUrl", serverUrl);

        try {
            this.serverUrl = new URL(serverUrl);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("invalid url: " + serverUrl);
        }
    }

    @Override
    public byte[] send(
            final byte[] request)
    throws IOException {
        HttpURLConnection httpUrlConnection = (HttpURLConnection) serverUrl.openConnection();
        httpUrlConnection.setDoOutput(true);
        httpUrlConnection.setUseCaches(false);

        int size = request.length;

        httpUrlConnection.setRequestMethod("POST");
        httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
        httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
        OutputStream outputstream = httpUrlConnection.getOutputStream();
        outputstream.write(request);
        outputstream.flush();

        InputStream inputStream = httpUrlConnection.getInputStream();
        if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            inputStream.close();
            throw new IOException("bad response: "
                    + httpUrlConnection.getResponseCode() + "    "
                    + httpUrlConnection.getResponseMessage());
        }
        String responseContentType = httpUrlConnection.getContentType();
        boolean isValidContentType = false;
        if (responseContentType != null) {
            if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE)) {
                isValidContentType = true;
            }
        }
        if (!isValidContentType) {
            inputStream.close();
            throw new IOException("bad response: mime type "
                    + responseContentType
                    + " not supported!");
        }

        return IoUtil.read(inputStream);
    } // method send

}
