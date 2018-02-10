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

package org.xipki.ocsp.client.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import org.xipki.common.util.Base64;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class DfltHttpOcspRequestor extends AbstractOcspRequestor {

    // result in maximal 254 Base-64 encoded octets
    private static final int MAX_LEN_GET = 190;

    private static final String CT_REQUEST = "application/ocsp-request";

    private static final String CT_RESPONSE = "application/ocsp-response";

    public DfltHttpOcspRequestor() {
    }

    @Override
    protected byte[] send(byte[] request, URL responderUrl, RequestOptions requestOptions)
            throws IOException {
        ParamUtil.requireNonNull("request", request);
        ParamUtil.requireNonNull("responderUrl", responderUrl);
        ParamUtil.requireNonNull("requestOptions", requestOptions);

        int size = request.length;
        HttpURLConnection httpUrlConnection;
        if (size <= MAX_LEN_GET && requestOptions.isUseHttpGetForRequest()) {
            String b64Request = Base64.encodeToString(request);
            String urlEncodedReq = URLEncoder.encode(b64Request, "UTF-8");
            String baseUrl = responderUrl.toString();
            String url = StringUtil.concat(baseUrl, (baseUrl.endsWith("/") ? "" : "/"),
                    urlEncodedReq);

            URL newUrl = new URL(url);
            httpUrlConnection = IoUtil.openHttpConn(newUrl);
            httpUrlConnection.setRequestMethod("GET");
        } else {
            httpUrlConnection = IoUtil.openHttpConn(responderUrl);
            httpUrlConnection.setDoOutput(true);
            httpUrlConnection.setUseCaches(false);

            httpUrlConnection.setRequestMethod("POST");
            httpUrlConnection.setRequestProperty("Content-Type", CT_REQUEST);
            httpUrlConnection.setRequestProperty("Content-Length", Integer.toString(size));
            OutputStream outputstream = httpUrlConnection.getOutputStream();
            outputstream.write(request);
            outputstream.flush();
        }

        InputStream inputstream = httpUrlConnection.getInputStream();
        if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            inputstream.close();
            throw new IOException("bad response: "
                    + httpUrlConnection.getResponseCode() + "    "
                    + httpUrlConnection.getResponseMessage());
        }
        String responseContentType = httpUrlConnection.getContentType();
        boolean isValidContentType = false;
        if (responseContentType != null) {
            if (responseContentType.equalsIgnoreCase(CT_RESPONSE)) {
                isValidContentType = true;
            }
        }
        if (!isValidContentType) {
            inputstream.close();
            throw new IOException("bad response: mime type " + responseContentType
                    + " not supported!");
        }

        return IoUtil.read(inputstream);
    } // method send

}
