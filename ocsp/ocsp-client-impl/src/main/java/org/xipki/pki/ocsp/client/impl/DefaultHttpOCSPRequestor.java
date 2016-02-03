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

package org.xipki.pki.ocsp.client.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.pki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 * @since 2.0
 */

public class DefaultHttpOCSPRequestor extends AbstractOCSPRequestor {

  // result in maximal 254 Base-64 encoded octets
  private static final int MAX_LEN_GET = 190;

  private static final String CT_REQUEST  = "application/ocsp-request";

  private static final String CT_RESPONSE = "application/ocsp-response";

  public DefaultHttpOCSPRequestor() {
  }

  @Override
  protected byte[] send(
      final byte[] request,
      final URL responderURL,
      final RequestOptions requestOptions)
  throws IOException {
    int size = request.length;
    HttpURLConnection httpUrlConnection;
    if (size <= MAX_LEN_GET && requestOptions.isUseHttpGetForRequest()) {
      String b64Request = Base64.toBase64String(request);
      String urlEncodedReq = URLEncoder.encode(b64Request, "UTF-8");
      StringBuilder urlBuilder = new StringBuilder();
      String baseUrl = responderURL.toString();
      urlBuilder.append(baseUrl);
      if (!baseUrl.endsWith("/")) {
        urlBuilder.append('/');
      }
      urlBuilder.append(urlEncodedReq);

      URL newURL = new URL(urlBuilder.toString());

      httpUrlConnection = (HttpURLConnection) newURL.openConnection();
      httpUrlConnection.setRequestMethod("GET");
    } else {
      httpUrlConnection = (HttpURLConnection) responderURL.openConnection();
      httpUrlConnection.setDoOutput(true);
      httpUrlConnection.setUseCaches(false);

      httpUrlConnection.setRequestMethod("POST");
      httpUrlConnection.setRequestProperty("Content-Type", CT_REQUEST);
      httpUrlConnection.setRequestProperty("Content-Length",
          java.lang.Integer.toString(size));
      OutputStream outputstream = httpUrlConnection.getOutputStream();
      outputstream.write(request);
      outputstream.flush();
    }

    InputStream inputstream = httpUrlConnection.getInputStream();
    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      inputstream.close();
      throw new IOException("bad response: "
          + httpUrlConnection.getResponseCode() + "  "
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
