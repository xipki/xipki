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

package org.xipki.commons.http.servlet;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
public class ServletURI {

    private String path;

    private String fragement;

    private String query;

    private Map<String, String> parameters;

    public ServletURI(String rawPath) throws URISyntaxException {
        // TODO: debug to make sure rawPath mostly starts with "/"
        if (rawPath == null || rawPath.isEmpty() || "/".equals(rawPath)) {
            path = "/";
        } else {
            URI uri = new URI(rawPath);
            path = uri.getPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            } else if (path.charAt(0) != '/') {
                path += "/" + path;
            }

            fragement = uri.getFragment();
            query = uri.getQuery();
        }
    }

    public static void main(String[] args) {
        try {
            String encoded = URLEncoder.encode("http://localhost/a b?c d=e=f", "utF-8");
            System.out.println(encoded);
            System.out.println(URLDecoder.decode(encoded, "utf-8"));
            URI uri = new URI("abc/?a=aa&b=bb#ff");
            System.out.println("path: " + uri.getPath());
            System.out.println("quey: " + uri.getQuery());
            System.out.println("fragement: " + uri.getFragment());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public String path() {
        return path;
    }

    public String query() {
        return query;
    }

    public String fragement() {
        return fragement;
    }

    public String parameter(String name) {
        if (query == null) {
            return null;
        }

        if (parameters != null) {
            return parameters.get(name);
        }

        parameters = new HashMap<>();
        StringTokenizer st = new StringTokenizer(query, "&");
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            int idx = token.indexOf('=');
            if (idx != -1 && idx != token.length()) {
                String pn = token.substring(0, idx);
                String pv = token.substring(idx + 1);
                try {
                    pn = URLDecoder.decode(pn, "UTF-8");
                    pv = URLDecoder.decode(pv, "UTF-8");
                } catch (UnsupportedEncodingException ex) {
                    throw new RuntimeException("should not happen: " + ex.getMessage());
                }
                parameters.put(pn, pv);
            }
        }

        return parameters.get(name);
    }

}
