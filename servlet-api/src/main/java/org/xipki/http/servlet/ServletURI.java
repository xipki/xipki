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

package org.xipki.http.servlet;

import java.net.URI;
import java.net.URISyntaxException;
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

    public void setPath(String path) {
        this.path = (path == null || path.isEmpty()) ? "/" : path;
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
                parameters.put(pn, pv);
            }
        }

        return parameters.get(name);
    }

}
