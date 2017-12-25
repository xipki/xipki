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

package org.xipki.http.servlet;

import java.net.URISyntaxException;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

// CHECKSTYLE:SKIP
public class ServletURIPool {

    private static final ServletURI SLASH_URI;

    private static SimpleLruCache<String, ServletURI> uriMap = new SimpleLruCache<>(100);

    static {
        try {
            SLASH_URI = new ServletURI("/");
        } catch (URISyntaxException ex) {
            throw new ExceptionInInitializerError(
                    "could not create ServletURI: " + ex.getMessage());
        }
    }

    private ServletURIPool() {
    }

    public static ServletURI getServletURI(String uri) throws URISyntaxException {
        if (uri == null || uri.isEmpty() || uri.equals("/")) {
            return SLASH_URI;
        } else if (uri.length() > 50) {
            return new ServletURI(uri);
        } else {
            // cache only short URI
            ServletURI uriObj = uriMap.get(uri);
            if (uriObj == null) {
                uriObj = new ServletURI(uri);
                uriMap.put(uri, uriObj);
            }
            return uriObj;
        }
    }

}
