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

package org.xipki.ocsp.server.impl.store.db;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.xipki.ocsp.api.OcspStoreException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class StoreConf {

    private static final String KEY_cacerts_includes = "cacerts.includes";

    private static final String KEY_cacerts_excludes = "cacerts.excludes";

    private final Set<String> caCertsIncludes = new HashSet<>();

    private final Set<String> caCertsExcludes = new HashSet<>();

    StoreConf(final String propsConf) throws OcspStoreException {
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(propsConf.getBytes()));
        } catch (IOException ex) {
            throw new OcspStoreException("could not load properties: " + ex.getMessage(), ex);
        }

        String str = props.getProperty(KEY_cacerts_includes);
        if (str != null) {
            StringTokenizer st = new StringTokenizer(str, ", ");
            while (st.hasMoreTokens()) {
                caCertsIncludes.add(st.nextToken());
            }
        }

        str = props.getProperty(KEY_cacerts_excludes);
        if (str != null) {
            StringTokenizer st = new StringTokenizer(str, ", ");
            while (st.hasMoreTokens()) {
                caCertsExcludes.add(st.nextToken());
            }
        }
    }

    Set<String> caCertsIncludes() {
        return caCertsIncludes;
    }

    Set<String> caCertsExcludes() {
        return caCertsExcludes;
    }

}
