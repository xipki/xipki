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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.HashAlgoType;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class IssuerFilter {

    private final Set<String> includeSha1Fps;

    private final Set<String> excludeSha1Fps;

    public IssuerFilter(Set<X509Certificate> includes, Set<X509Certificate> excludes)
            throws CertificateEncodingException {
        if (includes == null) {
            includeSha1Fps = null;
        } else {
            includeSha1Fps = new HashSet<>(includes.size());
            for (X509Certificate include : includes) {
                String sha1Fp = HashAlgoType.SHA1.base64Hash(include.getEncoded());
                includeSha1Fps.add(sha1Fp);
            }
        }

        if (excludes == null) {
            excludeSha1Fps = null;
        } else {
            excludeSha1Fps = new HashSet<>(excludes.size());
            for (X509Certificate exclude : excludes) {
                String sha1Fp = HashAlgoType.SHA1.base64Hash(exclude.getEncoded());
                excludeSha1Fps.add(sha1Fp);
            }
        }
    }

    public boolean includeIssuerWithSha1Fp(String sha1Fp) {
        ParamUtil.requireNonBlank("sha1Fp", sha1Fp);
        if (includeSha1Fps == null || includeSha1Fps.contains(sha1Fp)) {
            return (excludeSha1Fps == null) ? true : !excludeSha1Fps.contains(sha1Fp);
        } else {
            return false;
        }
    }

}
