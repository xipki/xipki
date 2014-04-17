/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.publisher;

import java.util.Arrays;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

class IssuerEntry
{
    private final int id;
    private final String subject;
    private final byte[] sha1Fp;
    private final byte[] cert;

    IssuerEntry(int id, String subject, String hexSha1Fp,
            String b64Cert)
    {
        super();
        this.id = id;
        this.subject = subject;
        this.sha1Fp = Hex.decode(hexSha1Fp);
        this.cert = Base64.decode(b64Cert);
    }

    int getId()
    {
        return id;
    }

    String getSubject()
    {
        return subject;
    }

    boolean matchSha1Fp(byte[] sha1Fp)
    {
        return Arrays.equals(this.sha1Fp, sha1Fp);
    }

    boolean matchCert(byte[] encodedCert)
    {
        return Arrays.equals(this.cert, encodedCert);
    }
}
