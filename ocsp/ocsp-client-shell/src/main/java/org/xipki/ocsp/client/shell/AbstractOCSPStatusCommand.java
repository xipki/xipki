/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.ocsp.client.shell;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.common.StringUtil;
import org.xipki.console.karaf.XipkiOsgiCommandSupport;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 */

public abstract class AbstractOCSPStatusCommand extends XipkiOsgiCommandSupport
{
    private static final String DFLT_URL = "http://localhost:8080/ocsp";

    @Option(name = "-url",
            description = "Server URL")
    protected String serverURL = DFLT_URL;

    @Option(name = "-cacert",
            required = true, description = "Required. CA certificate file")
    protected String caCertFile;

    @Option(name = "-nonce",
            description = "Use nonce")
    protected Boolean useNonce = Boolean.FALSE;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name")
    protected String hashAlgo = "SHA256";

    @Option(name = "-sigalgs",
            required = false, description = "comma-seperated preferred signature algorithms")
    protected String prefSigAlgs;

    @Option(name = "-httpget",
            required = false, description = "Use HTTP GET for small request")
    protected Boolean useHttpGetForSmallRequest = Boolean.FALSE;

    @Option(name = "-sign",
            required = false, description = "Sign request")
    protected Boolean signRequest = Boolean.FALSE;

    protected OCSPRequestor requestor;

    protected URL getServiceURL()
    throws MalformedURLException
    {
        return new URL(serverURL);
    }

    protected RequestOptions getRequestOptions()
    throws Exception
    {
        ASN1ObjectIdentifier hashAlgoOid;

        hashAlgo = hashAlgo.trim().toUpperCase();

        if("SHA1".equalsIgnoreCase(hashAlgo) || "SHA-1".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = X509ObjectIdentifiers.id_SHA1;
        }
        else if("SHA256".equalsIgnoreCase(hashAlgo) || "SHA-256".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = NISTObjectIdentifiers.id_sha256;
        }
        else if("SHA384".equalsIgnoreCase(hashAlgo) || "SHA-384".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = NISTObjectIdentifiers.id_sha384;
        }
        else if("SHA512".equalsIgnoreCase(hashAlgo) || "SHA-512".equalsIgnoreCase(hashAlgo))
        {
            hashAlgoOid = NISTObjectIdentifiers.id_sha512;
        }
        else
        {
            throw new Exception("Unsupported hash algorithm " + hashAlgo);
        }

        RequestOptions options = new RequestOptions();
        options.setUseNonce(useNonce.booleanValue());
        options.setHashAlgorithmId(hashAlgoOid);
        options.setSignRequest(signRequest.booleanValue());
        options.setUseHttpGetForRequest(useHttpGetForSmallRequest.booleanValue());

        if(prefSigAlgs != null)
        {
            options.setPreferredSignatureAlgorithms2(StringUtil.split(prefSigAlgs, ",;: \t"));
        }

        return options;
    }

    public OCSPRequestor getRequestor()
    {
        return requestor;
    }

    public void setRequestor(OCSPRequestor requestor)
    {
        this.requestor = requestor;
    }
}
