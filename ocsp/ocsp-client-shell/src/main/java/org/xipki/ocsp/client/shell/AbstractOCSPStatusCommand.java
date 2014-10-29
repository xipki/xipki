/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.shell;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.felix.gogo.commands.Option;
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
