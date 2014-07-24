/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.shell;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.felix.gogo.commands.Option;
import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.RequestOptions;

/**
 * @author Lijun Liao
 */

public abstract class AbstractOCSPStatusCommand extends OsgiCommandSupport
{
    private static final String DFLT_URL = "http://localhost:8080/ocsp";

    @Option(name = "-url",
            description = "Server URL, the default is " + DFLT_URL)
    protected String            serverURL;

    @Option(name = "-cacert",
            required = true, description = "Required. CA certificate file")
    protected String            caCertFile;

    @Option(name = "-nonce",
            description = "Use nonce")
    protected Boolean            useNonce;

    @Option(name = "-hash",
            required = false, description = "Hash algorithm name. The default is SHA256")
    protected String            hashAlgo;

    @Option(name = "-sigalgs",
            required = false, description = "comma-seperated preferred signature algorithms")
    protected String           prefSigAlgs;

    @Option(name = "-httpget",
            required = false, description = "Use HTTP GET for small request")
    protected Boolean          useHttpGetForSmallRequest;

    @Option(name = "-sign",
            required = false, description = "Sign request")
    protected Boolean          signRequest;

    protected OCSPRequestor      requestor;

    protected URL getServiceURL()
    throws MalformedURLException
    {
        return new URL(serverURL == null ? DFLT_URL : serverURL);
    }

    protected RequestOptions getRequestOptions()
    throws Exception
    {
        if(hashAlgo == null)
        {
            hashAlgo = "SHA256";
        }

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
        options.setUseNonce(useNonce == null ? false : useNonce.booleanValue());
        options.setHashAlgorithmId(hashAlgoOid);
        options.setSignRequest(signRequest == null ? false : signRequest.booleanValue());

        if(useHttpGetForSmallRequest != null)
        {
            options.setUseHttpGetForRequest(useHttpGetForSmallRequest.booleanValue());
        }

        if(prefSigAlgs != null)
        {
            StringTokenizer st = new StringTokenizer(prefSigAlgs, ",;: \t");
            List<String> sortedList = new ArrayList<>(st.countTokens());
            while(st.hasMoreTokens())
            {
                sortedList.add(st.nextToken());
            }

            options.setPreferredSignatureAlgorithms2(sortedList);
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
