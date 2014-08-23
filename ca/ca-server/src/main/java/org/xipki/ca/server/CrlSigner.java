/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.server.mgmt.api.CRLControl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CrlSigner
{
    private final ConcurrentContentSigner signer;
    private final byte[] subjectKeyIdentifier;

    private final CRLControl crlControl;

    public CrlSigner(ConcurrentContentSigner signer, CRLControl crlControl)
    throws OperationException
    {
        ParamChecker.assertNotNull("crlControl", crlControl);

        this.signer = signer;
        this.crlControl = crlControl;

        if(signer == null)
        {
            subjectKeyIdentifier = null;
        }
        else
        {
            byte[] encodedSkiValue = signer.getCertificate().getExtensionValue(
                    Extension.subjectKeyIdentifier.getId());
            if(encodedSkiValue == null)
            {
                throw new OperationException(ErrorCode.INVALID_EXTENSION,
                        "CA certificate does not have required extension SubjectKeyIdentifier");
            }
            ASN1OctetString ski;
            try
            {
                ski = (ASN1OctetString) X509ExtensionUtil.fromExtensionValue(encodedSkiValue);
            } catch (IOException e)
            {
                throw new OperationException(ErrorCode.INVALID_EXTENSION, e.getMessage());
            }
            this.subjectKeyIdentifier = ski.getOctets();
        }
    }

    public ConcurrentContentSigner getSigner()
    {
        return signer;
    }

    public CRLControl getCRLcontrol()
    {
        return crlControl;
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return subjectKeyIdentifier == null ? null : Arrays.clone(subjectKeyIdentifier);
    }

}
