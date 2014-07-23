/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class ExtensionTuple
{
    private final ASN1ObjectIdentifier type;
    private final boolean critical;
    private final ASN1Encodable value;

    public ExtensionTuple(ASN1ObjectIdentifier type, boolean critical, ASN1Encodable value)
    {
        ParamChecker.assertNotNull("type", type);
        ParamChecker.assertNotNull("value", value);

        this.type = type;
        this.critical = critical;
        this.value = value;
    }

    public ExtensionTuple(boolean critical, Extension extension)
    {
        ParamChecker.assertNotNull("extension", extension);

        this.type = extension.getExtnId();
        this.critical = critical;
        this.value = extension.getParsedValue();
    }

    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    public boolean isCritical()
    {
        return critical;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }
}
