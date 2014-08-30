/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.api.p11.remote;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * @author Lijun Liao
 */

public class RemoteP11Constants
{
    // just dummy, for intern purpose
    private static final ASN1ObjectIdentifier id_remotep11      = new ASN1ObjectIdentifier("1.2.3.4.5.6");

    public static final ASN1ObjectIdentifier id_version         = id_remotep11.branch("1");
    public static final ASN1ObjectIdentifier id_pso_rsa_x509    = id_remotep11.branch("2");
    public static final ASN1ObjectIdentifier id_pso_rsa_pkcs    = id_remotep11.branch("3");
    public static final ASN1ObjectIdentifier id_pso_ecdsa       = id_remotep11.branch("4");
    public static final ASN1ObjectIdentifier id_get_publickey   = id_remotep11.branch("5");
    public static final ASN1ObjectIdentifier id_get_certificate = id_remotep11.branch("6");
    public static final ASN1ObjectIdentifier id_list_slots      = id_remotep11.branch("7");
    public static final ASN1ObjectIdentifier id_list_keylabels  = id_remotep11.branch("8");

    public static final GeneralName CMP_SERVER =
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/server");
    public static final GeneralName CMP_CLIENT =
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://xipki.org/remotep11/client");

}
