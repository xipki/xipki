/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.server.impl.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.ca.api.CertprofileException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaUtil {

    private CaUtil() {
    }

    public static Extensions getExtensions(
            final CertificationRequestInfo p10Req) {
        ParamUtil.requireNonNull("p10Req", p10Req);
        ASN1Set attrs = p10Req.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
                return Extensions.getInstance(attr.getAttributeValues()[0]);
            }
        }
        return null;
    }

    public static String getChallengePassword(
            final CertificationRequestInfo p10Req) {
        ParamUtil.requireNonNull("p10Req", p10Req);
        ASN1Set attrs = p10Req.getAttributes();
        for (int i = 0; i < attrs.size(); i++) {
            Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
            if (PKCSObjectIdentifiers.pkcs_9_at_challengePassword.equals(attr.getAttrType())) {
                ASN1String str = (ASN1String) attr.getAttributeValues()[0];
                return str.getString();
            }
        }
        return null;
    }

    public static BasicConstraints createBasicConstraints(
            final boolean isCa,
            final Integer pathLen) {
        BasicConstraints basicConstraints;
        if (isCa) {
            if (pathLen != null) {
                basicConstraints = new BasicConstraints(pathLen);
            } else {
                basicConstraints = new BasicConstraints(true);
            }
        } else {
            basicConstraints = new BasicConstraints(false);
        }
        return basicConstraints;
    }

    public static AuthorityInformationAccess createAuthorityInformationAccess(
            final List<String> caIssuerUris,
            final List<String> ocspUris) {
        if (CollectionUtil.isEmpty(caIssuerUris) && CollectionUtil.isEmpty(ocspUris)) {
            throw new IllegalArgumentException("caIssuerUris and ospUris must not be both empty");
        }

        List<AccessDescription> accessDescriptions = new ArrayList<>(ocspUris.size());

        if (CollectionUtil.isNonEmpty(caIssuerUris)) {
            for (String uri : caIssuerUris) {
                GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
                accessDescriptions.add(
                        new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers, gn));
            }
        }

        if (CollectionUtil.isNonEmpty(ocspUris)) {
            for (String uri : ocspUris) {
                GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
                accessDescriptions.add(new AccessDescription(X509ObjectIdentifiers.id_ad_ocsp, gn));
            }
        }

        DERSequence seq = new DERSequence(accessDescriptions.toArray(new AccessDescription[0]));
        return AuthorityInformationAccess.getInstance(seq);
    }

    public static CRLDistPoint createCrlDistributionPoints(
            final List<String> crlUris,
            final X500Name caSubject,
            final X500Name crlSignerSubject)
    throws IOException, CertprofileException {
        ParamUtil.requireNonEmpty("crlUris", crlUris);
        int n = crlUris.size();
        DistributionPoint[] points = new DistributionPoint[1];

        GeneralName[] names = new GeneralName[n];
        for (int i = 0; i < n; i++) {
            names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, crlUris.get(i));
        }
        // Distribution Point
        GeneralNames gns = new GeneralNames(names);
        DistributionPointName pointName = new DistributionPointName(gns);

        GeneralNames crlIssuer = null;
        if (crlSignerSubject != null && !crlSignerSubject.equals(caSubject)) {
            GeneralName crlIssuerName = new GeneralName(crlSignerSubject);
            crlIssuer = new GeneralNames(crlIssuerName);
        }

        points[0] = new DistributionPoint(pointName, null, crlIssuer);

        return new CRLDistPoint(points);
    }

}
