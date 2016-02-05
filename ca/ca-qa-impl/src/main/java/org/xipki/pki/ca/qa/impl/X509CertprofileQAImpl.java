/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.pki.ca.qa.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.qa.ValidationIssue;
import org.xipki.commons.common.qa.ValidationResult;
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.util.AlgorithmUtil;
import org.xipki.commons.security.api.util.X509Util;
import org.xipki.pki.ca.api.CertprofileException;
import org.xipki.pki.ca.api.profile.CertValidity;
import org.xipki.pki.ca.api.profile.Range;
import org.xipki.pki.ca.api.profile.x509.X509CertVersion;
import org.xipki.pki.ca.certprofile.XmlX509CertprofileUtil;
import org.xipki.pki.ca.certprofile.x509.jaxb.ConstantExtValue;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionType;
import org.xipki.pki.ca.certprofile.x509.jaxb.ExtensionsType;
import org.xipki.pki.ca.certprofile.x509.jaxb.RangeType;
import org.xipki.pki.ca.certprofile.x509.jaxb.RangesType;
import org.xipki.pki.ca.certprofile.x509.jaxb.X509ProfileType;
import org.xipki.pki.ca.qa.api.X509CertprofileQA;
import org.xipki.pki.ca.qa.api.X509IssuerInfo;
import org.xipki.pki.ca.qa.impl.internal.QaExtensionValue;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertprofileQAImpl implements X509CertprofileQA {

    private static final Logger LOG = LoggerFactory.getLogger(X509CertprofileQAImpl.class);

    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    private static final long SECOND = 1000L;

    private static final long MAX_CERT_TIME_MS = 253402300799982L; //9999-12-31-23-59-59

    private static final long EPOCHTIME_2050010100 = 2524608000L;

    private final SubjectChecker subjectChecker;

    private final PublicKeyChecker publicKeyChecker;

    private final ExtensionsChecker extensionsChecker;

    private final CertValidity validity;

    private final X509CertVersion version;

    private final Set<String> signatureAlgorithms;

    private final boolean notBeforeMidnight;

    private final int maxSize;

    public X509CertprofileQAImpl(
            final String data)
    throws CertprofileException {
        this(data.getBytes());
    }

    public X509CertprofileQAImpl(
            final byte[] dataBytes)
    throws CertprofileException {
        try {
            X509ProfileType conf = XmlX509CertprofileUtil.parse(
                    new ByteArrayInputStream(dataBytes));

            this.version = X509CertVersion.getInstance(conf.getVersion());
            if (this.version == null) {
                throw new CertprofileException("invalid version " + conf.getVersion());
            }

            Integer i = conf.getMaxSize();
            this.maxSize = (i == null)
                    ? 0
                    : i;

            if (conf.getSignatureAlgorithms() == null) {
                this.signatureAlgorithms = null;
            } else {
                this.signatureAlgorithms = new HashSet<>();
                for (String algo :conf.getSignatureAlgorithms().getAlgorithm()) {
                    String c14nAlgo;
                    try {
                        c14nAlgo = AlgorithmUtil.canonicalizeSignatureAlgo(algo);
                    } catch (NoSuchAlgorithmException e) {
                        throw new CertprofileException(e.getMessage(), e);
                    }
                    this.signatureAlgorithms.add(c14nAlgo);
                }
            }

            this.validity = CertValidity.getInstance(conf.getValidity());
            this.notBeforeMidnight = "midnight".equalsIgnoreCase(conf.getNotBeforeTime());
            this.publicKeyChecker = new PublicKeyChecker(conf);
            this.subjectChecker = new SubjectChecker(conf);
            this.extensionsChecker = new ExtensionsChecker(conf);
        } catch (RuntimeException e) {
            final String message = "RuntimeException";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
            throw new CertprofileException(
                    "RuntimeException thrown while initializing certprofile: " + e.getMessage());
        }
    } // constructor

    @Override
    public ValidationResult checkCert(
            final byte[] certBytes,
            final X509IssuerInfo issuerInfo,
            final X500Name requestedSubject,
            final SubjectPublicKeyInfo requestedPublicKey,
            final Extensions requestedExtensions) {
        ParamUtil.assertNotNull("certBytes", certBytes);
        ParamUtil.assertNotNull("issuerInfo", issuerInfo);
        ParamUtil.assertNotNull("requestedSubject", requestedSubject);
        ParamUtil.assertNotNull("requestedPublicKey", requestedPublicKey);

        List<ValidationIssue> resultIssues = new LinkedList<ValidationIssue>();

        Certificate bcCert;
        TBSCertificate tbsCert;
        X509Certificate cert;
        ValidationIssue issue;

        // certificate size
        issue = new ValidationIssue("X509.SIZE", "certificate size");
        resultIssues.add(issue);
        if (maxSize > 0) {
            int size = certBytes.length;
            if (size > maxSize) {
                issue.setFailureMessage(
                    String.format("certificate exceeds the maximal allowed size: %d > %d",
                            size, maxSize));
            }
        }

        // certificate encoding
        issue = new ValidationIssue("X509.ENCODING", "certificate encoding");
        resultIssues.add(issue);
        try {
            bcCert = Certificate.getInstance(certBytes);
            tbsCert = bcCert.getTBSCertificate();
            cert = X509Util.parseCert(certBytes);
        } catch (CertificateException | IOException e) {
            issue.setFailureMessage("certificate is not corrected encoded");
            return new ValidationResult(resultIssues);
        }

        // syntax version
        issue = new ValidationIssue("X509.VERSION", "certificate version");
        resultIssues.add(issue);
        int versionNumber = cert.getVersion();
        if (versionNumber != version.getVersion()) {
            issue.setFailureMessage("is '" + versionNumber
                    + "' but expected '" + version.getVersion() + "'");
        }

        // serialNumber
        issue = new ValidationIssue("X509.serialNumber", "certificate serial number");
        resultIssues.add(issue);
        BigInteger serialNumber = tbsCert.getSerialNumber().getValue();
        if (serialNumber.signum() != 1) {
            issue.setFailureMessage("not positive");
        } else {
            if (serialNumber.bitLength() >= 160) {
                issue.setFailureMessage("serial number has more than 20 octets");
            }
        }

        // signatureAlgorithm
        if (CollectionUtil.isNotEmpty(signatureAlgorithms)) {
            issue = new ValidationIssue("X509.SIGALG", "signature algorithm");
            resultIssues.add(issue);

            AlgorithmIdentifier sigAlgId = bcCert.getSignatureAlgorithm();
            AlgorithmIdentifier tbsSigAlgId = tbsCert.getSignature();
            if (!tbsSigAlgId.equals(sigAlgId)) {
                issue.setFailureMessage(
                        "Certificate.tbsCertificate.signature != Certificate.signatureAlgorithm");
            }

            try {

                String sigAlgo = AlgorithmUtil.getSignatureAlgoName(sigAlgId);
                if (!issue.isFailed()) {
                    if (!signatureAlgorithms.contains(sigAlgo)) {
                        issue.setFailureMessage("signatureAlgorithm '" + sigAlgo
                                + "' is not allowed");
                    }
                }

                // check parameters
                if (!issue.isFailed()) {
                    AlgorithmIdentifier expSigAlgId = AlgorithmUtil.getSignatureAlgoId(sigAlgo);
                    if (!expSigAlgId.equals(sigAlgId)) {
                        issue.setFailureMessage("invalid parameters");
                    }
                }
            } catch (NoSuchAlgorithmException e) {
                issue.setFailureMessage("unsupported signature algorithm "
                        + sigAlgId.getAlgorithm().getId());
            }
        }

        // notBefore encoding
        issue = new ValidationIssue("X509.NOTBEFORE.ENCODING", "notBefore encoding");
        checkTime(tbsCert.getStartDate(), issue);

        // notAfter encoding
        issue = new ValidationIssue("X509.NOTAFTER.ENCODING", "notAfter encoding");
        checkTime(tbsCert.getStartDate(), issue);

        // notBefore
        if (notBeforeMidnight) {
            issue = new ValidationIssue("X509.NOTBEFORE", "notBefore midnight");
            resultIssues.add(issue);
            Calendar c = Calendar.getInstance(UTC);
            c.setTime(cert.getNotBefore());
            int hourOfDay = c.get(Calendar.HOUR_OF_DAY);
            int minute = c.get(Calendar.MINUTE);
            int second = c.get(Calendar.SECOND);

            if (hourOfDay != 0 || minute != 0 || second != 0) {
                issue.setFailureMessage(" '" + cert.getNotBefore()
                    + "' is not midnight time (UTC)");
            }
        }

        // validity
        issue = new ValidationIssue("X509.VALIDITY", "cert validity");
        resultIssues.add(issue);

        if (cert.getNotAfter().before(cert.getNotBefore())) {
            issue.setFailureMessage("notAfter could not be before notBefore");
        }

        if (!issue.isFailed()) {
            Date expectedNotAfter = validity.add(cert.getNotBefore());
            if (expectedNotAfter.getTime() > MAX_CERT_TIME_MS) {
                expectedNotAfter = new Date(MAX_CERT_TIME_MS);
            }

            if (Math.abs(expectedNotAfter.getTime() - cert.getNotAfter().getTime()) > 60 * SECOND) {
                issue.setFailureMessage("cert validity is not within " + validity.toString());
            }
        }

        // subjectPublicKeyInfo
        resultIssues.addAll(publicKeyChecker.checkPublicKey(bcCert.getSubjectPublicKeyInfo(),
                requestedPublicKey));

        // Signature
        issue = new ValidationIssue("X509.SIG",
                "whether certificate is signed by CA");
        resultIssues.add(issue);
        try {
            cert.verify(issuerInfo.getCert().getPublicKey(), "BC");
        } catch (Exception e) {
            issue.setFailureMessage("invalid signature");
        }

        // issuer
        issue = new ValidationIssue("X509.ISSUER", "certificate issuer");
        resultIssues.add(issue);
        if (!cert.getIssuerX500Principal().equals(
                issuerInfo.getCert().getSubjectX500Principal())) {
            issue.setFailureMessage(
                    "issue in certificate does not equal the subject of CA certificate");
        }

        // subject
        resultIssues.addAll(
                subjectChecker.checkSubject(
                bcCert.getSubject(),
                requestedSubject));

        // issuerUniqueID
        issue = new ValidationIssue("X509.IssuerUniqueID", "issuerUniqueID");
        resultIssues.add(issue);
        if (tbsCert.getIssuerUniqueId() != null) {
            issue.setFailureMessage("is present but not permitted");
        }

        // subjectUniqueID
        issue = new ValidationIssue("X509.SubjectUniqueID", "subjectUniqueID");
        resultIssues.add(issue);
        if (tbsCert.getSubjectUniqueId() != null) {
            issue.setFailureMessage("is present but not permitted");
        }

        // extensions
        resultIssues.addAll(
                extensionsChecker.checkExtensions(bcCert, issuerInfo, requestedExtensions));

        return new ValidationResult(resultIssues);
    } // method checkCert

    static Set<Range> buildParametersMap(
            final RangesType ranges) {
        if (ranges == null) {
            return null;
        }

        Set<Range> ret = new HashSet<>();
        for (RangeType range : ranges.getRange()) {
            if (range.getMin() != null || range.getMax() != null) {
                ret.add(new Range(range.getMin(), range.getMax()));
            }
        }
        return ret;
    }

    public static Map<ASN1ObjectIdentifier, QaExtensionValue> buildConstantExtesions(
            final ExtensionsType extensionsType)
    throws CertprofileException {
        if (extensionsType == null) {
            return null;
        }

        Map<ASN1ObjectIdentifier, QaExtensionValue> map = new HashMap<>();

        for (ExtensionType m : extensionsType.getExtension()) {
            if (m.getValue() == null || !(m.getValue().getAny() instanceof ConstantExtValue)) {
                continue;
            }

            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(m.getType().getValue());
            if (Extension.subjectAlternativeName.equals(oid)
                    || Extension.subjectInfoAccess.equals(oid)
                    || Extension.biometricInfo.equals(oid)) {
                continue;
            }

            ConstantExtValue extConf = (ConstantExtValue) m.getValue().getAny();
            byte[] encodedValue = extConf.getValue();
            ASN1StreamParser parser = new ASN1StreamParser(encodedValue);
            try {
                parser.readObject();
            } catch (IOException e) {
                throw new CertprofileException("could not parse the constant extension value", e);
            }
            QaExtensionValue extension = new QaExtensionValue(m.isCritical(), encodedValue);
            map.put(oid, extension);
        }

        if (CollectionUtil.isEmpty(map)) {
            return null;
        }

        return Collections.unmodifiableMap(map);
    } // method buildConstantExtesions

    private static void checkTime(Time time, ValidationIssue issue) {
        ASN1Primitive asn1Time = time.toASN1Primitive();
        if (time.getDate().getTime() / 1000 < EPOCHTIME_2050010100) {
            if (!(asn1Time instanceof ASN1UTCTime)) {
                issue.setFailureMessage("not encoded as UTCTime");
            }
        } else {
            if (!(asn1Time instanceof ASN1GeneralizedTime)) {
                issue.setFailureMessage("not encoded as GeneralizedTime");
            }
        }
    }

}
