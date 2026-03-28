// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.BadInputException;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.DHSigStaticKeyCertPair;
import org.xipki.security.pkix.KeyUsage;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.CsrControl;
import org.xipki.security.sign.KemHmacSignature;
import org.xipki.security.sign.SignAlgoMode;
import org.xipki.security.sign.Signer;
import org.xipki.security.sign.SignerConf;
import org.xipki.security.util.Asn1Util;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * XiPKI CSR commands.
 *
 * @author Lijun Liao (xipki)
 */
public class CsrCommands {
  @Command(name = "crl-info", description = "print CRL information",
      mixinStandardHelpOptions = true)
  static class CrlInfoCommand extends ShellBaseCommand {

    @Option(names = "--in", description = "CRL file", required = true)
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(names = "--hex", description = "print hex number")
    private boolean hex;

    @Option(names = "--crlnumber", description = "print CRL number")
    private boolean crlNumber;

    @Option(names = "--issuer", description = "print issuer")
    private boolean issuer;

    @Option(names = "--this-update", description = "print thisUpdate")
    private boolean thisUpdate;

    @Option(names = "--next-update", description = "print nextUpdate")
    private boolean nextUpdate;

    @Override
    public void run() {
      try {
        CertificateList crl = CertificateList.getInstance(
                                X509Util.toDerEncoded(IoUtil.read(inFile)));
        String result;
        if (crlNumber) {
          ASN1Encodable asn1 = crl.getTBSCertList().getExtensions()
              .getExtensionParsedValue(OIDs.Extn.cRLNumber);
          result = asn1 == null ? "null"
                                : getNumber(ASN1Integer.getInstance(asn1).getPositiveValue());
        } else if (issuer) {
          result = crl.getIssuer().toString();
        } else if (thisUpdate) {
          result = toUtcTime(crl.getThisUpdate().getDate().toInstant());
        } else if (nextUpdate) {
          result = crl.getNextUpdate() == null ? "null"
              : toUtcTime(crl.getNextUpdate().getDate().toInstant());
        } else {
          result = crl.toString();
        }
        println(result);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private String toUtcTime(Instant instant) {
      return DateUtil.toUtcTimeyyyyMMddhhmmss(instant) + "Z";
    }

    private String getNumber(Number no) {
      if (!hex) {
        return no.toString();
      }

      if (no instanceof Byte) {
        return "0X" + Hex.encode(new byte[]{(byte) no});
      } else if (no instanceof Short) {
        return "0X" + Integer.toHexString((short) no);
      } else if (no instanceof Integer) {
        return "0X" + Integer.toHexString((int) no);
      } else if (no instanceof Long) {
        return "0X" + Long.toHexString((long) no);
      } else if (no instanceof BigInteger) {
        return "0X" + ((BigInteger) no).toString(16);
      } else {
        return no.toString();
      }
    }
  }

  abstract static class CsrGenCommand extends SecurityCommands.SecurityCommand {

    @Option(names = {"--subject-alt-name", "--san"}, description = "subjectAltName entries")
    private List<String> subjectAltNames;

    @Option(names = {"--subject-info-access", "--sia"}, description = "subjectInfoAccess entries")
    private List<String> subjectInfoAccesses;

    @Option(names = "--cert", description = "certificate file to copy subject/extensions from")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--cert-ext-exclude", split = ",",
        description = "extension OIDs excluded from --cert copy")
    private List<String> excludeCertExtns;

    @Option(names = "--cert-ext-include", split = ",",
        description = "extension OIDs included from --cert copy")
    private List<String> includeCertExtns;

    @Option(names = "--old-cert", description = "certificate file to update")
    @Completion(FilePathCompleter.class)
    private String oldCertFile;

    @Option(names = {"--subject", "-s"}, description = "subject in the CSR")
    private String subject;

    @Option(names = "--dateOfBirth", description = "date of birth YYYYMMdd in subject")
    private String dateOfBirth;

    @Option(names = "--postalAddress", split = ",", description = "postal address in subject")
    private List<String> postalAddress;

    @Option(names = "--outform", description = "output format of the CSR")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String outputFilename;

    @Option(names = {"--challenge-password", "-c"}, description = "challenge password")
    private String challengePasswordHint;

    @Option(names = "--keyusage", split = ",", description = "keyusage")
    @Completion(Completers.KeyUsageCompleter.class)
    private List<String> keyusages;

    @Option(names = "--ext-keyusage", split = ",", description = "extended keyusage")
    private List<String> extkeyusages;

    @Option(names = "--qc-eu-limit", split = ",",
        description = "QC EuLimitValue of format <currency>:<amount>:<exponent>")
    private List<String> qcEuLimits;

    @Option(names = "--biometric-type", description = "Biometric type")
    private String biometricType;

    @Option(names = "--biometric-hash", description = "Biometric hash algorithm")
    private String biometricHashAlgo;

    @Option(names = "--biometric-file", description = "Biometric data file")
    @Completion(FilePathCompleter.class)
    private String biometricFile;

    @Option(names = "--biometric-uri", description = "Biometric source data URI")
    private String biometricUri;

    @Option(names = "--extensions-file", description = "DER-encoded Extensions file")
    @Completion(FilePathCompleter.class)
    private String extensionsFile;

    protected abstract ConcurrentSigner getSigner() throws Exception;

    protected List<X509Cert> getPeerCertificates() throws Exception {
      CsrControl control = securities().securityFactory().csrControl();
      return control == null ? null : control.peerCerts();
    }

    protected List<Extension> getAdditionalExtensions() throws BadInputException {
      return Collections.emptyList();
    }

    protected X500Name getSubject(String subjectText) {
      return new X500Name(Args.notBlank(subjectText, "subjectText"));
    }

    protected KemEncapKey getKemEncapKey(SubjectPublicKeyInfo myPublicKey)
        throws ObjectCreationException {
      try {
        SecurityFactory securityFactory = securities().securityFactory();
        return securityFactory.csrControl().generateKemEncapKey(
            myPublicKey, securityFactory.random4Sign());
      } catch (Exception ex) {
        throw new ObjectCreationException("error computing EncapKey: " + ex.getMessage(), ex);
      }
    }

    @Override
    public void run() {
      try {
        if (certFile != null && oldCertFile != null) {
          throw new IllegalArgumentException("maximal one of cert and old-cert is allowed");
        }

        ConcurrentSigner signer = getSigner();
        SubjectPublicKeyInfo subjectPublicKeyInfo = signer.x509Cert() == null
            ? KeyUtil.createSubjectPublicKeyInfo(signer.publicKey())
            : signer.x509Cert().subjectPublicKeyInfo();

        if (extkeyusages != null) {
          List<String> list = new ArrayList<>(extkeyusages.size());
          for (String usage : extkeyusages) {
            String id = getExtKeyusageOid(usage);
            if (id == null) {
              new ASN1ObjectIdentifier(usage);
              list.add(usage);
            } else {
              list.add(id);
            }
          }
          extkeyusages = list;
        }

        List<Extension> extensions = new LinkedList<>();
        ASN1OctetString extnValue = CollectionUtil.isEmpty(subjectInfoAccesses) ? null
            : X509Util.createExtnSubjectInfoAccess(
                normalizeSubjectInfoAccesses(unescapeStructuredValues(subjectInfoAccesses)),
                false).getExtnValue();
        if (extnValue != null) {
          extensions.add(new Extension(OIDs.Extn.subjectInfoAccess, false, extnValue));
        }

        if (CollectionUtil.isNotEmpty(keyusages)) {
          Set<KeyUsage> usages = new HashSet<>();
          for (String usage : keyusages) {
            usages.add(KeyUsage.getKeyUsage(usage));
          }
          extensions.add(new Extension(OIDs.Extn.keyUsage, false,
              X509Util.createKeyUsage(usages).getEncoded()));
        }

        if (CollectionUtil.isNotEmpty(extkeyusages)) {
          extensions.add(new Extension(OIDs.Extn.extendedKeyUsage, false,
              X509Util.createExtendedUsage(textToAsn1Oids(extkeyusages)).getEncoded()));
        }

        if (CollectionUtil.isNotEmpty(qcEuLimits)) {
          ASN1EncodableVector vec = new ASN1EncodableVector();
          for (String value : qcEuLimits) {
            StringTokenizer st = new StringTokenizer(value, ":");
            try {
              String currencyS = st.nextToken();
              String amountS = st.nextToken();
              String exponentS = st.nextToken();
              Iso4217CurrencyCode currency;
              try {
                currency = new Iso4217CurrencyCode(Integer.parseInt(currencyS));
              } catch (NumberFormatException ex) {
                currency = new Iso4217CurrencyCode(currencyS);
              }

              MonetaryValue mv = new MonetaryValue(currency,
                  Integer.parseInt(amountS), Integer.parseInt(exponentS));
              vec.add(new QCStatement(OIDs.QCS.id_etsi_qcs_QcLimitValue, mv));
            } catch (Exception ex) {
              throw new IOException("invalid qc-eu-limit '" + value + "'");
            }
          }

          extensions.add(new Extension(OIDs.Extn.qCStatements, false,
              new DERSequence(vec).getEncoded()));
        }

        if (biometricType != null && biometricHashAlgo != null && biometricFile != null) {
          TypeOfBiometricData bioType = StringUtil.isNumber(biometricType)
              ? new TypeOfBiometricData(Integer.parseInt(biometricType))
              : new TypeOfBiometricData(new ASN1ObjectIdentifier(biometricType));
          HashAlgo hashAlgo = HashAlgo.getInstance(biometricHashAlgo);
          byte[] bioHash = hashAlgo.hash(IoUtil.read(biometricFile));
          BiometricData bioData = Asn1Util.buildBiometricData(
              bioType, hashAlgo.algorithmIdentifier(), bioHash, biometricUri);
          extensions.add(new Extension(OIDs.Extn.biometricInfo, false,
              new DERSequence(bioData).getEncoded()));
        } else if (!(biometricType == null && biometricHashAlgo == null && biometricFile == null)) {
          throw new IOException("either all of biometric triples must be set or none");
        }

        List<ASN1ObjectIdentifier> addedExtnTypes = new ArrayList<>(extensions.size());
        for (Extension extn : extensions) {
          addedExtnTypes.add(extn.getExtnId());
        }

        if (extensionsFile != null) {
          Extensions extns = Extensions.getInstance(IoUtil.read(extensionsFile));
          for (ASN1ObjectIdentifier extnId : extns.getExtensionOIDs()) {
            if (addedExtnTypes.contains(extnId)) {
              throw new IOException("duplicated extension " + extnId.getId());
            }
            extensions.add(extns.getExtension(extnId));
            addedExtnTypes.add(extnId);
          }
        }

        extensions.addAll(getAdditionalExtensions());
        char[] challengePassword = StringUtil.isBlank(challengePasswordHint)
            ? null : Passwords.resolvePassword(challengePasswordHint);

        if (certFile != null) {
          Certificate cert = Certificate.getInstance(X509Util.toDerEncoded(IoUtil.read(certFile)));
          if (!Arrays.equals(subjectPublicKeyInfo.getEncoded(),
              cert.getSubjectPublicKeyInfo().getEncoded())) {
            throw new IOException("public key extracted from signer differs from certificate");
          }

          Extensions certExtns = cert.getTBSCertificate().getExtensions();
          List<ASN1ObjectIdentifier> stdExcludeOids = Arrays.asList(
              OIDs.Extn.authorityKeyIdentifier, OIDs.Extn.authorityInfoAccess,
              OIDs.Extn.certificateIssuer, OIDs.Extn.certificatePolicies,
              OIDs.Extn.cRLDistributionPoints, OIDs.Extn.freshestCRL,
              OIDs.Extn.nameConstraints, OIDs.Extn.policyMappings,
              OIDs.Extn.policyConstraints, OIDs.Extn.certificatePolicies,
              OIDs.Extn.subjectInfoAccess, OIDs.Extn.subjectDirectoryAttributes);

          for (ASN1ObjectIdentifier certExtnOid : certExtns.getExtensionOIDs()) {
            boolean add = !addedExtnTypes.contains(certExtnOid);
            if (add) {
              add = CollectionUtil.isNotEmpty(includeCertExtns)
                  ? includeCertExtns.contains(certExtnOid.getId())
                  : !stdExcludeOids.contains(certExtnOid);
            }
            if (add && CollectionUtil.isNotEmpty(excludeCertExtns)) {
              add = !excludeCertExtns.contains(certExtnOid.getId());
            }
            if (add) {
              extensions.add(certExtns.getExtension(certExtnOid));
            }
          }

          PKCS10CertificationRequest csr = generateRequest(
              signer, subjectPublicKeyInfo, cert.getSubject(), challengePassword, extensions);
          saveVerbose("saved CSR to file", outputFilename, derPemEncode(
              csr.getEncoded(), outform, PemEncoder.PemLabel.CERTIFICATE_REQUEST));
          return;
        }

        boolean updateOldCert = oldCertFile != null;
        X500Name newSubjectDn = null;
        if (subject == null) {
          if (StringUtil.isNotBlank(dateOfBirth)) {
            throw new IllegalArgumentException("dateOfBirth cannot be set if subject is not set");
          }
          if (CollectionUtil.isNotEmpty(postalAddress)) {
            throw new IllegalArgumentException("postalAddress cannot be set if subject is not set");
          }
          if (!updateOldCert) {
            X509Cert signerCert = signer.x509Cert();
            if (signerCert == null) {
              throw new IllegalArgumentException("subject must be set");
            }
            newSubjectDn = signerCert.subject();
          }
        } else {
          newSubjectDn = getSubject(subject);
          List<RDN> list = new LinkedList<>();
          if (StringUtil.isNotBlank(dateOfBirth)) {
            ASN1ObjectIdentifier id = OIDs.DN.dateOfBirth;
            RDN[] rdns = newSubjectDn.getRDNs(id);
            if (rdns == null || rdns.length == 0) {
              Instant date = DateUtil.parseUtcTimeyyyyMMdd(dateOfBirth).plus(12, ChronoUnit.HOURS);
              list.add(new RDN(id, new DERGeneralizedTime(
                  DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z")));
            }
          }
          if (CollectionUtil.isNotEmpty(postalAddress)) {
            ASN1ObjectIdentifier id = OIDs.DN.postalAddress;
            RDN[] rdns = newSubjectDn.getRDNs(id);
            if (rdns == null || rdns.length == 0) {
              ASN1EncodableVector vec = new ASN1EncodableVector();
              for (String value : postalAddress) {
                vec.add(new DERUTF8String(value));
              }
              if (vec.size() > 0) {
                list.add(new RDN(id, new DERSequence(vec)));
              }
            }
          }
          if (!list.isEmpty()) {
            Collections.addAll(list, newSubjectDn.getRDNs());
            newSubjectDn = new X500Name(list.toArray(new RDN[0]));
          }
        }

        extnValue = CollectionUtil.isEmpty(subjectAltNames) ? null
            : X509Util.createExtnSubjectAltName(
                unescapeStructuredValues(subjectAltNames), false).getExtnValue();
        Extension newSubjectAltNames = null;
        if (extnValue != null) {
          newSubjectAltNames = new Extension(
              OIDs.Extn.subjectAlternativeName, false, extnValue);
        }

        Attribute attrChangeSubjectName = null;
        X500Name subjectDn;
        if (updateOldCert) {
          Certificate oldCert = Certificate.getInstance(
              X509Util.toDerEncoded(IoUtil.read(oldCertFile)));
          subjectDn = oldCert.getSubject();
          Extension oldSan = oldCert.getTBSCertificate().getExtensions()
              .getExtension(OIDs.Extn.subjectAlternativeName);
          if (oldSan != null) {
            extensions.add(oldSan);
          }

          if (newSubjectDn != null || newSubjectAltNames != null) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(newSubjectDn == null ? subjectDn : newSubjectDn);
            GeneralNames subjectAlt = null;
            if (newSubjectAltNames != null) {
              subjectAlt = GeneralNames.getInstance(newSubjectAltNames.getExtnValue().getOctets());
            } else if (oldSan != null) {
              subjectAlt = GeneralNames.getInstance(oldSan.getParsedValue());
            }
            if (subjectAlt != null) {
              vec.add(subjectAlt);
            }
            attrChangeSubjectName = new Attribute(
                OIDs.CMC.id_cmc_changeSubjectName, new DERSet(new DERSequence(vec)));
          }
        } else {
          subjectDn = newSubjectDn;
          if (newSubjectAltNames != null) {
            extensions.add(newSubjectAltNames);
          }
        }

        PKCS10CertificationRequest csr = generateRequest(
            signer, subjectPublicKeyInfo, subjectDn, challengePassword, extensions,
            attrChangeSubjectName);
        saveVerbose("saved CSR to file", outputFilename, derPemEncode(
            csr.getEncoded(), outform, PemEncoder.PemLabel.CERTIFICATE_REQUEST));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private PKCS10CertificationRequest generateRequest(
        ConcurrentSigner signer, SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
        char[] challengePassword, List<Extension> extensions, Attribute... attrs)
        throws XiSecurityException {
      Args.notNull(signer, "signer");
      Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
      Args.notNull(subjectDn, "subjectDn");

      Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();
      if (CollectionUtil.isNotEmpty(extensions)) {
        attributes.put(OIDs.PKCS9.pkcs9_at_extensionRequest,
            new Extensions(extensions.toArray(new Extension[0])));
      }
      if (challengePassword != null && challengePassword.length > 0) {
        attributes.put(OIDs.PKCS9.pkcs9_at_challengePassword,
            new DERPrintableString(new String(challengePassword)));
      }

      PKCS10CertificationRequestBuilder csrBuilder =
          new PKCS10CertificationRequestBuilder(subjectDn, subjectPublicKeyInfo);
      for (Map.Entry<ASN1ObjectIdentifier, ASN1Encodable> entry : attributes.entrySet()) {
        csrBuilder.addAttribute(entry.getKey(), entry.getValue());
      }
      if (attrs != null) {
        for (Attribute attr : attrs) {
          if (attr != null) {
            csrBuilder.addAttribute(attr.getAttrType(), attr.getAttrValues().toArray());
          }
        }
      }

      Signer signer0;
      try {
        signer0 = signer.borrowSigner();
      } catch (NoIdleSignerException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }

      try {
        return csrBuilder.build(signer0.x509Signer());
      } finally {
        signer.requiteSigner(signer0);
      }
    }

    private static List<ASN1ObjectIdentifier> textToAsn1Oids(List<String> oidTexts) {
      if (oidTexts == null) {
        return null;
      }
      List<ASN1ObjectIdentifier> ret = new ArrayList<>(oidTexts.size());
      for (String oidText : oidTexts) {
        if (oidText.isEmpty()) {
          continue;
        }
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidText);
        if (!ret.contains(oid)) {
          ret.add(oid);
        }
      }
      return ret;
    }

    private static List<String> normalizeSubjectInfoAccesses(List<String> accesses) {
      List<String> normalized = new ArrayList<>(accesses.size());
      for (String access : accesses) {
        int idx = access.indexOf('=');
        if (idx <= 0 || idx == access.length() - 1) {
          normalized.add(access);
          continue;
        }

        String method = access.substring(0, idx);
        String location = access.substring(idx + 1);
        normalized.add(escapeConfPairsToken(method) + "=" + escapeConfPairsToken(location));
      }
      return normalized;
    }

    private static List<String> unescapeStructuredValues(List<String> values) {
      List<String> ret = new ArrayList<>(values.size());
      for (String value : values) {
        ret.add(unescapeStructuredValue(value));
      }
      return ret;
    }

    private static String unescapeStructuredValue(String text) {
      StringBuilder sb = new StringBuilder(text.length());
      boolean escaped = false;
      for (int i = 0; i < text.length(); i++) {
        char ch = text.charAt(i);
        if (escaped) {
          sb.append(ch);
          escaped = false;
        } else if (ch == '\\') {
          escaped = true;
        } else {
          sb.append(ch);
        }
      }

      if (escaped) {
        sb.append('\\');
      }
      return sb.toString();
    }

    private static String escapeConfPairsToken(String text) {
      StringBuilder sb = new StringBuilder(text.length() + 8);
      for (int i = 0; i < text.length(); i++) {
        char ch = text.charAt(i);
        if (ch == '\\' || ch == ',' || ch == '=') {
          sb.append('\\');
        }
        sb.append(ch);
      }
      return sb.toString();
    }

    private static String getExtKeyusageOid(String usage) {
      switch (usage.toLowerCase()) {
        case "serverauth":
          return "1.3.6.1.5.5.7.3.1";
        case "clientauth":
          return "1.3.6.1.5.5.7.3.2";
        case "codesigning":
          return "1.3.6.1.5.5.7.3.3";
        case "emailprotection":
          return "1.3.6.1.5.5.7.3.4";
        case "timestamping":
          return "1.3.6.1.5.5.7.3.8";
        case "ocspsigning":
          return "1.3.6.1.5.5.7.3.9";
        default:
          return null;
      }
    }
  }

  @Command(name = "csr-jce", description = "generate CSR request with JCE device",
      mixinStandardHelpOptions = true)
  static class CsrJceCommand extends CsrGenCommand {

    @Option(names = "--type", required = true, description = "JCE signer type")
    @Completion(Completers.KeystoreTypeCompleter.class)
    private String type;

    @Option(names = "--alias", required = true, description = "alias of the key in the JCE device")
    private String alias;

    @Option(names = "--algo", required = true, description = "signature algorithm")
    @Completion(Completers.SigAlgoCompleter.class)
    private String algo;

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      SecurityFactory securityFactory = securities().securityFactory();
      SignerConf conf = new SignerConf(new ConfPairs()
          .putPair("parallelism", "1")
          .putPair("alias", alias)
          .putPair("algo", SignAlgo.getInstance(algo).jceName()));
      return securityFactory.createSigner(type, conf, (X509Cert) null);
    }
  }

  @Command(name = "csr-p11", description = "generate CSR request with PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class CsrP11Command extends CsrGenCommand {

    @Option(names = "--slot", description = "slot index")
    private String slotIndex = "0";

    @Option(names = "--id", description = "id (hex) of the private key in the PKCS#11 device")
    private String id;

    @Option(names = "--label", description = "label of the private key in the PKCS#11 device")
    private String label;

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Option(names = "--rsa-pss", description = "whether to use RSAPSS for POP")
    private Boolean rsaPss = Boolean.FALSE;

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      byte[] idBytes = id == null ? null : Hex.decode(id);
      if (idBytes == null && label == null) {
        throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
      }

      SignerConf conf = new SignerConf().setParallelism(1).setSlot(Integer.parseInt(slotIndex));
      if (StringUtil.isNotBlank(moduleName)) {
        conf.setModule(moduleName);
      }
      if (idBytes != null) {
        conf.setKeyId(idBytes);
      }
      if (label != null) {
        conf.setKeyLabel(label);
      }
      if (Boolean.TRUE.equals(rsaPss)) {
        conf.setMode(SignAlgoMode.RSAPSS);
      }
      conf.setPeerCertificates(getPeerCertificates());
      return securities().securityFactory().createSigner("PKCS11", conf, (X509Cert) null);
    }
  }

  @Command(name = "csr-p12", description = "generate CSR with PKCS#12 keystore",
      mixinStandardHelpOptions = true)
  static class CsrP12Command extends CsrGenCommand {

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 keystore file")
    private String passwordHint;

    @Option(names = "--rsa-pss", description = "whether to use RSAPSS for POP")
    private Boolean rsaPss = Boolean.FALSE;

    private char[] getPassword() throws IOException, PasswordResolverException {
      return readPasswordIfNotSet("Enter the keystore password", passwordHint);
    }

    @Override
    protected ConcurrentSigner getSigner() throws ObjectCreationException {
      try {
        SignerConf conf = new SignerConf()
            .setPassword(new String(getPassword())).setParallelism(1)
            .setKeystore("file:" + p12File);
        if (Boolean.TRUE.equals(rsaPss)) {
          conf.setMode(SignAlgoMode.RSAPSS);
        }
        conf.setPeerCertificates(getPeerCertificates());
        return securities().securityFactory().createSigner("PKCS12", conf, (X509Cert) null);
      } catch (IOException | PasswordResolverException ex) {
        throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
      } catch (Exception ex) {
        if (ex instanceof ObjectCreationException) {
          throw (ObjectCreationException) ex;
        }
        throw new ObjectCreationException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "validate-csr", description = "validate CSR", mixinStandardHelpOptions = true)
  static class ValidateCsrCommand extends SecurityCommands.SecurityCommand {

    @Option(names = "--csr", required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(names = "--keystore", description = "peer's keystore file")
    @Completion(FilePathCompleter.class)
    private String keystoreFile;

    @Option(names = "--keystore-type", description = "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String keystoreType = "PKCS12";

    @Option(names = "--keystore-password", description = "password of the keystore")
    private String keystorePasswordHint;

    @Override
    public void run() {
      try {
        byte[] encoded = X509Util.toDerEncoded(IoUtil.read(csrFile));
        CertificationRequest csr = X509Util.parseCsr(encoded);
        ASN1ObjectIdentifier sigAlgOid = csr.getSignatureAlgorithm().getAlgorithm();

        boolean isKemMac = OIDs.Xipki.id_alg_KEM_HMAC_SHA256.equals(sigAlgOid);
        boolean isXdh = OIDs.Xipki.id_alg_dhPop_x25519.equals(sigAlgOid)
            || OIDs.Xipki.id_alg_dhPop_x448.equals(sigAlgOid);

        if ((isKemMac || isXdh) && (keystoreFile == null || keystorePasswordHint == null)) {
          throw new IllegalArgumentException(
              "please specify --keystore and --keystore-password for this CSR type");
        }

        DHSigStaticKeyCertPair peerKeyAndCert = null;
        SecretKey peerMasterKey = null;

        if (isKemMac) {
          KemHmacSignature kemHmacSig = KemHmacSignature.decode(csr.getSignature().getOctets());
          peerMasterKey = readSecretKeyFromKeystore(
              keystoreFile, kemHmacSig.id(), keystorePasswordHint);
          if (peerMasterKey == null) {
            throw new IOException("could not find peer KEM key entry to verify the CSR");
          }
        } else if (isXdh) {
          if (!StringUtil.orEqualsIgnoreCase(keystoreType, "PKCS12", "PKCS#12")) {
            throw new IllegalArgumentException("keystoreType is not PKCS12: " + keystoreType);
          }

          EcCurveEnum requiredKeyAlg = OIDs.Xipki.id_alg_dhPop_x25519.equals(sigAlgOid)
              ? EcCurveEnum.X25519 : EcCurveEnum.X448;

          char[] password = Passwords.resolvePassword(keystorePasswordHint);
          File file = IoUtil.expandFilepath(new File(keystoreFile));
          try (InputStream is = Files.newInputStream(file.toPath())) {
            PKCS12KeyStore ks = KeyUtil.loadPKCS12KeyStore(is, password);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
              String alias = aliases.nextElement();
              if (!ks.isKeyEntry(alias)) {
                continue;
              }

              PrivateKeyInfo keyInfo = ks.getKey(alias);
              if (requiredKeyAlg == EcCurveEnum.ofOid(
                  keyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
                PrivateKey key = KeyUtil.getPrivateKey(keyInfo);
                peerKeyAndCert = new DHSigStaticKeyCertPair(key,
                                    new X509Cert(ks.getCertificate(alias)));
                break;
              }
            }
          }

          if (peerKeyAndCert == null) {
            throw new IOException("could not find peer key entry to verify the CSR");
          }
        }

        boolean valid = securities().securityFactory().verifyPop(
            csr, null, peerKeyAndCert, peerMasterKey);
        SignAlgo signAlgo = SignAlgo.getInstance(csr.getSignatureAlgorithm());
        println("The POP is " + (valid ? "" : "in") + "valid (signature algorithm "
            + signAlgo.jceName() + ").");
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private SecretKey readSecretKeyFromKeystore(
        String ksFile, String alias, String passwordHint) throws Exception {
      char[] password = Passwords.resolvePassword(passwordHint);
      try (InputStream is = Files.newInputStream(
          IoUtil.expandFilepath(new File(ksFile)).toPath())) {
        KeyStore ks = KeyUtil.loadKeyStore("JCEKS", is, password);
        if (!ks.isKeyEntry(alias)) {
          return null;
        }
        return (SecretKey) ks.getKey(alias, password);
      }
    }
  }
}
