// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
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
import org.xipki.security.*;
import org.xipki.security.encap.KemEncapKey;
import org.xipki.security.exception.BadInputException;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.exception.ObjectCreationException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * @author Lijun Liao (xipki)
 */
public class CsrActions {

  public static abstract class CsrGen extends SecurityActions.SecurityAction {

    @Option(name = "--subject-alt-name", aliases = "--san", multiValued = true,
        description =
            "subjectAltName, in the form of [tagNo]value or [tagText]value. " +
            "Valid tagNo/tagText/value:\n" +
            " '0'/'othername'/OID=[DirectoryStringChoice:]value,\n" +
            "    valid DirectoryStringChoices are printableString and " +
                "utf8String,\n" +
            "    default to utf8Sring" +
            " '1'/'email'/text,\n" +
            " '2'/'dns'/text,\n" +
            " '4'/'dirName'/X500 name e.g. CN=abc,\n" +
            " '5'/'edi'/key=value,\n" +
            " '6'/'uri'/text,\n" +
            " '7'/'ip'/IP address,\n" +
            " '8'/'rid'/OID")
    protected List<String> subjectAltNames;

    @Option(name = "--subject-info-access", aliases = "--sia",
        multiValued = true, description = "subjectInfoAccess")
    protected List<String> subjectInfoAccesses;

    @Option(name = "--cert", description =
        "Certificate file, from which subject and extensions will be " +
            "extracted.\n" +
            "Maximal one of cert and old-cert is allowed.")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--cert-ext-exclude", multiValued = true, description =
        "OIDs of extension types which are not copied from the " +
            "--cert option to CSR.")
    private List<String> excludeCertExtns;

    @Option(name = "--cert-ext-include", multiValued = true, description =
        "OIDs of extension types which are copied from the " +
            "--cert option to CSR.")
    private List<String> includeCertExtns;

    @Option(name = "--old-cert", description =
        "Certificate file to be updated. The subject and subjectAltNames " +
            "will be copied to the CSR.\n" +
        "The subject and subject-alt-name specified here will be specified " +
            "in the changeSubjectName attribute.\n" +
        "Maximal one of cert and old-cert is allowed.")
    @Completion(FileCompleter.class)
    private String oldCertFile;

    @Option(name = "--subject", aliases = "-s", description =
        "subject in the CSR, if not set, use the subject in the signer's " +
            "certificate ")
    private String subject;

    @Option(name = "--dateOfBirth", description =
        "Date of birth YYYYMMdd in subject")
    private String dateOfBirth;

    @Option(name = "--postalAddress", multiValued = true, description =
        "postal address in subject")
    private List<String> postalAddress;

    @Option(name = "--outform", description = "output format of the CSR")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description =
        "CSR file")
    @Completion(FileCompleter.class)
    private String outputFilename;

    @Option(name = "--challenge-password", aliases = "-c", description =
        "challenge password, as plaintext or PBE-encrypted.")
    private String challengePasswordHint;

    @Option(name = "--keyusage", multiValued = true, description = "keyusage")
    @Completion(Completers.KeyusageCompleter.class)
    private List<String> keyusages;

    @Option(name = "--ext-keyusage", multiValued = true, description =
        "extended keyusage (name or OID)")
    @Completion(Completers.ExtKeyusageCompleter.class)
    private List<String> extkeyusages;

    @Option(name = "--qc-eu-limit", multiValued = true, description =
        "QC EuLimitValue of format <currency>:<amount>:<exponent>")
    private List<String> qcEuLimits;

    @Option(name = "--biometric-type", description = "Biometric type")
    private String biometricType;

    @Option(name = "--biometric-hash", description = "Biometric hash algorithm")
    @Completion(Completers.HashAlgCompleter.class)
    private String biometricHashAlgo;

    @Option(name = "--biometric-file", description = "Biometric hash algorithm")
    private String biometricFile;

    @Option(name = "--biometric-uri", description = "Biometric sourcedata URI")
    @Completion(FileCompleter.class)
    private String biometricUri;

    @Option(name = "--extensions-file", description =
        "File containing the DER-encoded Extensions.")
    @Completion(FileCompleter.class)
    private String extensionsFile;

    /**
     * Gets the signer for the give signatureAlgoControl.
     *
     * @return the signer
     * @throws Exception If getting signer failed.
     */
    protected abstract ConcurrentContentSigner getSigner() throws Exception;

    protected List<X509Cert> getPeerCertificates()
        throws ObjectCreationException {
      try {
        return securityFactory.getCsrControl().getPeerCerts();
      } catch (XiSecurityException e) {
        throw new ObjectCreationException(e);
      }
    } // method getPeerCertificates

    @Override
    protected Object execute0() throws Exception {
      if (certFile != null && oldCertFile != null) {
        throw new IllegalCmdParamException(
            "maximal one of cert and old-cert is allowed");
      }

      ConcurrentContentSigner signer = getSigner();

      SubjectPublicKeyInfo subjectPublicKeyInfo =
          (signer.getCertificate() == null)
              ? KeyUtil.createSubjectPublicKeyInfo(signer.getPublicKey())
              : signer.getCertificate().getSubjectPublicKeyInfo();

      if (extkeyusages != null) {
        List<String> list = new ArrayList<>(extkeyusages.size());
        for (String m : extkeyusages) {
          String id = Completers.ExtKeyusageCompleter.getIdForUsageName(m);
          if (id == null) {
            try {
              new ASN1ObjectIdentifier(m);
            } catch (Exception ex) {
              throw new IllegalCmdParamException(
                  "invalid extended key usage " + m);
            }
          }
        }

        extkeyusages = list;
      }

      List<Extension> extensions = new LinkedList<>();

      // SubjectInfoAccess
      ASN1OctetString extnValue = isEmpty(subjectInfoAccesses) ? null
          : X509Util.createExtnSubjectInfoAccess(subjectInfoAccesses, false)
            .getExtnValue();

      if (extnValue != null) {
        extensions.add(
            new Extension(OIDs.Extn.subjectInfoAccess, false, extnValue));
      }

      // Keyusage
      if (isNotEmpty(keyusages)) {
        Set<KeyUsage> usages = new HashSet<>();
        for (String usage : keyusages) {
          usages.add(KeyUsage.getKeyUsage(usage));
        }
        extensions.add(new Extension(OIDs.Extn.keyUsage, false,
            X509Util.createKeyUsage(usages).getEncoded()));
      }

      // ExtendedKeyusage
      if (isNotEmpty(extkeyusages)) {
        extensions.add(new Extension(OIDs.Extn.extendedKeyUsage, false,
            X509Util.createExtendedUsage(textToAsn1Oids(extkeyusages))
                .getEncoded()));
      }

      // QcEuLimitValue
      if (isNotEmpty(qcEuLimits)) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (String m : qcEuLimits) {
          StringTokenizer st = new StringTokenizer(m, ":");
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

            MonetaryValue monterayValue = new MonetaryValue(currency,
                Integer.parseInt(amountS), Integer.parseInt(exponentS));
            QCStatement statment = new QCStatement(
                OIDs.QCS.id_etsi_qcs_QcLimitValue, monterayValue);
            vec.add(statment);
          } catch (Exception ex) {
            throw new Exception("invalid qc-eu-limit '" + m + "'");
          }
        }

        extensions.add(new Extension(OIDs.Extn.qCStatements, false,
            new DERSequence(vec).getEncoded()));
      }

      // biometricInfo
      if (biometricType != null && biometricHashAlgo != null
          && biometricFile != null) {
        TypeOfBiometricData tmpBiometricType =
            StringUtil.isNumber(biometricType)
                ? new TypeOfBiometricData(Integer.parseInt(biometricType))
                : new TypeOfBiometricData(
                    new ASN1ObjectIdentifier(biometricType));

        HashAlgo ha = HashAlgo.getInstance(biometricHashAlgo);
        byte[] tmpBiometricDataHash = ha.hash(IoUtil.read(biometricFile));

        DERIA5String tmpSourceDataUri = null;
        if (biometricUri != null) {
          tmpSourceDataUri = new DERIA5String(biometricUri);
        }
        BiometricData biometricData = new BiometricData(tmpBiometricType,
            ha.getAlgorithmIdentifier(),
            new DEROctetString(tmpBiometricDataHash), tmpSourceDataUri);

        extensions.add(new Extension(OIDs.Extn.biometricInfo, false,
            new DERSequence(biometricData).getEncoded()));
      } else if (biometricType == null && biometricHashAlgo == null
          && biometricFile == null) {
        // Do nothing
      } else {
        throw new Exception("either all of biometric triples (type, hash " +
            "algo, file） must be set or none of them should be set");
      }

      List<ASN1ObjectIdentifier> addedExtnTypes =
          new ArrayList<>(extensions.size());
      for (Extension extn : extensions) {
        addedExtnTypes.add(extn.getExtnId());
      }

      // extra extensions
      if (extensionsFile != null) {
        Extensions extns = Extensions.getInstance(IoUtil.read(extensionsFile));
        for (ASN1ObjectIdentifier extnId : extns.getExtensionOIDs()) {
          if (addedExtnTypes.contains(extnId)) {
            throw new Exception("duplicated extension " + extnId.getId());
          }

          Extension extn = extns.getExtension(extnId);
          extensions.add(extn);
          addedExtnTypes.add(extnId);
        }
      }

      extensions.addAll(getAdditionalExtensions());

      char[] challengePassword = StringUtil.isBlank(challengePasswordHint)
          ? null : resolvePassword(challengePasswordHint);

      if (certFile != null) {
        Certificate cert = Certificate.getInstance(
            X509Util.toDerEncoded(IoUtil.read(certFile)));

        if (!Arrays.equals(subjectPublicKeyInfo.getEncoded(),
                cert.getSubjectPublicKeyInfo().getEncoded())) {
          throw new IllegalCmdParamException("PublicKey extracted from " +
              "signer is different than in the certificate");
        }

        Extensions certExtns = cert.getTBSCertificate().getExtensions();

        List<ASN1ObjectIdentifier> stdExcludeOids = Arrays.asList(
            OIDs.Extn.authorityKeyIdentifier,
            OIDs.Extn.authorityInfoAccess,   OIDs.Extn.certificateIssuer,
            OIDs.Extn.certificatePolicies,   OIDs.Extn.cRLDistributionPoints,
            OIDs.Extn.freshestCRL,           OIDs.Extn.nameConstraints,
            OIDs.Extn.policyMappings,        OIDs.Extn.policyConstraints,
            OIDs.Extn.certificatePolicies,   OIDs.Extn.subjectInfoAccess,
            OIDs.Extn.subjectDirectoryAttributes);

        for (ASN1ObjectIdentifier certExtnOid : certExtns.getExtensionOIDs()) {
          boolean add = !addedExtnTypes.contains(certExtnOid);
          if (add) {
            add = isNotEmpty(includeCertExtns)
                ? includeCertExtns.contains(certExtnOid.getId())
                : !stdExcludeOids.contains(certExtnOid);
          }

          if (add && isNotEmpty(excludeCertExtns)) {
            add = !excludeCertExtns.contains(certExtnOid.getId());
          }

          if (add) {
            extensions.add(certExtns.getExtension(certExtnOid));
          }
        }

        PKCS10CertificationRequest csr = generateRequest(signer,
            subjectPublicKeyInfo, cert.getSubject(), challengePassword,
            extensions);
        saveVerbose("saved CSR to file", outputFilename,
            encodeCsr(csr.getEncoded(), outform));
        return null;
      }

      final boolean updateOldCert = oldCertFile != null;

      X500Name newSubjectDn = null;
      if (subject == null) {
        if (StringUtil.isNotBlank(dateOfBirth)) {
          throw new IllegalCmdParamException(
              "dateOfBirth cannot be set if subject is not set");
        }

        if (CollectionUtil.isNotEmpty(postalAddress)) {
          throw new IllegalCmdParamException(
              "postalAddress cannot be set if subject is not set");
        }

        if (!updateOldCert) {
          X509Cert signerCert = signer.getCertificate();
          if (signerCert == null) {
            throw new IllegalCmdParamException("subject must be set");
          }
          newSubjectDn = signerCert.getSubject();
        }
      } else {
        newSubjectDn = getSubject(subject);

        List<RDN> list = new LinkedList<>();

        if (StringUtil.isNotBlank(dateOfBirth)) {
          ASN1ObjectIdentifier id = OIDs.DN.dateOfBirth;
          RDN[] rdns = newSubjectDn.getRDNs(id);

          if (rdns == null || rdns.length == 0) {
            Instant date = DateUtil.parseUtcTimeyyyyMMdd(dateOfBirth);
            date = date.plus(12, ChronoUnit.HOURS);
            list.add(new RDN(id, new DERGeneralizedTime(
                DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z")));
          }
        }

        if (CollectionUtil.isNotEmpty(postalAddress)) {
          ASN1ObjectIdentifier id = OIDs.DN.postalAddress;
          RDN[] rdns = newSubjectDn.getRDNs(id);

          if (rdns == null || rdns.length == 0) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (String m : postalAddress) {
              vec.add(new DERUTF8String(m));
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

      // SubjectAltNames
      extnValue = isEmpty(subjectAltNames) ? null
          : X509Util.createExtnSubjectAltName(subjectAltNames, false)
              .getExtnValue();
      Extension newSubjectAltNames = null;
      if (extnValue != null) {
        newSubjectAltNames = new Extension(OIDs.Extn.subjectAlternativeName,
            false, extnValue);
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
          ASN1EncodableVector v = new ASN1EncodableVector();
          v.add(newSubjectDn == null ? subjectDn : newSubjectDn);

          GeneralNames subjectAlt = null;
          if (newSubjectAltNames != null) {
            subjectAlt = GeneralNames.getInstance(
                newSubjectAltNames.getExtnValue().getOctets());
          } else if (oldSan != null) {
            subjectAlt = GeneralNames.getInstance(oldSan.getParsedValue());
          }

          if (subjectAlt != null) {
            v.add(subjectAlt);
          }

          attrChangeSubjectName = new Attribute(
              OIDs.CMC.id_cmc_changeSubjectName,
              new DERSet(new DERSequence(v)));
        }
      } else {
        subjectDn = newSubjectDn;
        if (newSubjectAltNames != null) {
          extensions.add(newSubjectAltNames);
        }
      }

      PKCS10CertificationRequest csr = generateRequest(signer,
          subjectPublicKeyInfo, subjectDn, challengePassword, extensions,
          attrChangeSubjectName);
      saveVerbose("saved CSR to file", outputFilename,
          encodeCsr(csr.getEncoded(), outform));
      return null;
    } // method execute0

    protected X500Name getSubject(String subjectText) {
      return new X500Name(Args.notBlank(subjectText, "subjectText"));
    }

    protected List<Extension> getAdditionalExtensions()
        throws BadInputException {
      return Collections.emptyList();
    }

    private static List<ASN1ObjectIdentifier> textToAsn1Oids(
        List<String> oidTexts) {
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

    private PKCS10CertificationRequest generateRequest(
        ConcurrentContentSigner signer,
        SubjectPublicKeyInfo subjectPublicKeyInfo, X500Name subjectDn,
        char[] challengePassword, List<Extension> extensions,
        Attribute... attrs) throws XiSecurityException {
      Args.notNull(signer, "signer");
      Args.notNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
      Args.notNull(subjectDn, "subjectDn");

      Map<ASN1ObjectIdentifier, ASN1Encodable> attributes = new HashMap<>();
      if (isNotEmpty(extensions)) {
        attributes.put(OIDs.PKCS9.pkcs9_at_extensionRequest,
            new Extensions(extensions.toArray(new Extension[0])));
      }

      if (challengePassword != null && challengePassword.length > 0) {
        attributes.put(OIDs.PKCS9.pkcs9_at_challengePassword,
            new DERPrintableString(new String(challengePassword)));
      }

      PKCS10CertificationRequestBuilder csrBuilder =
          new PKCS10CertificationRequestBuilder(
              subjectDn, subjectPublicKeyInfo);
      if (CollectionUtil.isNotEmpty(attributes)) {
        for (Map.Entry<ASN1ObjectIdentifier, ASN1Encodable> entry
            : attributes.entrySet()) {
          csrBuilder.addAttribute(entry.getKey(), entry.getValue());
        }
      }

      if (attrs != null) {
        for (Attribute attr : attrs) {
          if (attr != null) {
            csrBuilder.addAttribute(attr.getAttrType(),
                attr.getAttrValues().toArray());
          }
        }
      }

      XiContentSigner signer0;
      try {
        signer0 = signer.borrowSigner();
      } catch (NoIdleSignerException ex) {
        throw new XiSecurityException(ex.getMessage(), ex);
      }

      try {
        return csrBuilder.build(signer0);
      } finally {
        signer.requiteSigner(signer0);
      }
    } // method generateRequest

    protected KemEncapKey getKemEncapkey(SubjectPublicKeyInfo myPublicKey)
        throws ObjectCreationException {
      try {
        return securityFactory.getCsrControl().generateKemEncapKey(
            myPublicKey, securityFactory.getRandom4Sign());
      } catch (XiSecurityException ex) {
        throw new ObjectCreationException(
            "error computing EncapKey: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "xi", name = "csr-jce", description =
      "generate CSR request with JCE device")
  @Service
  public static class CsrJceAction extends CsrGen {

    @Option(name = "--type", required = true, description = "JCE signer type")
    private String type;

    @Option(name = "--alias", required = true, description =
        "alias of the key in the JCE device")
    private String alias;

    @Option(name = "--algo", required = true, description =
        "signature algorithm")
    @Completion(SecurityCompleters.SignAlgoCompleter.class)
    private String algo;

    @Override
    protected ConcurrentContentSigner getSigner() throws Exception {
      return getSigner(type, alias, algo, securityFactory);
    }

    static ConcurrentContentSigner getSigner(
        String type, String alias, String algo,
        SecurityFactory securityFactory) throws Exception {
      SignerConf conf = getJceSignerConf(alias, 1,
          SignAlgo.getInstance(algo));
      return securityFactory.createSigner(type, conf, (X509Cert) null);
    }

    static SignerConf getJceSignerConf(String alias, int parallelism,
                                       SignAlgo signAlgo) {
      ConfPairs conf = new ConfPairs()
          .putPair("parallelism", Integer.toString(parallelism))
          .putPair("alias", alias)
          .putPair("algo", signAlgo.getJceName());
      return new SignerConf(conf);
    }

  }

  @Command(scope = "xi", name = "csr-p11", description =
      "generate CSR request with PKCS#11 device")
  @Service
  public static class CsrP11Action extends CsrGen {

    @Option(name = "--slot", description = "slot index")
    private String slotIndex = "0";
    // use String instead int so that the default value 0 will be shown in
    // the help.

    @Option(name = "--id", description =
        "id (hex) of the private key in the PKCS#11 device\n" +
        "either keyId or keyLabel must be specified")
    private String id;

    @Option(name = "--label", description =
        "label of the private key in the PKCS#11 device\n" +
        "either keyId or keyLabel must be specified")
    private String label;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Option(name = "--rsa-pss", description =
        "whether to use the RSAPSS for the POP computation\n" +
        "(only applied to RSA key)")
    private Boolean rsaPss = Boolean.FALSE;

    @Override
    protected ConcurrentContentSigner getSigner() throws Exception {
      SignAlgoMode mode = (rsaPss != null && rsaPss)
          ? SignAlgoMode.RSAPSS : null;
      return getSigner(moduleName, slotIndex, id, label, mode, securityFactory);
    }

    ConcurrentContentSigner getSigner(
        String moduleName, String slotIndex, String id, String label,
        SignAlgoMode mode, SecurityFactory securityFactory) throws Exception {
      byte[] idBytes = null;
      if (id != null) {
        idBytes = Hex.decode(id);
      }

      SignerConf conf = getPkcs11SignerConf(moduleName,
          Integer.parseInt(slotIndex), label, idBytes, 1, null, mode);
      return securityFactory.createSigner("PKCS11", conf, (X509Cert) null);
    }

    private SignerConf getPkcs11SignerConf(
        String pkcs11ModuleName, int slotIndex, String keyLabel, byte[] keyId,
        int parallelism, HashAlgo hashAlgo, SignAlgoMode mode)
            throws ObjectCreationException {
      Args.positive(parallelism, "parallelism");

      if (keyId == null && keyLabel == null) {
        throw new IllegalArgumentException(
            "at least one of keyId and keyLabel may not be null");
      }

      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(parallelism));

      if (pkcs11ModuleName != null && !pkcs11ModuleName.isEmpty()) {
        conf.putPair("module", pkcs11ModuleName);
      }

      conf.putPair("slot", Integer.toString(slotIndex));

      if (keyId != null) {
        conf.putPair("key-id", Hex.encode(keyId));
      }

      if (keyLabel != null) {
        conf.putPair("key-label", keyLabel);
      }

      if (mode != null) {
        conf.putPair("mode", mode.name());
      }

      if (hashAlgo != null) {
        conf.putPair("hash", hashAlgo.getJceName());
      }

      SignerConf signerConf = new SignerConf(conf);
      if (rsaPss != null && rsaPss) {
        signerConf.setMode(SignAlgoMode.RSAPSS);
      }
      signerConf.setPeerCertificates(getPeerCertificates());
      return signerConf;
    }

  }

  @Command(scope = "xi", name = "csr-p12", description =
      "generate CSR with PKCS#12 keystore")
  @Service
  public static class CsrP12Action extends CsrGen {

    @Option(name = "--p12", required = true, description =
        "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description =
        "password of the PKCS#12 keystore file, as plaintext or PBE-encrypted.")
    private String passwordHint;

    @Option(name = "--rsa-pss", description =
        "whether to use the RSAPSS for the POP computation\n"
        + "(only applied to RSA key)")
    private Boolean rsaPss = Boolean.FALSE;

    private char[] password;

    private char[] getPassword() throws IOException, PasswordResolverException {
      if (password == null) {
        password = readPasswordIfNotSet("Enter the keystore password",
            passwordHint);
      }
      return password;
    }

    @Override
    protected ConcurrentContentSigner getSigner()
        throws ObjectCreationException {
      char[] pwd;
      try {
        pwd = getPassword();
      } catch (IOException | PasswordResolverException ex) {
        throw new ObjectCreationException(
            "could not read password: " + ex.getMessage(), ex);
      }

      SignerConf conf = new SignerConf()
          .setPassword(new String(pwd))
          .setParallelism(1)
          .setKeystore("file:" + p12File);
      if (rsaPss != null && rsaPss) {
        conf.setMode(SignAlgoMode.RSAPSS);
      }

      conf.setPeerCertificates(getPeerCertificates());
      return securityFactory.createSigner("PKCS12", conf,
          (X509Cert) null);
    }

  }

  @Command(scope = "xi", name = "validate-csr", description = "validate CSR")
  @Service
  public static class ValidateCsrAction extends SecurityActions.SecurityAction {

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--keystore", description = "peer's keystore file")
    @Completion(FileCompleter.class)
    private String keystoreFile;

    @Option(name = "--keystore-type", description = "type of the keystore")
    @Completion(SecurityCompleters.KeystoreTypeCompleter.class)
    private String keystoreType = "PKCS12";

    @Option(name = "--keystore-password", description =
        "password of the keystore, as plaintext or PBE-encrypted.")
    private String keystorePasswordHint;

    @Override
    protected Object execute0() throws Exception {
      byte[] encoded = X509Util.toDerEncoded(IoUtil.read(csrFile));

      CertificationRequest csr = X509Util.parseCsr(encoded);

      ASN1ObjectIdentifier sigAlgOid =
          csr.getSignatureAlgorithm().getAlgorithm();

      boolean isKemMac = OIDs.Xipki.id_alg_KEM_HMAC_SHA256.equals(sigAlgOid);

      boolean isXdh =
          OIDs.Xipki.id_alg_dhPop_x25519.equals(sigAlgOid) ||
              OIDs.Xipki.id_alg_dhPop_x448.equals(sigAlgOid);

      if (isKemMac || isXdh) {
        if (keystoreFile == null || keystorePasswordHint == null) {
          System.err.println("could not verify CSR, please specify the " +
              "peer's master key keystore");
          return null;
        }
      }

      DHSigStaticKeyCertPair peerKeyAndCert = null;
      SecretKey peerMasterKey = null;

      if (isKemMac) {
        String id;
        // ignore the keystore type
        /*
         * See org.xipki.security.kemgmac.P12KemMacContentSignerBuilder
         */
        ASN1Sequence seq = ASN1Sequence.getInstance(
            csr.getSignature().getBytes());

        id = ASN1UTF8String.getInstance(seq.getObjectAt(0)).getString();
        peerMasterKey = readSecretKeyFromKeystore(keystoreFile, id,
            keystorePasswordHint);
        if (peerMasterKey == null) {
          System.err.println(
              "could not find peer KEM key entry to verify the CSR");
          return null;
        }
      } else if (isXdh) {
        EcCurveEnum requiredKeyAlg =
            OIDs.Xipki.id_alg_dhPop_x25519.equals(sigAlgOid)
              ? EcCurveEnum.X25519 : EcCurveEnum.X448;

        char[] password = readPasswordIfNotSet(
            "Enter the keystore password", keystorePasswordHint);
        KeyStore ks = KeyUtil.getInKeyStore(keystoreType);

        File file = IoUtil.expandFilepath(new File(keystoreFile));
        try (InputStream is = Files.newInputStream(file.toPath())) {
          ks.load(is, password);

          Enumeration<String> aliases = ks.aliases();
          while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!ks.isKeyEntry(alias)) {
              continue;
            }

            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            if (EcCurveEnum.ofAlias(key.getAlgorithm()) == requiredKeyAlg) {
              peerKeyAndCert = new DHSigStaticKeyCertPair(key,
                  new X509Cert((X509Certificate) ks.getCertificate(alias)));
              break;
            }
          }
        }

        if (peerKeyAndCert == null) {
          System.err.println("could not find peer key entry to verify the CSR");
          return null;
        }
      }

      boolean bo = securityFactory.verifyPop(csr, null,
          peerKeyAndCert, peerMasterKey);
      SignAlgo signAlgo = SignAlgo.getInstance(csr.getSignatureAlgorithm());
      println("The POP is " + (bo ? "" : "in") + "valid (signature algorithm "
          + signAlgo.getJceName() + ").");
      return null;
    }

  } // method ValidateCsr
}
