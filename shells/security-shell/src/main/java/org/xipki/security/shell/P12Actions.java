/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.security.shell;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.xipki.security.BadInputException;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs12.KeystoreGenerationParameters;
import org.xipki.security.pkcs12.P12KeyGenerationResult;
import org.xipki.security.pkcs12.P12KeyGenerator;
import org.xipki.security.shell.Actions.CsrGenAction;
import org.xipki.security.shell.Actions.SecurityAction;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Args;
import org.xipki.util.ConfPairs;
import org.xipki.util.ObjectCreationException;

/**
 * TODO.
 * @author Lijun Liao
 */

public class P12Actions {

  @Command(scope = "xi", name = "secretkey-p12",
      description = "generate secret key in JCEKS (not PKCS#12) keystore")
  @Service
  public static class SecretkeyP12 extends P12KeyGenAction {

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
     private String keyType;

    @Option(name = "--key-size", required = true, description = "keysize in bit")
    private Integer keysize;

    @Override
    protected Object execute0() throws Exception {
      if (!("AES".equalsIgnoreCase(keyType) || "DES3".equalsIgnoreCase(keyType)
            || "GENERIC".equalsIgnoreCase(keyType))) {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      P12KeyGenerationResult key = new P12KeyGenerator().generateSecretKey(
          keyType.toUpperCase(), keysize, getKeyGenParameters());
      saveKey(key);

      return null;
    }

  }

  @Command(scope = "xi", name = "export-cert-p12",
      description = "export certificate from PKCS#12 keystore")
  @Service
  public static class ExportCertP12 extends P12SecurityAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      KeyStore ks = getKeyStore();

      String keyname = null;
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (ks.isKeyEntry(alias)) {
          keyname = alias;
          break;
        }
      }

      if (keyname == null) {
        throw new CmdFailure("could not find private key");
      }

      X509Certificate cert = (X509Certificate) ks.getCertificate(keyname);
      saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(), outform));

      return null;
    }

  }

  @Command(scope = "xi", name = "update-cert-p12",
      description = "update certificate in PKCS#12 keystore")
  @Service
  public static class UpdateCertP12 extends P12SecurityAction {

    @Option(name = "--cert", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--ca-cert", multiValued = true, description = "CA Certificate file")
    @Completion(FileCompleter.class)
    private Set<String> caCertFiles;

    @Override
    protected Object execute0() throws Exception {
      KeyStore ks = getKeyStore();

      char[] pwd = getPassword();
      X509Certificate newCert = X509Util.parseCert(new File(certFile));

      assertMatch(newCert, new String(pwd));

      String keyname = null;
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (ks.isKeyEntry(alias)) {
          keyname = alias;
          break;
        }
      }

      if (keyname == null) {
        throw new XiSecurityException("could not find private key");
      }

      Key key = ks.getKey(keyname, pwd);
      Set<X509Certificate> caCerts = new HashSet<>();
      if (isNotEmpty(caCertFiles)) {
        for (String caCertFile : caCertFiles) {
          caCerts.add(X509Util.parseCert(new File(caCertFile)));
        }
      }
      X509Certificate[] certChain = X509Util.buildCertPath(newCert, caCerts);
      ks.setKeyEntry(keyname, key, pwd, certChain);

      try (OutputStream out = Files.newOutputStream(Paths.get(p12File))) {
        ks.store(out, pwd);
        println("updated certificate");
        return null;
      }
    }

    private void assertMatch(X509Certificate cert, String password)
        throws ObjectCreationException {
      ConfPairs pairs = new ConfPairs("keystore", "file:" + p12File);
      if (password != null) {
        pairs.putPair("password", new String(password));
      }

      SignerConf conf = new SignerConf(pairs.getEncoded(), HashAlgo.SHA256, null);
      securityFactory.createSigner("PKCS12", conf, cert);
    }

  }

  @Command(scope = "xi", name = "csr-p12-complex",
      description = "generate complex CSR with PKCS#12 keystore (only for test)")
  @Service
  public static class CsrP12Complex extends CsrGenAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 keystore file")
    private String password;

    @Option(name = "--complex-subject", description = "whether complex subject should be used")
    private Boolean complexSubject = Boolean.FALSE;

    private char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

    public KeyStore getKeyStore()
        throws IOException, KeyStoreException, NoSuchProviderException,
          NoSuchAlgorithmException, CertificateException {
      KeyStore ks;
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        ks = KeyUtil.getKeyStore("PKCS12");
        ks.load(in, getPassword());
      }
      return ks;
    }

    @Override
    protected ConcurrentContentSigner getSigner(SignatureAlgoControl signatureAlgoControl)
        throws ObjectCreationException {
      Args.notNull(signatureAlgoControl, "signatureAlgoControl");
      char[] pwd;
      try {
        pwd = getPassword();
      } catch (IOException ex) {
        throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
      }
      SignerConf signerConf = CsrP12.getKeystoreSignerConf(p12File, new String(pwd),
          HashAlgo.getNonNullInstance(hashAlgo), signatureAlgoControl);
      return securityFactory.createSigner("PKCS12", signerConf, (X509Certificate[]) null);
    }

    @Override
    protected X500Name getSubject(String subject) {
      X500Name name = new X500Name(subject);
      List<RDN> list = new LinkedList<>();
      RDN[] rs = name.getRDNs();
      for (RDN m : rs) {
        list.add(m);
      }

      ASN1ObjectIdentifier id;

      // dateOfBirth
      if (complexSubject.booleanValue()) {
        id = ObjectIdentifiers.DN_DATE_OF_BIRTH;
        RDN[] rdns = name.getRDNs(id);

        if (rdns == null || rdns.length == 0) {
          ASN1Encodable atvValue = new DERGeneralizedTime("19950102120000Z");
          RDN rdn = new RDN(id, atvValue);
          list.add(rdn);
        }
      }

      // postalAddress
      if (complexSubject.booleanValue()) {
        id = ObjectIdentifiers.DN_POSTAL_ADDRESS;
        RDN[] rdns = name.getRDNs(id);

        if (rdns == null || rdns.length == 0) {
          ASN1EncodableVector vec = new ASN1EncodableVector();
          vec.add(new DERUTF8String("my street 1"));
          vec.add(new DERUTF8String("12345 Germany"));

          ASN1Sequence atvValue = new DERSequence(vec);
          RDN rdn = new RDN(id, atvValue);
          list.add(rdn);
        }
      }

      // DN_UNIQUE_IDENTIFIER
      id = ObjectIdentifiers.DN_UNIQUE_IDENTIFIER;
      RDN[] rdns = name.getRDNs(id);

      if (rdns == null || rdns.length == 0) {
        DERUTF8String atvValue = new DERUTF8String("abc-def-ghi");
        RDN rdn = new RDN(id, atvValue);
        list.add(rdn);
      }

      return new X500Name(list.toArray(new RDN[0]));
    }

    @Override
    protected ASN1OctetString createExtnValueSubjectAltName() throws BadInputException {
      if (!isEmpty(subjectAltNames)) {
        throw new BadInputException("subjectAltNames must be null");
      }
      GeneralNames names = createComplexGeneralNames("SAN-");
      try {
        return new DEROctetString(names);
      } catch (IOException ex) {
        throw new BadInputException(ex.getMessage(), ex);
      }
    }

    @Override
    protected ASN1OctetString createExtnValueSubjectInfoAccess() throws BadInputException {
      if (!isEmpty(subjectInfoAccesses)) {
        throw new BadInputException("subjectInfoAccess must be null");
      }
      ASN1EncodableVector vec = new ASN1EncodableVector();

      GeneralName[] names = createComplexGeneralNames("SIA-").getNames();

      ASN1EncodableVector vec2 = new ASN1EncodableVector();
      vec2.add(ObjectIdentifiers.id_ad_caRepository);
      vec2.add(names[0]);
      vec.add(new DERSequence(vec2));

      for (int i = 1; i < names.length; i++) {
        vec2 = new ASN1EncodableVector();
        vec2.add(new ASN1ObjectIdentifier("2.3.4." + i));
        vec2.add(names[i]);
        vec.add(new DERSequence(vec2));
      }

      try {
        return new DEROctetString(new DERSequence(vec));
      } catch (IOException ex) {
        throw new BadInputException(ex.getMessage(), ex);
      }
    }

    private static GeneralNames createComplexGeneralNames(String prefix) {
      List<GeneralName> list = new LinkedList<>();
      // otherName
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new ASN1ObjectIdentifier("1.2.3.1"));
      vec.add(new DERTaggedObject(true, 0, new DERUTF8String(prefix + "I am otherName 1.2.3.1")));
      list.add(new GeneralName(GeneralName.otherName, new DERSequence(vec)));

      vec = new ASN1EncodableVector();
      vec.add(new ASN1ObjectIdentifier("1.2.3.2"));
      vec.add(new DERTaggedObject(true, 0, new DERUTF8String(prefix + "I am otherName 1.2.3.2")));
      list.add(new GeneralName(GeneralName.otherName, new DERSequence(vec)));

      // rfc822Name
      list.add(new GeneralName(GeneralName.rfc822Name, prefix + "info@example.org"));

      // dNSName
      list.add(new GeneralName(GeneralName.dNSName, prefix + "dns.example.org"));

      // directoryName
      list.add(new GeneralName(GeneralName.directoryName, new X500Name("CN=demo,C=DE")));

      // ediPartyName
      vec = new ASN1EncodableVector();
      vec.add(new DERTaggedObject(false, 0, new DirectoryString(prefix + "assigner1")));
      vec.add(new DERTaggedObject(false, 1, new DirectoryString(prefix + "party1")));
      list.add(new GeneralName(GeneralName.ediPartyName, new DERSequence(vec)));

      // uniformResourceIdentifier
      list.add(new GeneralName(GeneralName.uniformResourceIdentifier,
          prefix + "uri.example.org"));

      // iPAddress
      list.add(new GeneralName(GeneralName.iPAddress, "69.1.2.190"));

      // registeredID
      list.add(new GeneralName(GeneralName.registeredID, "2.3.4.5"));

      return new GeneralNames(list.toArray(new GeneralName[0]));
    }

    @Override
    protected List<Extension> getAdditionalExtensions() throws BadInputException {
      List<Extension> extensions = new LinkedList<>();

      // extension admission (Germany standard commonpki)
      ASN1EncodableVector vec = new ASN1EncodableVector();

      DirectoryString[] dummyItems = new DirectoryString[]{new DirectoryString("dummy")};
      ProfessionInfo pi = new ProfessionInfo(null, dummyItems, null, "aaaab", null);
      Admissions admissions = new Admissions(null, null, new ProfessionInfo[]{pi});
      vec.add(admissions);

      AdmissionSyntax adSyn = new AdmissionSyntax(null, new DERSequence(vec));

      try {
        extensions.add(new Extension(ObjectIdentifiers.id_extension_admission, false,
            adSyn.getEncoded()));
      } catch (IOException ex) {
        throw new BadInputException(ex.getMessage(), ex);
      }

      // extension subjectDirectoryAttributes (RFC 3739)
      Vector<Attribute> attrs = new Vector<>();
      ASN1GeneralizedTime dateOfBirth = new ASN1GeneralizedTime("19800122120000Z");
      attrs.add(new Attribute(ObjectIdentifiers.DN_DATE_OF_BIRTH, new DERSet(dateOfBirth)));

      DERPrintableString gender = new DERPrintableString("M");
      attrs.add(new Attribute(ObjectIdentifiers.DN_GENDER, new DERSet(gender)));

      DERUTF8String placeOfBirth = new DERUTF8String("Berlin");
      attrs.add(new Attribute(ObjectIdentifiers.DN_PLACE_OF_BIRTH, new DERSet(placeOfBirth)));

      String[] countryOfCitizenshipList = {"DE", "FR"};
      for (String country : countryOfCitizenshipList) {
        DERPrintableString val = new DERPrintableString(country);
        attrs.add(new Attribute(ObjectIdentifiers.DN_COUNTRY_OF_CITIZENSHIP,
            new DERSet(val)));
      }

      String[] countryOfResidenceList = {"DE"};
      for (String country : countryOfResidenceList) {
        DERPrintableString val = new DERPrintableString(country);
        attrs.add(new Attribute(ObjectIdentifiers.DN_COUNTRY_OF_RESIDENCE,
            new DERSet(val)));
      }

      SubjectDirectoryAttributes subjectDirAttrs = new SubjectDirectoryAttributes(attrs);
      try {
        extensions.add(new Extension(Extension.subjectDirectoryAttributes, false,
            subjectDirAttrs.getEncoded()));
      } catch (IOException ex) {
        throw new BadInputException(ex.getMessage(), ex);
      }

      return extensions;
    }

  }

  @Command(scope = "xi", name = "csr-p12", description = "generate CSR with PKCS#12 keystore")
  @Service
  public static class CsrP12 extends CsrGenAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 keystore file")
    private String password;

    private char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

    public KeyStore getKeyStore()
        throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
      KeyStore ks;
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        ks = KeyUtil.getKeyStore("PKCS12");
        ks.load(in, getPassword());
      }
      return ks;
    }

    @Override
    protected ConcurrentContentSigner getSigner(SignatureAlgoControl signatureAlgoControl)
        throws ObjectCreationException {
      Args.notNull(signatureAlgoControl, "signatureAlgoControl");
      char[] pwd;
      try {
        pwd = getPassword();
      } catch (IOException ex) {
        throw new ObjectCreationException("could not read password: " + ex.getMessage(), ex);
      }
      SignerConf conf = getKeystoreSignerConf(p12File, new String(pwd),
          HashAlgo.getNonNullInstance(hashAlgo), signatureAlgoControl);
      return securityFactory.createSigner("PKCS12", conf, (X509Certificate[]) null);
    }

    static SignerConf getKeystoreSignerConf(String keystoreFile, String password,
        HashAlgo hashAlgo, SignatureAlgoControl signatureAlgoControl) {
      ConfPairs conf = new ConfPairs("password", password);
      conf.putPair("parallelism", Integer.toString(1));
      conf.putPair("keystore", "file:" + keystoreFile);
      return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    }

  }

  @Command(scope = "xi", name = "dsa-p12", description = "generate RSA keypair in PKCS#12 keystore")
  @Service
  public static class DsaP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    private String subject;

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected Object execute0() throws Exception {
      if (plen % 1024 != 0) {
        throw new IllegalCmdParamException("plen is not multiple of 1024: " + plen);
      }

      if (qlen == null) {
        if (plen <= 1024) {
          qlen = 160;
        } else if (plen <= 2048) {
          qlen = 224;
        } else {
          qlen = 256;
        }
      }

      P12KeyGenerationResult keypair = new P12KeyGenerator().generateDSAKeypair(plen,
          qlen, getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    }

  }

  @Command(scope = "xi", name = "ec-p12", description = "generate EC keypair in PKCS#12 keystore")
  @Service
  public static class EcP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    protected String subject;

    @Option(name = "--curve", description = "EC curve name or OID")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName = "secp256r1";

    @Override
    protected Object execute0() throws Exception {
      P12KeyGenerationResult keypair = new P12KeyGenerator().generateECKeypair(curveName,
          getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    }

  }

  public abstract static class P12KeyGenAction extends SecurityAction {

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the key")
    @Completion(FileCompleter.class)
    protected String keyOutFile;

    @Option(name = "--password", description = "password of the keystore file")
    protected String password;

    protected void saveKey(P12KeyGenerationResult keyGenerationResult) throws IOException {
      Args.notNull(keyGenerationResult, "keyGenerationResult");
      saveVerbose("saved PKCS#12 keystore to file", keyOutFile, keyGenerationResult.keystore());
    }

    protected KeystoreGenerationParameters getKeyGenParameters() throws IOException {
      KeystoreGenerationParameters params = new KeystoreGenerationParameters(getPassword());

      SecureRandom random = securityFactory.getRandom4Key();
      if (random != null) {
        params.setRandom(random);
      }

      return params;
    }

    private char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

  }

  @Command(scope = "xi", name = "rsa-p12", description = "generate RSA keypair in PKCS#12 keystore")
  @Service
  public static class RsaP12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    private String subject;

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Override
    protected Object execute0() throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 1024: " + keysize);
      }

      P12KeyGenerationResult keypair = new P12KeyGenerator().generateRSAKeypair(keysize,
          toBigInt(publicExponent), getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    }

  }

  public abstract static class P12SecurityAction extends SecurityAction {

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    protected String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 file")
    protected String password;

    protected char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

    protected KeyStore getKeyStore()
        throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
          NoSuchProviderException {
      KeyStore ks;
      try (InputStream in = Files.newInputStream(Paths.get(expandFilepath(p12File)))) {
        ks = KeyUtil.getKeyStore("PKCS12");
        ks.load(in, getPassword());
      }
      return ks;
    }

  }

  @Command(scope = "xi", name = "sm2-p12",
      description = "generate SM2 (curve sm2p256v1) keypair in PKCS#12 keystore")
  @Service
  public static class Sm2P12 extends P12KeyGenAction {

    @Option(name = "--subject", aliases = "-s",
        description = "subject of the self-signed certificate")
    protected String subject;

    @Override
    protected Object execute0() throws Exception {
      P12KeyGenerationResult keypair = new P12KeyGenerator().generateECKeypair(
          GMObjectIdentifiers.sm2p256v1.getId(), getKeyGenParameters(), subject);
      saveKey(keypair);

      return null;
    }

  }

}
