// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.asn1.ccc.EndpointCertificateExtensionSchema;
import org.xipki.asn1.ccc.InstanceCACertificateExtensionSchema;
import org.xipki.asn1.ccc.SBxDKisCertificateExtensionSchema;
import org.xipki.asn1.cert.HardwareModuleName;
import org.xipki.asn1.rpki.*;
import org.xipki.asn1.spdm.DmtfDeviceInfo;
import org.xipki.asn1.stir.TNAuthorizationList;
import org.xipki.asn1.stir.TNEntry;
import org.xipki.asn1.stir.TelephoneNumberRange;
import org.xipki.asn1.tcg.*;
import org.xipki.asn1.x500.DirectoryString;
import org.xipki.asn1.x500.X500Name;
import org.xipki.asn1.x509.Attribute;
import org.xipki.asn1.x509.Extension;
import org.xipki.asn1.x509.Extensions;
import org.xipki.asn1.x509.GeneralName;
import org.xipki.asn1.x509.GeneralNames;
import org.xipki.asn1.x509.IssuerSerial;
import org.xipki.asn1.x509.OtherName;
import org.xipki.asn1.x509.SubjectDirectoryAttributes;
import org.xipki.asn1.x509.qualified.BiometricData;
import org.xipki.asn1.x509.qualified.BiometricSyntax;
import org.xipki.asn1.x509.qualified.Iso4217CurrencyCode;
import org.xipki.asn1.x509.qualified.MonetaryValue;
import org.xipki.asn1.x509.qualified.QCStatement;
import org.xipki.asn1.x509.qualified.QCStatements;
import org.xipki.asn1.x509.qualified.TypeOfBiometricData;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Utf8String;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.IPAddressFamily;
import org.xipki.codec.util.IoUtil;
import org.xipki.codec.util.Rfc3779IPAddress;
import org.xipki.codec.util.StringUtil;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.x509.id.TcgOIDs;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Generate file containing the DER-encoded Extensions.
 *
 * @author Lijun Liao (xipki)
 */
public class GenerateX509ExtensionsDemo {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  public static void main(String[] args) {
    try {
      saveExtensions("ccc-e.der", generateCCC_E_Instance_CA());
      saveExtensions("ccc-h.der", generateCCC_H_Endpoint());
      saveExtensions("ccc-t.der", generateCCC_T_SBxDKis_Endpoint());
      saveExtensions("spdm.der",  generateSPDM());
      saveExtensions("stir.der",  generateSTIR());
      saveExtensions("rpki.der",  generateRPKI());
      saveExtensions("rfc3739.der", generateRfc3739());
      saveExtensions("tcg.der",   generateTCG());
      saveExtensions("caliptra.der", generateCaliptra());
      saveExtensions("ee-complex.der", generateEeComplex());
      saveExtensions("gmt0015.der", generateGmt0015());
      saveExtensions("microsoft.der", generateMicrosoft());
      saveExtensions("othernames.der", generateOthernames());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void saveExtensions(String filename, Extensions extns)
      throws IOException {
    IoUtil.save("target/extensions/" + filename, extns.getEncoded());
  }

  private static byte[] fixedBytes(int len, int value) {
    byte[] ret = new byte[len];
    Arrays.fill(ret, (byte) value);
    return ret;
  }

  private static Extensions generateCCC_E_Instance_CA()  {
    InstanceCACertificateExtensionSchema schema = new InstanceCACertificateExtensionSchema(
        1, fixedBytes(4, 0x12), null);
    return new Extensions(Extension.ofCCC_E_Instance_CACert(true, schema));
  }

  private static Extensions generateCCC_H_Endpoint() throws Exception {
    KeyPairGenerator kpGen = cryptoApi.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec("P-256"));
    SubjectPublicKeyInfo vehiclePK = SubjectPublicKeyInfo.fromPublicKey(
        kpGen.generateKeyPair().getPublic());
    EndpointCertificateExtensionSchema schema = new EndpointCertificateExtensionSchema(
        1, fixedBytes(8, 0x23), (byte) 3, (byte) 4,
        fixedBytes(2, 11), vehiclePK, fixedBytes(2, 0x45));
    return new Extensions(Extension.ofCCC_H_EndpointCert(true, schema));
  }

  private static Extensions generateCCC_T_SBxDKis_Endpoint() {
    SBxDKisCertificateExtensionSchema schema = new SBxDKisCertificateExtensionSchema(
        fixedBytes(4, 0x12),  fixedBytes(4, 0x34),  fixedBytes(4, 0x56));
    return new Extensions(Extension.ofCCC_T_SBxDKisEndpointCert(true, schema));
  }

  private static Extensions generateSPDM() throws CodecException {
    OtherName otherName = OtherName.ofDmtfDeviceInfo(
        new DmtfDeviceInfo("my-manufacturer:my-product:my-serialNumber"));
    GeneralName altName = GeneralName.ofOtherName(otherName);
    GeneralNames altNames = new GeneralNames(altName);
    return new Extensions(Extension.ofSubjectAlternativeName(false, altNames));
  }

  private static Extensions generateSTIR() {
    List<TNEntry> entries = new LinkedList<>();
    entries.add(TNEntry.ofSpc("my-spc"));
    entries.add(TNEntry.ofOne("1234"));

    entries.add(TNEntry.ofRange(new TelephoneNumberRange("2345", BigInteger.valueOf(10))));
    TNAuthorizationList tnAuthList = new TNAuthorizationList(entries);
    return new Extensions(Extension.ofTNAuthList(false, tnAuthList));
  }

  private static Extensions generateRPKI() throws CodecException {
    List<Extension> extensions = new LinkedList<>();
    extensions.add(Extension.ofASIdentifiers(false, buildASIdentifiers()));

    ASIdentifierChoice asnum = ASIdentifierChoice.ofInherit();
    extensions.add(Extension.ofASIdentifiersV2(false, new ASIdentifiers(asnum, null)));

    extensions.add(Extension.ofIPAddrBlocks(false,
        buildIPAddrBlocks(true, null, false)));

    extensions.add(Extension.ofIPAddrBlocksV2(false,
        buildIPAddrBlocks(false, IPAddressFamily.SAFI_unicast, true)));

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  static ASIdentifiers buildASIdentifiers() {
    ASIdentifierChoice asnum = ASIdentifierChoice.ofAsIdsOrRanges(
        new ASIdOrRange.Seq0(ASIdOrRange.ofId(BigInteger.valueOf(2))));

    ASIdentifierChoice rdi = ASIdentifierChoice.ofAsIdsOrRanges(
        new ASIdOrRange.Seq0(
            ASIdOrRange.ofRange(new ASRange(BigInteger.valueOf(3), BigInteger.valueOf(6)))));
    return new ASIdentifiers(asnum, rdi);
  }

  static IPAddrBlocks buildIPAddrBlocks(
      boolean inherit, Byte safi, boolean withLongIPv6Bytes) throws CodecException {
    if (inherit) {
      IPAddressChoice ioAddrChoice = IPAddressChoice.ofInherit();
      return new IPAddrBlocks(
          new Asn1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv6, safi),
              ioAddrChoice),
          new Asn1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv4, safi),
              ioAddrChoice));
    }

    List<Asn1IPAddressFamily> families = new ArrayList<>(2);

    List<IPAddressOrRange> ipv4List = new LinkedList<>();
    ipv4List.add(buildIPAddressOrRange(true, "192.0.2.0/24"));
    ipv4List.add(buildIPAddressOrRange(true, "198.51.100.0/28"));
    ipv4List.add(buildIPAddressOrRange(true, "203.0.113.0/24"));

    // https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    List<IPAddressOrRange> ipv6List = new LinkedList<>();
    ipv6List.add(buildIPAddressOrRange(false, "2001:0db8:1234/48"));
    if (withLongIPv6Bytes) {
      ipv6List.add(buildIPAddressOrRange(false,
          "3fff:0003::-3fff:0122::2233:3344:5566:ffff:ffff"));
    } else {
      ipv6List.add(buildIPAddressOrRange(false,
          "3fff:0600::-3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    families.add(
        new Asn1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv6, safi),
            IPAddressChoice.ofAddressesOrRanges(new IPAddressOrRange.Seq0(ipv6List))));

    families.add(
        new Asn1IPAddressFamily(new IPAddressFamily(IPAddressFamily.AFI_IPv4, safi),
            IPAddressChoice.ofAddressesOrRanges(new IPAddressOrRange.Seq0(ipv4List))));

    return new IPAddrBlocks(families);
  }

  private static IPAddressOrRange buildIPAddressOrRange(boolean ipv4, String addr)
      throws CodecException {
    if (addr.contains("-")) {
      String[] tokens = addr.split("-");
      Rfc3779IPAddress min =
          Rfc3779IPAddress.getInstance(ipv4, tokens[0], Rfc3779IPAddress.Context.RANGE_MIN);
      Rfc3779IPAddress max =
          Rfc3779IPAddress.getInstance(ipv4, tokens[1], Rfc3779IPAddress.Context.RANGE_MAX);

      return IPAddressOrRange.ofAddressRange(new IPAddressRange(
          new Asn1IPAddress(min.value(), min.unusedBits()),
          new Asn1IPAddress(max.value(), max.unusedBits())));
    } else {
      Rfc3779IPAddress prefix =
          Rfc3779IPAddress.getInstance(ipv4, addr, Rfc3779IPAddress.Context.PREFIX);
      return IPAddressOrRange.ofAddressPrefix(
          new Asn1IPAddress(prefix.value(), prefix.unusedBits()));
    }
  }

  private static Extensions generateRfc3739() {
    List<Attribute> attrs = new ArrayList<>();
    attrs.add(Attribute.ofTitle(new DirectoryString(new Asn1PrintableString("Dr."))));
    attrs.add(Attribute.ofCountryOfResidence("DE"));
    attrs.add(Attribute.ofCountryOfCitizenship("FR"));
    attrs.add(Attribute.ofGender("M"));
    attrs.add(Attribute.ofPlaceOfBirth(
        new DirectoryString(new Asn1Utf8String("DummyCity"))));
    attrs.add(Attribute.ofDateOfBirth(1980, 12, 18));

    SubjectDirectoryAttributes sdAttrs = new SubjectDirectoryAttributes(attrs);

    List<Extension> extensions = new ArrayList<>();
    extensions.add(Extension.ofSubjectDirectoryAttributes(false, sdAttrs));

    TypeOfBiometricData bioType = TypeOfBiometricData.ofPredefinedBiometricType(0);
    HashAlgo hashAlgo = HashAlgo.SHA256;
    byte[] bioHash = fixedBytes(hashAlgo.length(), 0x12);
    String biometricUri = "https://myorg.org/?id=123";
    BiometricData bioData = new BiometricData(
        bioType, hashAlgo.algorithmIdentifier(), new Asn1OctetString(bioHash),
        new Asn1IA5String(biometricUri));
    extensions.add(Extension.ofBiometricInfo(false, new BiometricSyntax(bioData)));

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  private static Extensions generateGmt0015() {
    List<Extension> extensions = new ArrayList<>();

    String cnResidentIdCardNumber = "110101199001011234";
    String cnPassportNumber = "E12345678";
    String cnSocialInsuranceNumber = "110101199001013456";
    String cnUnifiedSocialCreditCode = "91310000MA1K12345X";

    // GM/T 0015
    if (StringUtil.isNotBlank(cnResidentIdCardNumber)) {
      extensions.add(Extension.ofCN_ResidentIdCardNumber(false, cnResidentIdCardNumber));
    }

    if (StringUtil.isNotBlank(cnPassportNumber)) {
      extensions.add(Extension.ofCN_PassportNumber(false, cnPassportNumber));
    }

    if (StringUtil.isNotBlank(cnSocialInsuranceNumber)) {
      extensions.add(Extension.ofCN_SocialInsuranceNumber(false, cnSocialInsuranceNumber));
    }

    if (StringUtil.isNotBlank(cnUnifiedSocialCreditCode)) {
      extensions.add(Extension.ofCN_UnifiedSocialCreditCode(false, cnUnifiedSocialCreditCode));
    }

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  private static Extensions generateMicrosoft() {
    // Microsoft SID, e.g. S-1-5-...
    String microsoftSid = "S-1-5-123456-234567-1234";
    List<Extension> extensions = new ArrayList<>();
    OtherName on = OtherName.ofMicrosoftObjectSid(
        microsoftSid.getBytes(StandardCharsets.US_ASCII));
    GeneralName gn = GeneralName.ofOtherName(on);
    GeneralNames gns = new GeneralNames(gn);

    extensions.add(Extension.ofMicrosoftSecurityIdentifier(false, gns));

    return new Extensions(extensions.toArray(new Extension[0]));
  }

  private static Extensions generateEeComplex() {
    List<QCStatement> vec = new LinkedList<>();

    MonetaryValue mv = new MonetaryValue(Iso4217CurrencyCode.ofAlphabetic("EUR"), 150, 15);
    vec.add(QCStatement.ofQcLimitValue(mv));

    return new Extensions(Extension.ofQCStatements(false, new QCStatements(vec)));
  }

  private static Extensions generateCaliptra() {
    return new Extensions(Extension.ofTcgDiceUeid(false, fixedBytes(4, 0x12)));
  }

  private static Extensions generateOthernames() throws Exception {
    List<OtherName> otherNames = new LinkedList<>();

    // macAddress
    otherNames.add(OtherName.ofMacAddress(fixedBytes(8, 12)));

    // smtpUtf8Mailbox
    otherNames.add(OtherName.ofSmtpUTF8Mailbox("学生@school.example.org"));

    // smtpUtf8Mailbox
    HardwareModuleName hwmName = new HardwareModuleName(
        new Asn1Oid("1.2.3.5"), fixedBytes(16, 0x45));
    otherNames.add(OtherName.ofHardwareModuleName(hwmName));

    // any otherName
    Asn1Sequence dummySeq = new Asn1Sequence(new Asn1Utf8String("first"),
        new Asn1Utf8String("second"));
    otherNames.add(OtherName.create(new Asn1Oid("1.2.3.4.5"), dummySeq));

    List<GeneralName> gns = new ArrayList<>(otherNames.size());
    for (OtherName otherName : otherNames) {
      gns.add(GeneralName.ofOtherName(otherName));
    }

    return new Extensions(Extension.ofSubjectAlternativeName(false,
        new GeneralNames(gns.toArray(new GeneralName[0]))));
  }

  private static Extensions generateTCG() throws Exception {
    // extension SubjectAltName
    Extension otherNameExt = generateTcgOtherNameExt();

    // extension SubjectDirectoryAttributes
    List<Attribute> attrs = new ArrayList<>();

    // tcg_at_tcgPlatformSpecification
    TCGPlatformSpecification platformSpec = new TCGPlatformSpecification(
        new TCGSpecificationVersion(1, 2, 3),
        fixedBytes(4, 0x34));
    attrs.add(Attribute.ofTcgPlatformSpecification(platformSpec));

    // tcg_at_tcgCredentialSpecification
    TCGSpecificationVersion specVersion = new TCGSpecificationVersion(1, 2, 3);
    attrs.add(Attribute.ofTcgCredentialSpecification(specVersion));

    // tcg_at_tcgCredentialType
    TCGCredentialType credentialType =
        new TCGCredentialType(TcgOIDs.tcg_kp_PlatformKeyCertificate);
    attrs.add(Attribute.ofTcgCredentialType(credentialType));

    // tcg_at_platformConfiguration_v3
    List<Property> props = new ArrayList<>();
    props.add(new Property("prop-name", "prop-value", AttributeStatus.added));
    PlatformConfigurationV3 confV3 = new PlatformConfigurationV3(
        generateTraitsForPlatformConfiguration(), new Properties(props));
    attrs.add(Attribute.ofTcgPlatformConfigurationV3(confV3));

    // tcg_at_platformConfigUri_v3
    attrs.add(Attribute.ofTcgPlatformConfigUriV3(generateTraitsForPlatformConfigUriV3()));

    // tcg_at_previousPlatformCertificates
    attrs.add(Attribute.ofTcgPreviousPlatformCertificates(
        generateTraitsForPreviousPlatformCertificates()));

    // tcg_at_tbbSecurityAssertions_v3
    attrs.add(Attribute.ofTcgTbbSecurityAssertionsV3(generateTraitsForTbbSecurityAssertions_v3()));

    // tcg_at_cryptographicAnchors
    attrs.add(Attribute.ofTcgCryptographicAnchors(generateTraitsForCryptographicAnchors()));

    // tcg_at_platformOwnership
    attrs.add(Attribute.ofTcgPlatformOwnership(generateTraitsForPlatformOwnership()));

    // tcg_at_manufacturingAssertions
    attrs.add(Attribute.ofTcgManufacturingAssertions(generateTraitsForManufacturingAssertions()));

    Extension subjectDirectoryAttributesExt = Extension.ofSubjectDirectoryAttributes(false,
        new SubjectDirectoryAttributes(attrs));
    return new Extensions(otherNameExt, subjectDirectoryAttributesExt);
  }

  private static Extension generateTcgOtherNameExt() {
    List<Trait> traits = new LinkedList<>();
    traits.add(Trait.ofIdUTF8String(
        "my platformManufacturer",
        TcgOIDs.tcg_tr_cat_platformManufacturer,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformManufacturer",
        "http://example.com/platformManufacturer"));

    traits.add(Trait.ofIdIA5String(
        "my platformModel",
        TcgOIDs.tcg_tr_cat_platformModel,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformModel",
        "http://example.com/platformModel"));

    traits.add(Trait.ofIdUTF8String(
        "my platformVersion",
        TcgOIDs.tcg_tr_cat_platformVersion,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformVersion",
        "http://example.com/platformVersion"));

    traits.add(Trait.ofIdUTF8String(
        "my platformSerial",
        TcgOIDs.tcg_tr_cat_platformSerial,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformSerial",
        "http://example.com/platformSerial"));

    traits.add(Trait.ofIdPEN(
        new Asn1Oid("1.3.6.1.4.1.45522.1234"),
        TcgOIDs.tcg_tr_cat_platformManufacturerIdentifier,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformManufacturerIdentifier",
        "http://example.com/platformManufacturerIdentifier"));

    OtherName otherName = OtherName.ofTcgPlatformIdentifier(new Traits(traits));

    return Extension.ofSubjectAlternativeName(false,
        new GeneralNames(GeneralName.ofOtherName(otherName)));
  }

  private static Traits generateTraitsForPlatformConfigUriV3() {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_URI
    traits.add(Trait.ofIdURI(
        new URIReference("http://example.org/platform-configuri-v3", null, null),
        TcgOIDs.tcg_tr_cat_PlatformCertificate,
        TcgOIDs.tcg_tr_reg_none, null, null));

    return new Traits(traits);
  }

  private static Traits generateTraitsForPlatformConfiguration() {
    List<Trait> traits = new LinkedList<>();

    traits.add(Trait.ofIdUTF8String(
        "my platformManufacturer",
        TcgOIDs.tcg_tr_cat_platformManufacturer,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformManufacturer",
        "http://example.com/platformManufacturer"));

    traits.add(Trait.ofIdIA5String(
        "my platformModel",
        TcgOIDs.tcg_tr_cat_platformModel,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformModel",
        "http://example.com/platformModel"));

    traits.add(Trait.ofIdUTF8String("my platformVersion",
        TcgOIDs.tcg_tr_cat_platformVersion,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformVersion",
        "http://example.com/platformVersion"));

    traits.add(Trait.ofIdUTF8String("my platformSerial",
        TcgOIDs.tcg_tr_cat_platformSerial,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformSerial",
        "http://example.com/platformSerial"));

    traits.add(Trait.ofIdPEN(
        new Asn1Oid("1.3.6.1.4.1.45522.1234"),
        TcgOIDs.tcg_tr_cat_platformManufacturerIdentifier,
        TcgOIDs.tcg_tr_reg_none,
        "description cat platformManufacturerIdentifier",
        "http://example.com/platformManufacturerIdentifier"));

    return new Traits(traits);
  }

  private static Traits generateTraitsForPreviousPlatformCertificates() {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_Boolean
    traits.add(Trait.ofIdBoolean(
        true,
        TcgOIDs.tcg_tr_cat_PlatformCertificate,
        TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_certificateIdentifier
    CertificateIdentifier certId = new CertificateIdentifier(
        new HashedCertificateIdentifier(
            HashAlgo.SHA256.algorithmIdentifier(), fixedBytes(32, 0x12)),
        new IssuerSerial(new GeneralNames(GeneralName.ofDirectoryName(new X500Name("CN=issuer"))),
            BigInteger.TEN));
    traits.add(Trait.ofIdCertificateIdentifier(certId,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_componentClass
    traits.add(Trait.ofIdComponentClass(fixedBytes(4, 0x22),
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_componentIdentifierV11
    ComponentClass componentClass = new ComponentClass(
        TcgOIDs.tcg_registry_componentClass_tcg, fixedBytes(4, 0x33));
    ComponentIdentifierV11 idV11 = new ComponentIdentifierV11(componentClass,
        "my component manufacturer", "my component model");
    traits.add(Trait.ofIdComponentIdentifierV11(idV11,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_networkMAC
    ComponentAddress componentAddress = new ComponentAddress(TcgOIDs.tcg_address_ethernetmac,
        "02:1A:2B:3C:4D:5E");
    traits.add(Trait.ofIdNetworkMAC(componentAddress,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_OID
    traits.add(Trait.ofIdOID(new Asn1Oid("1.2.3.4.5"),
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_status
    traits.add(Trait.ofIdStatus(AttributeStatus.added,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_PEMCertString
    traits.add(Trait.ofIdPEMCertString(
        "-----BEGIN CERTIFICATE-----\r\nMIIA\r\n-----END CERTIFICATE-----",
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    return new Traits(traits);
  }

  private static Traits generateTraitsForPlatformOwnership() {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_UTF8String
    traits.add(Trait.ofIdUTF8String("my PlatformOwnership",
        TcgOIDs.tcg_tr_cat_platformOwnership, TcgOIDs.tcg_tr_reg_none, null, null));

    return new Traits(traits);
  }

  private static Traits generateTraitsForManufacturingAssertions() {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_UTF8String
    traits.add(Trait.ofIdUTF8String("my ManufacturingAssertions",
        TcgOIDs.tcg_tr_cat_platformOwnership, TcgOIDs.tcg_tr_reg_none, null, null));

    return new Traits(traits);
  }

  private static Traits generateTraitsForCryptographicAnchors() throws Exception {
    List<Trait> traits = new LinkedList<>();

    KeyPairGenerator kpGen = cryptoApi.newKeyPairGenerator("EC");
    kpGen.initialize(new NamedParameterSpec("P-256"));
    KeyPair keyPair = kpGen.generateKeyPair();
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.fromPublicKey(keyPair.getPublic());
    traits.add(Trait.ofIdPublicKey(spki,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    return new Traits(traits);
  }

  private static Traits generateTraitsForTbbSecurityAssertions_v3() {
    List<Trait> traits = new LinkedList<>();

    // tcg_tr_ID_CommonCriteria
    CommonCriteriaMeasures ccMeasures = new CommonCriteriaMeasures(
        "3.1", EvaluationAssuranceLevel.level4, EvaluationStatus.evaluationCompleted, false,
        StrengthOfFunction.medium, null, null, null, null);
    CommonCriteriaEvaluation cce = new CommonCriteriaEvaluation(
        ccMeasures, "CC-Number", "CC-CertificateAuthority",
        "CC-Schema", null, null);
    traits.add(Trait.ofIdCommonCriteria(cce,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_FIPSLevel
    traits.add(Trait.ofIdFIPSLevel(new FIPSLevel("140-3", SecurityLevel.level3, false),
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_ISO9000Level
    traits.add(Trait.ofIdISO9000Level(
        new ISO9000Certification(true, "https://example.org/ISO9000Certification"),
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_platformFirmwareUpdateCompliance
    traits.add(Trait.ofIdPlatformFirmwareUpdateCompliance(
        PlatformFirmwareUpdateCompliance.sp800_147,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_platformHardwareCapabilities
    traits.add(Trait.ofIdPlatformHardwareCapabilities(
        PlatformHardwareCapabilities.firmwareFlashWP,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_platformFirmwareCapabilities
    traits.add(Trait.ofIdPlatformFirmwareCapabilities(
        PlatformFirmwareCapabilities.fwSetupAuthLocal,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_platformFirmwareSignatureVerification
    traits.add(Trait.ofIdPlatformFirmwareSignatureVerification(
        PlatformFirmwareSignatureVerification.secureBoot,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_RTM
    traits.add(Trait.ofIdRTM(RTMTypes.dynamic,
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    // tcg_tr_ID_URI
    traits.add(Trait.ofIdURI(
        new URIReference("http://example.org/id", null, null),
        TcgOIDs.tcg_tr_cat_PlatformCertificate, TcgOIDs.tcg_tr_reg_none, null, null));

    return new Traits(traits);
  }

}
