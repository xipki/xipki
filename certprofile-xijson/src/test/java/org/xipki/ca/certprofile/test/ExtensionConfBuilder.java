/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.ca.certprofile.test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.DirectoryStringType;
import org.xipki.ca.certprofile.xijson.conf.AdditionalInformation;
import org.xipki.ca.certprofile.xijson.conf.AuthorityInfoAccess;
import org.xipki.ca.certprofile.xijson.conf.AuthorityKeyIdentifier;
import org.xipki.ca.certprofile.xijson.conf.BasicConstraints;
import org.xipki.ca.certprofile.xijson.conf.BiometricInfo;
import org.xipki.ca.certprofile.xijson.conf.BiometricInfo.BiometricTypeType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.CertificatePolicyInformationType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.PolicyQualfierType;
import org.xipki.ca.certprofile.xijson.conf.CertificatePolicies.PolicyQualifier;
import org.xipki.ca.certprofile.xijson.conf.CrlDistributionPoints;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.ca.certprofile.xijson.conf.ExtendedKeyUsage;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.ca.certprofile.xijson.conf.ExtnSyntax;
import org.xipki.ca.certprofile.xijson.conf.ExtnSyntax.SubFieldSyntax;
import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.ca.certprofile.xijson.conf.InhibitAnyPolicy;
import org.xipki.ca.certprofile.xijson.conf.KeyUsage;
import org.xipki.ca.certprofile.xijson.conf.NameConstraints;
import org.xipki.ca.certprofile.xijson.conf.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.PolicyMappings.PolicyIdMappingType;
import org.xipki.ca.certprofile.xijson.conf.PrivateKeyUsagePeriod;
import org.xipki.ca.certprofile.xijson.conf.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.PdsLocationType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.QcEuLimitValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.QcStatementType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.QcStatementValueType;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.Range2Type;
import org.xipki.ca.certprofile.xijson.conf.Restriction;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities.SmimeCapability;
import org.xipki.ca.certprofile.xijson.conf.SmimeCapabilities.SmimeCapabilityParameter;
import org.xipki.ca.certprofile.xijson.conf.TlsFeature;
import org.xipki.ca.certprofile.xijson.conf.ValidityModel;
import org.xipki.security.HashAlgo;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.TlsExtensionType;
import org.xipki.security.X509ExtensionType.ConstantExtnValue;
import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.TripleState;

/**
 * Extension builder for xijson configuration.
 *
 * @author Lijun Liao
 */

public class ExtensionConfBuilder {

  private static final Set<ASN1ObjectIdentifier> REQUEST_EXTENSIONS;

  static {
    REQUEST_EXTENSIONS = new HashSet<>();
    REQUEST_EXTENSIONS.add(Extension.keyUsage);
    REQUEST_EXTENSIONS.add(Extension.extendedKeyUsage);
    REQUEST_EXTENSIONS.add(Extension.subjectAlternativeName);
    REQUEST_EXTENSIONS.add(Extension.subjectDirectoryAttributes);
    REQUEST_EXTENSIONS.add(Extension.subjectInfoAccess);
    REQUEST_EXTENSIONS.add(Extension.qCStatements);
    REQUEST_EXTENSIONS.add(Extension.biometricInfo);
    REQUEST_EXTENSIONS.add(Extn.id_extension_admission);
    REQUEST_EXTENSIONS.add(Extn.id_extension_additionalInformation);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_ICRegistrationNumber);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_IdentityCode);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_InsuranceNumber);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_OrganizationCode);
    REQUEST_EXTENSIONS.add(Extn.id_GMT_0015_TaxationNumber);
  } // method static

  public static List<ConstantExtnValue> createConstantSequenceOrSet() {
    /*
     *  1. SEQUENCE or SET {
     *  2.       UTF8String abc.def.myBlog EXPLICIT
     *  3.       SEQUENCE
     *  4.         UTF8String app
     *  5.   [0] UTF8String abc.def.myBlog.voip EXPLICIT
     *  6.   [1] SEQUENCE EXPLICIT
     *  7.         UTF8String voip
     *  8.   [2] UTF8String abc.def.myBlog.complication IMPLICIT
     *  9.   [3] SEQUENCE IMPLICIT
     * 10.         UTF8String complication
     * 11. }
     */
    List<ConstantExtnValue> subFields = new LinkedList<>();
    // Line 2
    ConstantExtnValue subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setValue("abc.def.myBlog");

    // Line 3-4
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("app");
    subField.setListValue(Arrays.asList(subsubField));

    // Line 5
    subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(0, true));
    subField.setValue("abc.def.myBlog.voip");

    // Line 6-7
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(1, true));
    subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("void");
    subField.setListValue(Arrays.asList(subsubField));

    // Line 8
    subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(2, false));
    subField.setValue("abc.def.myBlog.complication");

    // Line 9-10
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(9, false));
    subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("complication");
    subField.setListValue(Arrays.asList(subsubField));

    return subFields;
  } // method createConstantSequenceOrSet

  public static List<SubFieldSyntax> createSyntaxSequenceOrSet() {
    /*
     *  1. SEQUENCE or SET {
     *  2.       UTF8String # abc.def.myBlog EXPLICIT
     *  3.       SEQUENCE
     *  4.         UTF8String  # app
     *  5.   [0] UTF8String  # abc.def.myBlog.voip EXPLICIT
     *  6.   [1] SEQUENCE EXPLICIT
     *  7.         UTF8String  # voip
     *  8.   [2] UTF8String  # abc.def.myBlog.complication IMPLICIT
     *  9.   [3] SEQUENCE IMPLICIT
     * 10.         UTF8String  # complication
     * 11. }
     */
    List<SubFieldSyntax> subFields = new LinkedList<>();
    // Line 2
    SubFieldSyntax subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);

    // Line 3-4
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    SubFieldSyntax subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setSubFields(Arrays.asList(subsubField));

    // Line 5
    subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(0, true));

    // Line 6-7
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(1, true));
    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setSubFields(Arrays.asList(subsubField));

    // Line 8
    subField = new SubFieldSyntax(FieldType.UTF8String);
    subFields.add(subField);
    subField.setTag(new Tag(2, false));

    // Line 9-10
    subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);
    subField.setTag(new Tag(9, false));
    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subField.setSubFields(Arrays.asList(subsubField));

    return subFields;
  } // method createSyntaxSequenceOrSet

  public static List<ConstantExtnValue> createConstantSequenceOfOrSetOf() {
    /*
     *  1. SEQUENCE or SET {
     *  3.   SEQUENCE
     *  3.     UTF8String abc.def.myBlog
     *  4.     UTF8String app
     *  5.   SEQUENCE
     *  6.       UTF8String abc.def.myBlog.voip
     *  7.       UTF8String voip
     *  8.   SEQUENCE
     *  9.     UTF8String abc.def.myBlog.complication
     * 10.     UTF8String complication
     * 11. }
     */
    List<ConstantExtnValue> subFields = new LinkedList<>();

    // Line 2-4
    {
      ConstantExtnValue subField = new ConstantExtnValue(FieldType.SEQUENCE);
      subFields.add(subField);

      List<ConstantExtnValue> subsubFields = new LinkedList<>();
      subField.setListValue(subsubFields);

      ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("abc.def.myBlog");
      subsubFields.add(subsubField);

      subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("app");
      subsubFields.add(subsubField);
    }

    // Line 5-7
    {
      ConstantExtnValue subField = new ConstantExtnValue(FieldType.SEQUENCE);
      subFields.add(subField);

      List<ConstantExtnValue> subsubFields = new LinkedList<>();
      subField.setListValue(subsubFields);

      ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("abc.def.myBlog.voip");
      subsubFields.add(subsubField);

      subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("voip");
      subsubFields.add(subsubField);
    }

    // Line 5-7
    {
      ConstantExtnValue subField = new ConstantExtnValue(FieldType.SEQUENCE);
      subFields.add(subField);

      List<ConstantExtnValue> subsubFields = new LinkedList<>();
      subField.setListValue(subsubFields);

      ConstantExtnValue subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("abc.def.myBlog.complication");
      subsubFields.add(subsubField);

      subsubField = new ConstantExtnValue(FieldType.UTF8String);
      subsubField.setValue("complication");
      subsubFields.add(subsubField);
    }

    return subFields;
  } // method createConstantSequenceOfOrSetOf

  public static List<SubFieldSyntax> createSyntaxSequenceOfOrSetOf() {
    /*
     *  1. SEQUENCE OF or SET OF{
     *  3.   SEQUENCE
     *  3.     UTF8String
     *  4.     UTF8String
     *  5. }
     */
    List<SubFieldSyntax> subFields = new LinkedList<SubFieldSyntax>();

    // Line 2-4
    SubFieldSyntax subField = new SubFieldSyntax(FieldType.SEQUENCE);
    subFields.add(subField);

    List<SubFieldSyntax> subsubFields = new LinkedList<>();
    subField.setSubFields(subsubFields);

    SubFieldSyntax subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubFields.add(subsubField);

    subsubField = new SubFieldSyntax(FieldType.UTF8String);
    subsubFields.add(subsubField);

    return subFields;
  } // method createSyntaxSequenceOfOrSetOf

  public static List<ExtensionType> createConstantExtensions(
      ASN1ObjectIdentifier oidPrefix, Tag tag)
          throws IOException {
    List<ExtensionType> list = new LinkedList<>();

    // Custom Constant Extension Value
    list.add(createConstantExtension(oidPrefix.branch("1"), true, false, tag,
        FieldType.BIT_STRING, Base64.encodeToString(new byte[] {1, 2})));
    list.add(createConstantExtension(oidPrefix.branch("2"), true, false, tag,
        FieldType.BMPString, "A BMP string"));
    list.add(createConstantExtension(oidPrefix.branch("3"), true, false, tag,
        FieldType.BOOLEAN, Boolean.TRUE.toString()));
    list.add(createConstantExtension(oidPrefix.branch("4"), true, false, tag,
        FieldType.IA5String, "An IA5 string"));
    list.add(createConstantExtension(oidPrefix.branch("5"), true, false, tag,
        FieldType.INTEGER, "10"));
    list.add(createConstantExtension(oidPrefix.branch("6"), true, false, tag,
        FieldType.NULL, null));
    list.add(createConstantExtension(oidPrefix.branch("7"), true, false, tag,
        FieldType.OCTET_STRING, Base64.encodeToString(new byte[] {3, 4})));
    list.add(createConstantExtension(oidPrefix.branch("8"), true, false, tag,
        FieldType.OID, "2.3.4.5"));
    list.add(createConstantExtension(oidPrefix.branch("9"), true, false, tag,
        FieldType.PrintableString, "A printable string"));
    list.add(createConstantExtension(oidPrefix.branch("10"), true, false, tag,
        FieldType.RAW, Base64.encodeToString(DERNull.INSTANCE.getEncoded())));
    last(list).getConstant().setDescription("DER NULL");

    list.add(createConstantExtension(oidPrefix.branch("11"), true, false, tag,
        FieldType.TeletexString, "A teletax string"));
    list.add(createConstantExtension(oidPrefix.branch("12"), true, false, tag,
        FieldType.UTF8String, "A UTF8 string"));
    list.add(createConstantExtension(oidPrefix.branch("13"), true, false, tag,
        FieldType.ENUMERATED, "2"));
    list.add(createConstantExtension(oidPrefix.branch("14"), true, false, tag,
        FieldType.GeneralizedTime, new ASN1GeneralizedTime("20180314130102Z").getTimeString()));
    list.add(createConstantExtension(oidPrefix.branch("15"), true, false, tag,
        FieldType.UTCTime, "190314130102Z"));
    list.add(createConstantExtension(oidPrefix.branch("16"), true, false, tag,
        FieldType.Name, "CN=abc,C=DE"));

    list.add(createConstantExtension(oidPrefix.branch("17"), true, false, tag,
        FieldType.SEQUENCE, null));
    last(list).getConstant().setListValue(createConstantSequenceOrSet());

    list.add(createConstantExtension(oidPrefix.branch("18"), true, false, tag,
        FieldType.SEQUENCE_OF, null));
    last(list).getConstant().setListValue(createConstantSequenceOfOrSetOf());

    list.add(createConstantExtension(oidPrefix.branch("19"), true, false, tag,
        FieldType.SET, null));
    last(list).getConstant().setListValue(createConstantSequenceOrSet());

    list.add(createConstantExtension(oidPrefix.branch("20"), true, false, tag,
        FieldType.SET_OF, null));
    last(list).getConstant().setListValue(createConstantSequenceOfOrSetOf());

    return list;
  } // method createConstantExtensions

  public static List<ExtensionType> createSyntaxExtensions(ASN1ObjectIdentifier oidPrefix,
      Tag tag) {
    List<ExtensionType> list = new LinkedList<>();
    // Custom extension with syntax
    list.add(createSyntaxExtension(oidPrefix.branch("1"), true, false, tag,
        FieldType.BIT_STRING));
    list.add(createSyntaxExtension(oidPrefix.branch("2"), true, false, tag,
        FieldType.BMPString));
    list.add(createSyntaxExtension(oidPrefix.branch("3"), true, false, tag,
        FieldType.BOOLEAN));
    list.add(createSyntaxExtension(oidPrefix.branch("4"), true, false, tag,
        FieldType.IA5String));
    list.add(createSyntaxExtension(oidPrefix.branch("5"), true, false, tag,
        FieldType.INTEGER));
    list.add(createSyntaxExtension(oidPrefix.branch("6"), true, false, tag,
        FieldType.NULL));
    list.add(createSyntaxExtension(oidPrefix.branch("7"), true, false, tag,
        FieldType.OCTET_STRING));
    list.add(createSyntaxExtension(oidPrefix.branch("8"), true, false, tag,
        FieldType.OID));
    list.add(createSyntaxExtension(oidPrefix.branch("9"), true, false, tag,
        FieldType.PrintableString));
    list.add(createSyntaxExtension(oidPrefix.branch("10"), true, false, tag,
        FieldType.RAW));
    list.add(createSyntaxExtension(oidPrefix.branch("11"), true, false, tag,
        FieldType.TeletexString));
    list.add(createSyntaxExtension(oidPrefix.branch("12"), true, false, tag,
        FieldType.UTF8String));
    list.add(createSyntaxExtension(oidPrefix.branch("13"), true, false, tag,
        FieldType.ENUMERATED));
    list.add(createSyntaxExtension(oidPrefix.branch("14"), true, false, tag,
        FieldType.GeneralizedTime));
    list.add(createSyntaxExtension(oidPrefix.branch("15"), true, false, tag,
        FieldType.UTCTime));
    list.add(createSyntaxExtension(oidPrefix.branch("16"), true, false, tag,
        FieldType.Name));

    list.add(createSyntaxExtension(oidPrefix.branch("17"), true, false, tag,
        FieldType.SEQUENCE));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOrSet());

    list.add(createSyntaxExtension(oidPrefix.branch("18"), true, false, tag,
        FieldType.SEQUENCE_OF));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOfOrSetOf());

    list.add(createSyntaxExtension(oidPrefix.branch("19"), true, false, tag,
        FieldType.SET));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOrSet());

    list.add(createSyntaxExtension(oidPrefix.branch("20"), true, false, tag,
        FieldType.SET_OF));
    last(list).getSyntax().setSubFields(createSyntaxSequenceOfOrSetOf());

    return list;
  } // method createSyntaxExtensions

  public static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical) {
    return createExtension(type, required, critical, null);
  }

  public static ExtensionType createExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical, String description) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setPermittedInRequest(REQUEST_EXTENSIONS.contains(type));
    // children
    ret.setType(createOidType(type, description));
    ret.setCritical(critical);
    return ret;
  }

  public static ExtensionType createConstantExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical, Tag tag, FieldType fieldType, String value) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setPermittedInRequest(false);
    // children
    String desc = "custom constant extension " + fieldType.getText();
    if (tag != null) {
      desc += " (" + tag.getValue() + ", " + (tag.isExplicit() ? "EXPLICIT)" : "IMPLICIT)");
    }
    ret.setType(createOidType(type, desc));
    ret.setCritical(critical);

    ConstantExtnValue constantExtn = new ConstantExtnValue(fieldType);
    ret.setConstant(constantExtn);
    if (value != null) {
      constantExtn.setValue(value);
    }

    if (tag != null) {
      constantExtn.setTag(tag);
    }

    return ret;
  } // method createConstantExtension

  public static ExtensionType createSyntaxExtension(ASN1ObjectIdentifier type, boolean required,
      boolean critical, Tag tag, FieldType fieldType) {
    ExtensionType ret = new ExtensionType();
    // attributes
    ret.setRequired(required);
    ret.setPermittedInRequest(true);
    // children
    String desc = "custom syntax extension " + fieldType.getText();
    if (tag != null) {
      desc += " (" + tag.getValue() + ", " + (tag.isExplicit() ? "EXPLICIT)" : "IMPLICIT)");
    }
    ret.setType(createOidType(type, desc));
    ret.setCritical(critical);

    ExtnSyntax extnSyntax = new ExtnSyntax(fieldType);
    if (tag != null) {
      extnSyntax.setTag(tag);
    }

    ret.setSyntax(extnSyntax);

    return ret;
  } // method createSyntaxExtension

  public static KeyUsage createKeyUsage(org.xipki.security.KeyUsage[] requiredUsages,
      org.xipki.security.KeyUsage[] optionalUsages) {
    KeyUsage extValue = new KeyUsage();
    if (requiredUsages != null) {
      for (org.xipki.security.KeyUsage m : requiredUsages) {
        KeyUsage.Usage usage = new KeyUsage.Usage();
        usage.setValue(m);
        usage.setRequired(true);
        extValue.getUsages().add(usage);
      }
    }
    if (optionalUsages != null) {
      for (org.xipki.security.KeyUsage m : optionalUsages) {
        KeyUsage.Usage usage = new KeyUsage.Usage();
        usage.setValue(m);
        usage.setRequired(false);
        extValue.getUsages().add(usage);
      }
    }

    return extValue;
  } // method createKeyUsage

  // CHECKSTYLE:SKIP
  public static AuthorityKeyIdentifier createAKIwithSerialAndSerial() {
    AuthorityKeyIdentifier akiType = new AuthorityKeyIdentifier();
    akiType.setUseIssuerAndSerial(true);
    return akiType;
  } // method createAKIwithSerialAndSerial

  public static AuthorityInfoAccess createAuthorityInfoAccess() {
    AuthorityInfoAccess extnValue = new AuthorityInfoAccess();
    extnValue.setIncludeCaIssuers(true);
    extnValue.setIncludeOcsp(true);
    extnValue.setCaIssuersProtocols(new HashSet<>(Arrays.asList("http")));
    extnValue.setOcspProtocols(new HashSet<>(Arrays.asList("http")));
    return extnValue;
  } // method createAuthorityInfoAccess

  public static CrlDistributionPoints createCrlDistibutoionPoints() {
    CrlDistributionPoints extnValue = new CrlDistributionPoints();
    extnValue.setProtocols(new HashSet<>(Arrays.asList("http")));
    return extnValue;
  }

  public static BasicConstraints createBasicConstraints(int pathLen) {
    BasicConstraints extValue = new BasicConstraints();
    extValue.setPathLen(pathLen);
    return extValue;
  }

  public static ExtendedKeyUsage createExtendedKeyUsage(
      ASN1ObjectIdentifier[] requiredUsages, ASN1ObjectIdentifier[] optionalUsages) {
    ExtendedKeyUsage extValue = new ExtendedKeyUsage();
    if (requiredUsages != null) {
      List<ASN1ObjectIdentifier> oids = Arrays.asList(requiredUsages);
      oids = sortOidList(oids);
      for (ASN1ObjectIdentifier usage : oids) {
        extValue.getUsages().add(createSingleExtKeyUsage(usage, true));
      }
    }

    if (optionalUsages != null) {
      List<ASN1ObjectIdentifier> oids = Arrays.asList(optionalUsages);
      oids = sortOidList(oids);
      for (ASN1ObjectIdentifier usage : oids) {
        extValue.getUsages().add(createSingleExtKeyUsage(usage, false));
      }
    }

    return extValue;
  } // method createExtendedKeyUsage

  public static ExtendedKeyUsage.Usage createSingleExtKeyUsage(
      ASN1ObjectIdentifier usage, boolean required) {
    ExtendedKeyUsage.Usage type = new ExtendedKeyUsage.Usage();
    type.setOid(usage.getId());
    type.setRequired(required);
    String desc = getDescription(usage);
    if (desc != null) {
      type.setDescription(desc);
    }
    return type;
  } // method createSingleExtKeyUsage

  public static Restriction createRestriction(DirectoryStringType type, String text) {
    Restriction extValue = new Restriction();
    extValue.setType(type);
    extValue.setText(text);
    return extValue;
  } // method createRestriction

  public static AdditionalInformation createAdditionalInformation(DirectoryStringType type,
      String text) {
    AdditionalInformation extValue = new AdditionalInformation();
    extValue.setType(type);
    extValue.setText(text);
    return extValue;
  } // method createAdditionalInformation

  public static PrivateKeyUsagePeriod createPrivateKeyUsagePeriod(String validity) {
    PrivateKeyUsagePeriod extValue = new PrivateKeyUsagePeriod();
    extValue.setValidity(validity);
    return extValue;
  }

  public static QcStatements createQcStatements(boolean requireRequestExt) {
    QcStatements extValue = new QcStatements();
    QcStatementType statement = new QcStatementType();

    // QcCompliance
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcCompliance));
    extValue.getQcStatements().add(statement);

    // QC SCD
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcSSCD));
    extValue.getQcStatements().add(statement);

    // QC RetentionPeriod
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcRetentionPeriod));
    QcStatementValueType statementValue = new QcStatementValueType();
    statementValue.setQcRetentionPeriod(10);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    // QC LimitValue
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcLimitValue));
    statementValue = new QcStatementValueType();

    QcEuLimitValueType euLimit = new QcEuLimitValueType();
    euLimit.setCurrency("EUR");
    Range2Type rangeAmount = new Range2Type();
    int min = 100;
    rangeAmount.setMin(min);
    rangeAmount.setMax(requireRequestExt ? 200 : min);
    euLimit.setAmount(rangeAmount);

    Range2Type rangeExponent = new Range2Type();
    min = 10;
    rangeExponent.setMin(min);
    rangeExponent.setMax(requireRequestExt ? 20 : min);
    euLimit.setExponent(rangeExponent);

    statementValue.setQcEuLimitValue(euLimit);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    // QC PDS
    statement = new QcStatementType();
    statement.setStatementId(createOidType(Extn.id_etsi_qcs_QcPDS));
    extValue.getQcStatements().add(statement);
    statementValue = new QcStatementValueType();
    statement.setStatementValue(statementValue);
    List<PdsLocationType> pdsLocations = new LinkedList<>();
    statementValue.setPdsLocations(pdsLocations);

    PdsLocationType pdsLocation = new PdsLocationType();
    pdsLocations.add(pdsLocation);
    pdsLocation.setUrl("http://pki.myorg.org/pds/en");
    pdsLocation.setLanguage("en");

    pdsLocation = new PdsLocationType();
    pdsLocations.add(pdsLocation);
    pdsLocation.setUrl("http://pki.myorg.org/pds/de");
    pdsLocation.setLanguage("de");

    // QC Constant value
    statement = new QcStatementType();
    statement.setStatementId(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5"), "dummy"));
    statementValue = new QcStatementValueType();
    DescribableBinary value = new DescribableBinary();
    try {
      value.setValue(DERNull.INSTANCE.getEncoded());
    } catch (IOException ex) {
      throw new IllegalStateException(ex);
    }
    value.setDescription("DER NULL");
    statementValue.setConstant(value);
    statement.setStatementValue(statementValue);
    extValue.getQcStatements().add(statement);

    return extValue;
  } // method createQcStatements

  public static BiometricInfo createBiometricInfo() {
    BiometricInfo extValue = new BiometricInfo();

    // type
    // predefined image (0)
    BiometricTypeType type = new BiometricTypeType();
    extValue.getTypes().add(type);

    DescribableInt predefined = new DescribableInt();
    predefined.setValue(0);
    predefined.setDescription("image");
    type.setPredefined(predefined);

    // predefined handwritten-signature(1)
    type = new BiometricTypeType();
    predefined = new DescribableInt();
    predefined.setValue(1);
    predefined.setDescription("handwritten-signature");
    type.setPredefined(predefined);
    extValue.getTypes().add(type);

    // OID
    type = new BiometricTypeType();
    type.setOid(createOidType(new ASN1ObjectIdentifier("1.2.3.4.5.6"), "dummy biometric type"));
    extValue.getTypes().add(type);

    // hash algorithm
    HashAlgo[] hashAlgos = new HashAlgo[]{HashAlgo.SHA256, HashAlgo.SHA384};
    for (HashAlgo hashAlgo : hashAlgos) {
      extValue.getHashAlgorithms().add(createOidType(hashAlgo.getOid(), hashAlgo.getName()));
    }

    extValue.setIncludeSourceDataUri(TripleState.required);
    return extValue;
  } // method createBiometricInfo

  public static ValidityModel createValidityModel(DescribableOid modelId) {
    ValidityModel extValue = new ValidityModel();
    extValue.setModelId(modelId);
    return extValue;
  } // method createValidityModel

  public static CertificatePolicies createCertificatePolicies(
      Map<ASN1ObjectIdentifier, String> policies) {
    if (policies == null || policies.isEmpty()) {
      return null;
    }

    CertificatePolicies extValue = new CertificatePolicies();
    List<CertificatePolicyInformationType> pis = extValue.getCertificatePolicyInformations();
    for (ASN1ObjectIdentifier oid : policies.keySet()) {
      CertificatePolicyInformationType single = new CertificatePolicyInformationType();
      pis.add(single);
      single.setPolicyIdentifier(createOidType(oid));

      List<PolicyQualifier> qualifiers = new ArrayList<>(1);
      String cpsUri = policies.get(oid);
      if (cpsUri != null) {
        PolicyQualifier qualifier = new PolicyQualifier();
        qualifier.setType(PolicyQualfierType.cpsUri);
        qualifier.setValue(cpsUri);
        qualifiers.add(qualifier);
      }
      single.setPolicyQualifiers(qualifiers);
    }

    return extValue;
  } // method createCertificatePolicies

  private static String getDescription(ASN1ObjectIdentifier oid) {
    return ObjectIdentifiers.getName(oid);
  }

  public static PolicyIdMappingType createPolicyIdMapping(
      ASN1ObjectIdentifier issuerPolicyId, ASN1ObjectIdentifier subjectPolicyId) {
    PolicyIdMappingType ret = new PolicyIdMappingType();
    ret.setIssuerDomainPolicy(createOidType(issuerPolicyId));
    ret.setSubjectDomainPolicy(createOidType(subjectPolicyId));

    return ret;
  } // method createPolicyIdMapping

  public static PolicyConstraints createPolicyConstraints(Integer inhibitPolicyMapping,
      Integer requireExplicitPolicy) {
    PolicyConstraints ret = new PolicyConstraints();
    if (inhibitPolicyMapping != null) {
      ret.setInhibitPolicyMapping(inhibitPolicyMapping);
    }

    if (requireExplicitPolicy != null) {
      ret.setRequireExplicitPolicy(requireExplicitPolicy);
    }
    return ret;
  } // method createPolicyConstraints

  public static NameConstraints createNameConstraints() {
    NameConstraints ret = new NameConstraints();
    List<GeneralSubtreeType> permitted = new LinkedList<>();
    ret.setPermittedSubtrees(permitted);

    GeneralSubtreeType single = new GeneralSubtreeType();
    single.setBase(new GeneralSubtreeType.Base());
    single.getBase().setDirectoryName("O=myorg organization, C=DE");
    permitted.add(single);

    List<GeneralSubtreeType> excluded = new LinkedList<>();
    single = new GeneralSubtreeType();
    excluded.add(single);

    single.setBase(new GeneralSubtreeType.Base());
    single.getBase().setDirectoryName("OU=bad OU, O=myorg organization, C=DE");
    ret.setExcludedSubtrees(excluded);

    return ret;
  } // method createNameConstraints

  public static InhibitAnyPolicy createInhibitAnyPolicy(int skipCerts) {
    InhibitAnyPolicy ret = new InhibitAnyPolicy();
    ret.setSkipCerts(skipCerts);
    return ret;
  } // method createInhibitAnyPolicy

  public static DescribableOid createOidType(ASN1ObjectIdentifier oid) {
    return createOidType(oid, null);
  }

  public static DescribableOid createOidType(ASN1ObjectIdentifier oid, String description) {
    DescribableOid ret = new DescribableOid();
    ret.setOid(oid.getId());

    String desc = (description == null) ? getDescription(oid) : description;
    if (desc != null) {
      ret.setDescription(desc);
    }
    return ret;
  } // method

  public static Range createRange(Integer min, Integer max) {
    Range ret = new Range();
    ret.setMin(min);
    ret.setMax(max);
    return ret;
  } // method createRange

  public static Map<String, String> createDescription(String details) {
    Map<String, String> map = new HashMap<>();
    map.put("category", "A");
    map.put("details", details);
    return map;
  } // method createDescription

  public static TlsFeature createTlsFeature(TlsExtensionType... features) {
    List<TlsExtensionType> exts = Arrays.asList(features);
    Collections.sort(exts);

    TlsFeature tlsFeature = new TlsFeature();
    for (TlsExtensionType m : exts) {
      DescribableInt dint = new DescribableInt();
      dint.setValue(m.getCode());
      dint.setDescription(m.getName());
      tlsFeature.getFeatures().add(dint);
    }

    return tlsFeature;
  } // method createTlsFeature

  public static SmimeCapabilities createSmimeCapabilities() {
    SmimeCapabilities caps = new SmimeCapabilities();

    // DES-EDE3-CBC
    SmimeCapability cap = new SmimeCapability();
    caps.getCapabilities().add(cap);
    cap.setCapabilityId(createOidType(new ASN1ObjectIdentifier("1.2.840.113549.3.7"),
        "DES-EDE3-CBC"));

    // RC2-CBC keysize 128
    cap = new SmimeCapability();
    caps.getCapabilities().add(cap);
    cap.setCapabilityId(createOidType(new ASN1ObjectIdentifier("1.2.840.113549.3.2"), "RC2-CBC"));
    cap.setParameter(new SmimeCapabilityParameter());
    cap.getParameter().setInteger(BigInteger.valueOf(128));

    // RC2-CBC keysize 64
    cap = new SmimeCapability();
    caps.getCapabilities().add(cap);
    cap.setCapabilityId(createOidType(new ASN1ObjectIdentifier("1.2.840.113549.3.2"), "RC2-CBC"));
    cap.setParameter(new SmimeCapabilityParameter());

    DescribableBinary binary = new DescribableBinary();
    try {
      binary.setValue(new ASN1Integer(64).getEncoded());
      binary.setDescription("INTEGER 64");
    } catch (IOException ex) {
      throw new IllegalStateException(ex.getMessage());
    }
    cap.getParameter().setBinary(binary);

    return caps;
  } // method createSmimeCapabilities

  private static List<ASN1ObjectIdentifier> sortOidList(List<ASN1ObjectIdentifier> oids) {
    Args.notNull(oids, "oids");
    List<String> list = new ArrayList<>(oids.size());
    for (ASN1ObjectIdentifier m : oids) {
      list.add(m.getId());
    }
    Collections.sort(list);

    List<ASN1ObjectIdentifier> sorted = new ArrayList<>(oids.size());
    for (String m : list) {
      for (ASN1ObjectIdentifier n : oids) {
        if (m.equals(n.getId()) && !sorted.contains(n)) {
          sorted.add(n);
        }
      }
    }
    return sorted;
  } // method sortOidList

  private static ExtensionType last(List<ExtensionType> list) {
    return list.get(list.size() - 1);
  } // method last
}
