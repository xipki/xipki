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

package org.xipki.security.shell.test;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.X509ExtensionType;
import org.xipki.security.X509ExtensionType.ConstantExtnValue;
import org.xipki.security.X509ExtensionType.DescribableOid;
import org.xipki.security.X509ExtensionType.ExtensionsType;
import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.IoUtil;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * Demonstrate how to create constant extension configuration that can be used
 * in the actions xi:csr-p12 and xi:csr-p11.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ExtensionsConfCreatorDemo {

  public static class ExtnDemoWithConf {
    private List<String> texts;

    public List<String> getTexts() {
      return texts;
    }

    public void setTexts(List<String> texts) {
      this.texts = texts;
    }

  }

  private ExtensionsConfCreatorDemo() {
  }

  public static void main(String[] args) {
    try {
      extensionsEeCompelx("extensions-ee-complex.json");
      extensionsSyntaxExt("extensions-syntax-ext.json",
          new ASN1ObjectIdentifier("1.2.3.6.1"), null);
      extensionsSyntaxExt("extensions-syntax-ext-implicit-tag.json",
          new ASN1ObjectIdentifier("1.2.3.6.2"), new Tag(1, false));
      extensionsSyntaxExt("extensions-syntax-ext-explicit-tag.json",
          new ASN1ObjectIdentifier("1.2.3.6.3"), new Tag(1, true));
      extensionsAppleWwdr("extensions-apple-wwdr.json");
      extensionsGmt0015("extensions-gmt0015.json");
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  } // method main

  private static void marshall(ExtensionsType extensionsType, String filename) {
    try {
      extensionsType.validate();
      Path path = Paths.get("tmp", filename);
      IoUtil.mkdirsParent(path);
      try (OutputStream out = Files.newOutputStream(path)) {
        JSON.writeJSONString(out, extensionsType,
            SerializerFeature.PrettyFormat, SerializerFeature.SortField,
            SerializerFeature.DisableCircularReferenceDetect);
      }
      System.out.println("marshalled " + path.toString());

      check(path);
    } catch (Exception ex) {
      System.err.println("Error while generating extensions in " + filename);
      ex.printStackTrace();
    }

  } // method marshal

  private static void check(Path path) throws Exception {
    byte[] bytes = IoUtil.read(path.toFile());
    ExtensionsType extraExtensions = JSON.parseObject(bytes, ExtensionsType.class);
    extraExtensions.validate();

    List<X509ExtensionType> extnConfs = extraExtensions.getExtensions();
    if (CollectionUtil.isNotEmpty(extnConfs)) {
      for (X509ExtensionType m : extnConfs) {
        byte[] encodedExtnValue =
            m.getConstant().toASN1Encodable().toASN1Primitive().getEncoded(ASN1Encoding.DER);
        new Extension(new ASN1ObjectIdentifier(m.getType().getOid()), false, encodedExtnValue);
      }
    }
  } // method check

  private static void extensionsEeCompelx(String destFilename) throws Exception {
    ExtensionsType extensions = new ExtensionsType();
    // Extensions
    // Extensions - general
    List<X509ExtensionType> list = new LinkedList<>();
    extensions.setExtensions(list);

    // extension subjectDirectoryAttributes (RFC 3739)
    /*
         SubjectDirectoryAttributes ::= Attributes
          Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
          Attribute ::= SEQUENCE
          {
            type AttributeType
            values SET OF AttributeValue
          }

          AttributeType ::= OBJECT IDENTIFIER
          AttributeValue ::= ANY DEFINED BY AttributeType
    */
    X509ExtensionType sdaExt = new X509ExtensionType();
    list.add(sdaExt);

    sdaExt.setType(
        createOidType(Extension.subjectDirectoryAttributes, "subjectDirectoryAttributes"));

    ConstantExtnValue sdaSyntax = new ConstantExtnValue(FieldType.SEQUENCE_OF);
    sdaExt.setConstant(sdaSyntax);

    // CHECKSTYLE:SKIP
    List<ConstantExtnValue> sdaSyntax_values = new LinkedList<>();
    sdaSyntax.setListValue(sdaSyntax_values);

    List<ASN1ObjectIdentifier> types = new LinkedList<>();
    List<FieldType> attrTypes = new LinkedList<>();
    List<String> attrValues = new LinkedList<>();

    // dateOfBirth
    types.add(ObjectIdentifiers.DN.dateOfBirth);
    attrTypes.add(FieldType.GeneralizedTime);
    attrValues.add("19800122120000Z");

    // Gender
    types.add(ObjectIdentifiers.DN.gender);
    attrTypes.add(FieldType.PrintableString);
    attrValues.add("M");

    // placeOfBirth
    types.add(ObjectIdentifiers.DN.placeOfBirth);
    attrTypes.add(FieldType.UTF8String);
    attrValues.add("Berlin");

    // placeOfBirth
    types.add(ObjectIdentifiers.DN.countryOfCitizenship);
    attrTypes.add(FieldType.PrintableString);
    attrValues.add("DE");

    types.add(ObjectIdentifiers.DN.countryOfCitizenship);
    attrTypes.add(FieldType.PrintableString);
    attrValues.add("FR");

    // countryOfResidence
    types.add(ObjectIdentifiers.DN.countryOfResidence);
    attrTypes.add(FieldType.PrintableString);
    attrValues.add("DE");

    for (int i = 0; i < types.size(); i++) {
      ConstantExtnValue attribute = new ConstantExtnValue(FieldType.SEQUENCE);
      sdaSyntax_values.add(attribute);

      // CHECKSTYLE:SKIP
      List<ConstantExtnValue> attribute_values = new LinkedList<>();
      attribute.setListValue(attribute_values);

      ConstantExtnValue type = new ConstantExtnValue(FieldType.OID);
      attribute_values.add(type);
      type.setValue(types.get(i).getId());
      String desc = ObjectIdentifiers.getName(types.get(i));
      if (desc != null) {
        type.setDescription(desc);
      }

      ConstantExtnValue values = new ConstantExtnValue(FieldType.SET);
      attribute_values.add(values);

      // CHECKSTYLE:SKIP
      List<ConstantExtnValue> values_values = new LinkedList<>();
      values.setListValue(values_values);

      ConstantExtnValue value = new ConstantExtnValue(attrTypes.get(i));
      values_values.add(value);
      value.setValue(attrValues.get(i));
    }

    marshall(extensions, destFilename);
  } // method extensionsEeCompelx

  private static void extensionsSyntaxExt(String destFilename, ASN1ObjectIdentifier oidPrefix,
      Tag tag) throws Exception {
    ExtensionsType extensions = new ExtensionsType();
    // Extensions
    // Extensions - general
    List<X509ExtensionType> list = new LinkedList<>();
    extensions.setExtensions(list);
    list.addAll(createConstantExtensions(oidPrefix, tag));
    marshall(extensions, destFilename);
  } // method extensionsSyntaxExt

  private static List<X509ExtensionType> createConstantExtensions(ASN1ObjectIdentifier oidPrefix,
      Tag tag) {
    List<X509ExtensionType> list = new LinkedList<>();

    // Custom Constant Extension Value
    list.add(createConstantExtension(oidPrefix.branch("1"), tag, FieldType.BIT_STRING,
        Base64.encodeToString(new byte[] {1, 2})));
    list.add(createConstantExtension(oidPrefix.branch("2"), tag, FieldType.BMPString,
        "A BMP string"));
    list.add(createConstantExtension(oidPrefix.branch("3"), tag, FieldType.BOOLEAN,
        Boolean.TRUE.toString()));
    list.add(createConstantExtension(oidPrefix.branch("4"), tag, FieldType.IA5String,
        "An IA5 string"));
    list.add(createConstantExtension(oidPrefix.branch("5"), tag, FieldType.INTEGER,
        "10"));
    list.add(createConstantExtension(oidPrefix.branch("6"), tag, FieldType.NULL,
        null));
    list.add(createConstantExtension(oidPrefix.branch("7"), tag, FieldType.OCTET_STRING,
        Base64.encodeToString(new byte[] {3, 4})));
    list.add(createConstantExtension(oidPrefix.branch("8"), tag, FieldType.OID,
        "2.3.4.5"));
    list.add(createConstantExtension(oidPrefix.branch("9"), tag, FieldType.PrintableString,
        "A printable string"));

    list.add(createConstantExtension(oidPrefix.branch("10"), tag, FieldType.NULL,
        null));

    list.add(createConstantExtension(oidPrefix.branch("11"), tag, FieldType.TeletexString,
        "A teletax string"));
    list.add(createConstantExtension(oidPrefix.branch("12"), tag, FieldType.UTF8String,
        "A UTF8 string"));
    list.add(createConstantExtension(oidPrefix.branch("13"), tag, FieldType.ENUMERATED,
        "2"));
    list.add(createConstantExtension(oidPrefix.branch("14"), tag, FieldType.GeneralizedTime,
        new ASN1GeneralizedTime("20180314130102Z").getTimeString()));
    list.add(createConstantExtension(oidPrefix.branch("15"), tag, FieldType.UTCTime,
        "190314130102Z"));
    list.add(createConstantExtension(oidPrefix.branch("16"), tag, FieldType.Name,
        "CN=abc,C=DE"));

    list.add(createConstantExtension(oidPrefix.branch("17"), tag, FieldType.SEQUENCE, null));
    last(list).getConstant().setListValue(createConstantSequenceOrSet());

    list.add(createConstantExtension(oidPrefix.branch("18"), tag, FieldType.SEQUENCE_OF, null));
    last(list).getConstant().setListValue(createConstantSequenceOfOrSetOf());

    list.add(createConstantExtension(oidPrefix.branch("19"), tag, FieldType.SET, null));
    last(list).getConstant().setListValue(createConstantSequenceOrSet());

    list.add(createConstantExtension(oidPrefix.branch("20"), tag, FieldType.SET_OF, null));
    last(list).getConstant().setListValue(createConstantSequenceOfOrSetOf());

    return list;
  } // method createConstantExtensions

  private static X509ExtensionType createConstantExtension(ASN1ObjectIdentifier type, Tag tag,
      FieldType fieldType, String value) {
    X509ExtensionType ret = new X509ExtensionType();
    // children
    String desc = "custom constant extension " + fieldType.getText();
    if (tag != null) {
      desc += " (" + tag.getValue() + ", " + (tag.isExplicit() ? "EXPLICIT)" : "IMPLICIT)");
    }

    ret.setType(createOidType(type, desc));

    ret.setConstant(new ConstantExtnValue(fieldType));
    if (value != null) {
      ret.getConstant().setValue(value);
    }
    if (tag != null) {
      ret.getConstant().setTag(tag);
    }
    return ret;
  } // method createConstantExtension

  private static List<ConstantExtnValue> createConstantSequenceOrSet() {
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

  private static List<ConstantExtnValue> createConstantSequenceOfOrSetOf() {
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

  private static void extensionsAppleWwdr(String destFilename) throws Exception {
    ExtensionsType extensions = new ExtensionsType();
    List<X509ExtensionType> list = new LinkedList<>();
    extensions.setExtensions(list);

    /*
     *  1. SEQUENCE or SET {
     *  2.   UTF8String abc.def.myBlog EXPLICIT
     *  3.   SEQUENCE
     *  4.     UTF8String app
     *  5.   UTF8String abc.def.myBlog.voip EXPLICIT
     *  6.   SEQUENCE EXPLICIT
     *  7.     UTF8String voip
     *  8.   UTF8String abc.def.myBlog.complication IMPLICIT
     *  9.   SEQUENCE IMPLICIT
     * 10.     UTF8String complication
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
    subField.setValue("abc.def.myBlog.voip");

    // Line 6-7
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("void");
    subField.setListValue(Arrays.asList(subsubField));

    // Line 8
    subField = new ConstantExtnValue(FieldType.UTF8String);
    subFields.add(subField);
    subField.setValue("abc.def.myBlog.complication");

    // Line 9-10
    subField = new ConstantExtnValue(FieldType.SEQUENCE);
    subFields.add(subField);
    subsubField = new ConstantExtnValue(FieldType.UTF8String);
    subsubField.setValue("complication");
    subField.setListValue(Arrays.asList(subsubField));

    X509ExtensionType extn = new X509ExtensionType();
    list.add(extn);

    // children
    extn.setType(createOidType(new ASN1ObjectIdentifier("1.2.840.113635.100.6.3.6"),
        "custom apple extension"));
    ConstantExtnValue extnValue = new ConstantExtnValue(FieldType.SEQUENCE);
    extnValue.setListValue(subFields);
    extn.setConstant(extnValue);

    marshall(extensions, destFilename);
  } // method extensionsAppleWwdr

  private static void extensionsGmt0015(String destFilename) throws Exception {
    ExtensionsType extensions = new ExtensionsType();
    List<X509ExtensionType> list = new LinkedList<>();
    extensions.setExtensions(list);

    /*
     * Extension IdentityCode
     *   [0] 362323880212651 IMPLICIT
     */
    ConstantExtnValue subField = new ConstantExtnValue(FieldType.PrintableString);
    subField.setValue("362323880212651");
    subField.setTag(new Tag(0, false));

    X509ExtensionType extn = new X509ExtensionType();
    list.add(extn);
    extn.setType(createOidType(Extn.id_GMT_0015_IdentityCode, null));
    extn.setConstant(subField);

    Map<ASN1ObjectIdentifier, String> extns = new HashMap<>();
    extns.put(Extn.id_GMT_0015_InsuranceNumber, "insurance123");
    extns.put(Extn.id_GMT_0015_ICRegistrationNumber, "cor1234");
    extns.put(Extn.id_GMT_0015_OrganizationCode, "orgcode1234");
    extns.put(Extn.id_GMT_0015_TaxationNumber, "taxcode1234");
    for (ASN1ObjectIdentifier type : extns.keySet()) {
      subField = new ConstantExtnValue(FieldType.PrintableString);
      subField.setValue(extns.get(type));

      extn = new X509ExtensionType();
      list.add(extn);
      extn.setType(createOidType(type, null));
      extn.setConstant(subField);
    }

    marshall(extensions, destFilename);
  } // method extensionsGmt0015

  private static DescribableOid createOidType(ASN1ObjectIdentifier oid, String description) {
    DescribableOid ret = new DescribableOid();
    ret.setOid(oid.getId());

    String desc = (description == null) ? ObjectIdentifiers.getName(oid) : description;
    if (desc != null) {
      ret.setDescription(desc);
    }
    return ret;
  } // method createOidType

  private static <T> T last(List<T> list) {
    if (list == null || list.isEmpty()) {
      return null;
    } else {
      return list.get(list.size() - 1);
    }
  } // method last

}
