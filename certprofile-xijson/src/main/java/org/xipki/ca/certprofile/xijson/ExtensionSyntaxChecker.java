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

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.TextVadidator;
import org.xipki.ca.certprofile.xijson.conf.ExtnSyntax;
import org.xipki.ca.certprofile.xijson.conf.ExtnSyntax.SubFieldSyntax;
import org.xipki.security.X509ExtensionType.FieldType;
import org.xipki.security.X509ExtensionType.Tag;

import java.util.ArrayList;
import java.util.List;

/**
 * The extension syntax checker.
 *
 * @author Lijun Liao
 */

public class ExtensionSyntaxChecker {

  // CHECKSTYLE:SKIP
  private static class ASN1ObjectHolder {
    private ASN1Encodable object;
  }

  public static void checkExtension(String name, ASN1Encodable extnValue, ExtnSyntax syntax)
      throws BadCertTemplateException {
    checkField(name, extnValue, syntax);
  }

  private static void checkField(String name, ASN1Encodable extnValue, ExtnSyntax syntax)
      throws BadCertTemplateException {
    ASN1TaggedObject taggedExtnValue = null;
    Tag extnTag = null;
    if (extnValue instanceof ASN1TaggedObject) {
      taggedExtnValue = (ASN1TaggedObject) extnValue;
      extnTag = new Tag(taggedExtnValue.getTagNo(), taggedExtnValue.isExplicit());
    }

    Tag expectedTag = syntax.getTag();

    if (expectedTag == null ^ extnTag == null) {
      // exactly one is not null
      throw new BadCertTemplateException("invalid " + name);
    } else if (expectedTag != null) {
      // both are not null
      if (expectedTag.getValue() != extnTag.getValue()) {
        throw new BadCertTemplateException("invalid " + name);
      } else if (expectedTag.isExplicit()) {
        if (!extnTag.isExplicit()) {
          throw new BadCertTemplateException("invalid " + name);
        }
      }
    }

    if (extnTag != null && !extnTag.isExplicit()) {
      extnValue = getParsedImplicitValue(name, taggedExtnValue, syntax.type());
    } else {
      if (extnTag != null && extnTag.isExplicit()) {
        extnValue = taggedExtnValue.getObject();
      }

      try {
        switch (syntax.type()) {
          case BIT_STRING:
            extnValue = DERBitString.getInstance(extnValue);
            break;
          case BMPString:
            extnValue = DERBMPString.getInstance(extnValue);
            break;
          case BOOLEAN:
            extnValue = ASN1Boolean.getInstance(extnValue);
            break;
          case ENUMERATED:
            extnValue = ASN1Enumerated.getInstance(extnValue);
            break;
          case GeneralizedTime:
            extnValue = DERGeneralizedTime.getInstance(extnValue);
            break;
          case IA5String:
            extnValue = DERIA5String.getInstance(extnValue);
            break;
          case INTEGER:
            extnValue = ASN1Integer.getInstance(extnValue);
            break;
          case Name:
            extnValue = X500Name.getInstance(extnValue);
            break;
          case NULL:
            extnValue = DERNull.getInstance(extnValue);
            break;
          case OCTET_STRING:
            extnValue = DEROctetString.getInstance(extnValue);
            break;
          case OID:
            extnValue = ASN1ObjectIdentifier.getInstance(extnValue);
            break;
          case PrintableString:
            extnValue = DERPrintableString.getInstance(extnValue);
            break;
          case RAW:
            break;
          case SEQUENCE:
          case SEQUENCE_OF:
            extnValue = ASN1Sequence.getInstance(extnValue);
            break;
          case SET:
          case SET_OF:
            extnValue = ASN1Set.getInstance(extnValue);
            break;
          case TeletexString:
            extnValue = DERT61String.getInstance(extnValue);
            break;
          case UTCTime:
            extnValue = DERUTCTime.getInstance(extnValue);
            break;
          case UTF8String:
            extnValue = DERUTF8String.getInstance(extnValue);
            break;
          default:
            throw new RuntimeException("Unknown FieldType " + syntax.type());
        }
      } catch (IllegalArgumentException ex) {
        throw new BadCertTemplateException("invalid " + name, ex);
      }
    }

    checkContentTextOrSubFields(name, syntax, extnValue);
  } // method checkField

  private static void checkSequenceSyntax(String name, ASN1Sequence seq,
      List<SubFieldSyntax> subFields)
          throws BadCertTemplateException {
    final int subFieldsSize = subFields.size();
    int subFieldsIndex = 0;

    final int size = seq.size();

    for (int i = 0; i < size; i++) {
      ASN1Encodable obj = seq.getObjectAt(i);

      Tag tag = null;
      if (obj instanceof ASN1TaggedObject) {
        ASN1TaggedObject taggedObj = (ASN1TaggedObject) obj;
        tag = new Tag(taggedObj.getTagNo(), taggedObj.isExplicit());
      }

      // find the matched SubField
      int matchIndex = -1;
      for (int j = subFieldsIndex; j < subFieldsSize; j++) {
        SubFieldSyntax subFieldSyntax = subFields.get(j);
        FieldType syntaxType = subFieldSyntax.type();
        Tag syntaxTag = subFieldSyntax.getTag();

        if (tag != null) {
          if (syntaxTag != null && (syntaxTag.getValue() == tag.getValue())) {
            if (syntaxTag.isExplicit() && tag.isExplicit()) {
              obj = ((ASN1TaggedObject) obj).getObject();
              FieldType expectedType = getFieldType(obj);
              if ((syntaxType == expectedType)
                  || (syntaxType == FieldType.SEQUENCE_OF && expectedType == FieldType.SEQUENCE)
                  || (syntaxType == FieldType.SET_OF && expectedType == FieldType.SET)) {
                matchIndex = j;
              }
            } else if (!syntaxTag.isExplicit() && !tag.isExplicit()) {
              obj = getParsedImplicitValue(name, (ASN1TaggedObject) obj, syntaxType);
              matchIndex = j;
            } else if (!syntaxTag.isExplicit() && tag.isExplicit()) {
              // 1. [t] IMPLICIT SEQUENCE { type } is wired the same as [t] EXPLICIT type
              // 2. [t] IMPLICIT      SET { type } is wired the same as [t] EXPLICIT type
              if (syntaxType == FieldType.SEQUENCE || syntaxType == FieldType.SEQUENCE_OF) {
                obj = new DERSequence(((ASN1TaggedObject) obj).getObject());
                matchIndex = j;
              } else if (syntaxType == FieldType.SET || syntaxType == FieldType.SET_OF) {
                obj = new DERSet(((ASN1TaggedObject) obj).getObject());
                matchIndex = j;
              }
            }
            break;
          }
        } else if (syntaxTag == null) {
          FieldType expectedType = getFieldType(obj);
          if ((syntaxType == expectedType)
              || (syntaxType == FieldType.SEQUENCE_OF && expectedType == FieldType.SEQUENCE)
              || (syntaxType == FieldType.SET_OF && expectedType == FieldType.SET)) {
            matchIndex = j;
            break;
          }
        }

        if (subFieldSyntax.isRequired()) {
          // cannot be skipped
          throw new BadCertTemplateException("invalid " + name);
        }
      }

      if (matchIndex == -1) {
        throw new BadCertTemplateException("invalid " + name);
      }

      SubFieldSyntax syntax = subFields.get(matchIndex);
      subFieldsIndex = matchIndex + 1;

      checkContentTextOrSubFields(name, syntax, obj);
    }

    // make sure that all required fields are present
    if (subFieldsIndex < subFieldsSize) {
      for (; subFieldsIndex < subFieldsSize; subFieldsIndex++) {
        if (subFields.get(subFieldsIndex).isRequired()) {
          throw new BadCertTemplateException("invalid " + name);
        }
      }
    }
  } // method checkSequenceSyntax

  private static void checkSetSyntax(String name, ASN1Set set, List<SubFieldSyntax> subFields)
      throws BadCertTemplateException {
    List<SubFieldSyntax> subFields0 = new ArrayList<>(subFields);

    final int size = set.size();

    for (int i = 0; i < size; i++) {
      ASN1ObjectHolder objHolder = new ASN1ObjectHolder();
      objHolder.object = set.getObjectAt(i);
      // find the matched SubField
      SubFieldSyntax syntax = getSyntax(name, objHolder, subFields0);

      if (syntax == null) {
        throw new BadCertTemplateException("invalid " + name);
      }

      subFields0.remove(syntax);
      checkContentTextOrSubFields(name, syntax, objHolder.object);
    }

    for (SubFieldSyntax m : subFields0) {
      if (m.isRequired()) {
        throw new BadCertTemplateException("invalid " + name);
      }
    }
  } // method checkSetSyntax

  private static SubFieldSyntax getSyntax(String name, ASN1ObjectHolder objHolder,
      List<SubFieldSyntax> subFields)
          throws BadCertTemplateException {
    // find the matched SubField
    ASN1Encodable obj = objHolder.object;

    SubFieldSyntax syntax = null;
    if (obj instanceof ASN1TaggedObject) {
      ASN1TaggedObject taggedObj = (ASN1TaggedObject) obj;
      Tag tag = new Tag(taggedObj.getTagNo(), taggedObj.isExplicit());

      for (SubFieldSyntax m : subFields) {
        // found the syntax with given tag.
        if (m.getTag() != null && m.getTag().getValue() == tag.getValue()) {
          if (m.getTag().isExplicit() == tag.isExplicit()) {
            syntax = m;
          } else if (!m.getTag().isExplicit()) {
            // 1. [t] IMPLICIT SEQUENCE { type } is wired the same as [t] EXPLICIT type
            // 2. [t] IMPLICIT      SET { type } is wired the same as [t] EXPLICIT type
            FieldType type = m.type();
            if (type == FieldType.SEQUENCE || type == FieldType.SEQUENCE_OF) {
              obj = new DERSequence(((ASN1TaggedObject) obj).getObject());
              syntax = m;
            } else if (type == FieldType.SET || type == FieldType.SET_OF) {
              obj = new DERSet(((ASN1TaggedObject) obj).getObject());
              syntax = m;
            }
          } else {
            throw new BadCertTemplateException("invalid " + name);
          }

          if (syntax != null) {
            break;
          }
        }
      } // end for

      if (syntax != null) {
        if (syntax.getTag().isExplicit()) {
          obj = taggedObj.getObject();
          FieldType expectedType = getFieldType(obj);
          FieldType syntaxType = syntax.type();

          if (!((syntaxType == expectedType)
                  || (syntaxType == FieldType.SEQUENCE_OF && expectedType == FieldType.SEQUENCE)
                  || (syntaxType == FieldType.SET_OF && expectedType == FieldType.SET))) {
            throw new BadCertTemplateException("invalid " + name);
          }
        } else {
          obj = getParsedImplicitValue(name, taggedObj, syntax.type());
        }
      }
    } else {
      FieldType expectedType = getFieldType(obj);

      for (SubFieldSyntax m : subFields) {
        FieldType syntaxType = m.type();

        if ((m.getTag() == null)
            && (syntaxType == expectedType
            || (syntaxType == FieldType.SEQUENCE_OF && expectedType == FieldType.SEQUENCE)
            || (syntaxType == FieldType.SET_OF && expectedType == FieldType.SET))) {
          syntax = m;
          break;
        }
      }
    }

    objHolder.object = obj;
    return syntax;
  } // method getSyntax

  private static void checkSequenceOfOrSetOfSyntax(String name, ASN1Sequence seq,
      ASN1Set set, List<SubFieldSyntax> subFields)
          throws BadCertTemplateException {
    final int size = (seq != null) ? seq.size() : set.size();

    for (int i = 0; i < size; i++) {
      ASN1ObjectHolder objHolder = new ASN1ObjectHolder();
      objHolder.object = (seq != null) ? seq.getObjectAt(i) : set.getObjectAt(i);
      SubFieldSyntax subField = getSyntax(name, objHolder, subFields);
      if (subField == null) {
        throw new BadCertTemplateException("invalid " + name);
      }
      checkField(name, objHolder.object, subField);
    }
  } // method checkSequenceOfOrSetOfSyntax

  private static FieldType getFieldType(ASN1Encodable obj) {
    FieldType expectedType;
    if (obj instanceof DERBitString) {
      expectedType = FieldType.BIT_STRING;
    } else if (obj instanceof DERBMPString) {
      expectedType = FieldType.BMPString;
    } else if (obj instanceof ASN1Boolean) {
      expectedType = FieldType.BOOLEAN;
    } else if (obj instanceof ASN1Enumerated) {
      expectedType = FieldType.ENUMERATED;
    } else if (obj instanceof DERGeneralizedTime) {
      expectedType = FieldType.GeneralizedTime;
    } else if (obj instanceof DERIA5String) {
      expectedType = FieldType.IA5String;
    } else if (obj instanceof ASN1Integer) {
      expectedType = FieldType.INTEGER;
    } else if (obj instanceof DERNull) {
      expectedType = FieldType.NULL;
    } else if (obj instanceof DEROctetString) {
      expectedType = FieldType.OCTET_STRING;
    } else if (obj instanceof ASN1ObjectIdentifier) {
      expectedType = FieldType.OID;
    } else if (obj instanceof DERPrintableString) {
      expectedType = FieldType.PrintableString;
    } else if (obj instanceof DERT61String) {
      expectedType = FieldType.TeletexString;
    } else if (obj instanceof DERUTCTime) {
      expectedType = FieldType.UTCTime;
    } else if (obj instanceof DERUTF8String) {
      expectedType = FieldType.UTF8String;
    } else if (obj instanceof X500Name) {
      expectedType = FieldType.Name;
    } else if (obj instanceof ASN1Sequence) {
      try {
        X500Name.getInstance(obj);
        expectedType = FieldType.Name;
      } catch (Exception ex) {
        expectedType = FieldType.SEQUENCE;
      }
    } else if (obj instanceof ASN1Set) {
      expectedType = FieldType.SET;
    } else {
      expectedType = null;
    }

    return expectedType;
  } // method getFieldType

  private static void assertMatch(String name, String pattern, String text)
      throws BadCertTemplateException {
    if (!TextVadidator.compile(pattern).isValid(text)) {
      throw new BadCertTemplateException(
          String.format("invalid %s '%s' against regex '%s'", name, text, pattern));
    }
  } // method assertMatch

  private static ASN1Encodable getParsedImplicitValue(String name, ASN1TaggedObject taggedObject,
      FieldType fieldType)
          throws BadCertTemplateException {
    try {
      switch (fieldType) {
        case BIT_STRING:
          return DERBitString.getInstance(taggedObject, false);
        case BMPString:
          return DERBMPString.getInstance(taggedObject, false);
        case BOOLEAN:
          return ASN1Boolean.getInstance(taggedObject, false);
        case ENUMERATED:
          return ASN1Enumerated.getInstance(taggedObject, false);
        case GeneralizedTime:
          return DERGeneralizedTime.getInstance(taggedObject, false);
        case IA5String:
          return DERIA5String.getInstance(taggedObject, false);
        case INTEGER:
          return ASN1Integer.getInstance(taggedObject, false);
        case Name:
          return X500Name.getInstance(taggedObject, false);
        case NULL:
          if (!(taggedObject.getObject() instanceof ASN1OctetString
              && ((ASN1OctetString) taggedObject.getObject()).getOctets().length == 0)) {
            throw new BadCertTemplateException("invalid " + name);
          }
          return DERNull.INSTANCE;
        case OCTET_STRING:
          return DEROctetString.getInstance(taggedObject, false);
        case OID:
          return ASN1ObjectIdentifier.getInstance(taggedObject, false);
        case PrintableString:
          return DERPrintableString.getInstance(taggedObject, false);
        case RAW:
          return taggedObject.getObject();
        case SEQUENCE:
        case SEQUENCE_OF:
          return ASN1Sequence.getInstance(taggedObject, false);
        case SET:
        case SET_OF:
          return ASN1Set.getInstance(taggedObject, false);
        case TeletexString:
          return DERT61String.getInstance(taggedObject, false);
        case UTCTime:
          return DERUTCTime.getInstance(taggedObject, false);
        case UTF8String:
          return DERUTF8String.getInstance(taggedObject, false);
        default:
          throw new RuntimeException("Unknown FieldType " + fieldType);
      }
    } catch (IllegalArgumentException ex) {
      throw new BadCertTemplateException("invalid " + name, ex);
    }
  } // method getParsedImplicitValue

  private static void checkContentTextOrSubFields(String name, ExtnSyntax subField,
      ASN1Encodable obj)
          throws BadCertTemplateException {
    if (obj instanceof ASN1String) {
      if (subField.getStringRegex() != null) {
        assertMatch(name, subField.getStringRegex(), ((ASN1String) obj).getString());
      }
      return;
    }

    FieldType syntaxType = subField.type();
    if (syntaxType == FieldType.SEQUENCE) {
      checkSequenceSyntax(name, (ASN1Sequence) obj, subField.getSubFields());
    } else if (syntaxType == FieldType.SET) {
      checkSetSyntax(name, (ASN1Set) obj, subField.getSubFields());
    } else if (syntaxType == FieldType.SEQUENCE_OF) {
      checkSequenceOfOrSetOfSyntax(name, (ASN1Sequence) obj, null, subField.getSubFields());
    } else if (syntaxType == FieldType.SET_OF) {
      checkSequenceOfOrSetOfSyntax(name, null, (ASN1Set) obj, subField.getSubFields());
    }
  } // method checkContentTextOrSubFields

}
