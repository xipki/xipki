// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca.extn;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CertPolicyId;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.xipki.ca.api.profile.Certprofile.ExtensionControl;
import org.xipki.ca.api.profile.Certprofile.GeneralNameMode;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.SubjectDirectoryAttributesControl;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyConstraints;
import org.xipki.ca.certprofile.xijson.conf.extn.PolicyMappings;
import org.xipki.ca.certprofile.xijson.conf.extn.QcStatements;
import org.xipki.ca.certprofile.xijson.conf.extn.TlsFeature;
import org.xipki.pki.BadCertTemplateException;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.ObjectIdentifiers.Extn;
import org.xipki.security.ctlog.CtLog.SignedCertificateTimestampList;
import org.xipki.security.util.X509Util;
import org.xipki.util.CollectionUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.Validity;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.Vector;

import static org.xipki.qa.ca.extn.CheckerUtil.addViolation;
import static org.xipki.qa.ca.extn.CheckerUtil.createGeneralName;
import static org.xipki.qa.ca.extn.CheckerUtil.hex;
import static org.xipki.qa.ca.extn.CheckerUtil.strInBnotInA;

/**
 * Checker for extensions whose name is from O to T.
 * @author Lijun Liao (xipki)
 */

class O2tChecker extends ExtensionChecker {

  private static final byte[] DER_NULL = new byte[] {5, 0};

  O2tChecker(ExtensionsChecker parent) {
    super(parent);
  }

  void checkExtnOcspNocheck(StringBuilder failureMsg, byte[] extnValue) {
    if (!Arrays.equals(DER_NULL, extnValue)) {
      failureMsg.append("value is not DER NULL; ");
    }
  }

  void checkExtnPolicyConstraints(StringBuilder failureMsg, byte[] extnValue,
      Extensions requestedExtns, ExtensionControl extnControl) {
    PolicyConstraints conf = caller.getPolicyConstraints();
    if (conf == null) {
      caller.checkConstantExtnValue(Extension.policyConstraints, failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    org.bouncycastle.asn1.x509.PolicyConstraints isPolicyConstraints =
        org.bouncycastle.asn1.x509.PolicyConstraints.getInstance(extnValue);
    Integer expRequireExplicitPolicy = conf.getRequireExplicitPolicy();
    BigInteger bigInt = isPolicyConstraints.getRequireExplicitPolicyMapping();
    Integer isRequireExplicitPolicy = (bigInt == null) ? null : bigInt.intValue();

    boolean match = true;
    if (expRequireExplicitPolicy == null) {
      if (isRequireExplicitPolicy != null) {
        match = false;
      }
    } else if (!expRequireExplicitPolicy.equals(isRequireExplicitPolicy)) {
      match = false;
    }

    if (!match) {
      addViolation(failureMsg, "requireExplicitPolicy", isRequireExplicitPolicy, expRequireExplicitPolicy);
    }

    Integer expInhibitPolicyMapping = conf.getInhibitPolicyMapping();
    bigInt = isPolicyConstraints.getInhibitPolicyMapping();
    Integer isInhibitPolicyMapping = (bigInt == null) ? null : bigInt.intValue();

    match = true;
    if (expInhibitPolicyMapping == null) {
      if (isInhibitPolicyMapping != null) {
        match = false;
      }
    } else if (!expInhibitPolicyMapping.equals(isInhibitPolicyMapping)) {
      match = false;
    }

    if (!match) {
      addViolation(failureMsg, "inhibitPolicyMapping", isInhibitPolicyMapping, expInhibitPolicyMapping);
    }
  } // method checkExtnPolicyConstraints

  void checkExtnPolicyMappings(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns, ExtensionControl extnControl) {
    PolicyMappings conf = caller.getPolicyMappings();
    if (conf == null) {
      caller.checkConstantExtnValue(Extension.policyMappings, failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    ASN1Sequence isPolicyMappings = DERSequence.getInstance(extnValue);
    Map<String, String> isMap = new HashMap<>();
    int size = isPolicyMappings.size();
    for (int i = 0; i < size; i++) {
      ASN1Sequence seq = ASN1Sequence.getInstance(isPolicyMappings.getObjectAt(i));
      CertPolicyId issuerDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(0));
      CertPolicyId subjectDomainPolicy = CertPolicyId.getInstance(seq.getObjectAt(1));
      isMap.put(issuerDomainPolicy.getId(), subjectDomainPolicy.getId());
    }

    for (PolicyMappings.PolicyIdMappingType m : conf.getMappings()) {
      String expIssuerDomainPolicy = m.getIssuerDomainPolicy().getOid();
      String expSubjectDomainPolicy = m.getSubjectDomainPolicy().getOid();

      String isSubjectDomainPolicy = isMap.remove(expIssuerDomainPolicy);
      if (isSubjectDomainPolicy == null) {
        failureMsg.append("issuerDomainPolicy '").append(expIssuerDomainPolicy).append("' is absent but is required; ");
      } else if (!isSubjectDomainPolicy.equals(expSubjectDomainPolicy)) {
        addViolation(failureMsg, "subjectDomainPolicy for issuerDomainPolicy",
            isSubjectDomainPolicy, expSubjectDomainPolicy);
      }
    }

    if (CollectionUtil.isNotEmpty(isMap)) {
      failureMsg.append("issuerDomainPolicies '").append(isMap.keySet()).append("' are present but not expected; ");
    }
  } // method checkExtnMappings

  void checkExtnPrivateKeyUsagePeriod(
      StringBuilder failureMsg, byte[] extnValue, Instant certNotBefore, Instant certNotAfter) {
    ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(Date.from(certNotBefore));
    Instant dateNotAfter;
    Validity privateKeyUsagePeriod = getCertprofile().extensions().getPrivateKeyUsagePeriod();
    if (privateKeyUsagePeriod == null) {
      dateNotAfter = certNotAfter;
    } else {
      dateNotAfter = privateKeyUsagePeriod.add(certNotBefore);
      if (dateNotAfter.isAfter(certNotAfter)) {
        dateNotAfter = certNotAfter;
      }
    }
    ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(Date.from(dateNotAfter));

    org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod extValue =
        org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod.getInstance(extnValue);

    ASN1GeneralizedTime time = extValue.getNotBefore();
    if (time == null) {
      failureMsg.append("notBefore is absent but expected present; ");
    } else if (!time.equals(notBefore)) {
      addViolation(failureMsg, "notBefore", time.getTimeString(), notBefore.getTimeString());
    }

    time = extValue.getNotAfter();
    if (time == null) {
      failureMsg.append("notAfter is absent but expected present; ");
    } else if (!time.equals(notAfter)) {
      addViolation(failureMsg, "notAfter", time.getTimeString(), notAfter.getTimeString());
    }
  } // method checkExtnPrivateKeyUsagePeriod

  void checkExtnQcStatements(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns, ExtensionControl extnControl) {
    QcStatements qcStatements = caller.getQcStatements();
    if (qcStatements == null) {
      caller.checkConstantExtnValue(Extension.qCStatements, failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    final int expSize = qcStatements.getQcStatements().size();
    ASN1Sequence extValue = ASN1Sequence.getInstance(extnValue);
    final int isSize = extValue.size();
    if (isSize != expSize) {
      addViolation(failureMsg, "number of statements", isSize, expSize);
      return;
    }

    // extract the euLimit and pdsLocations data from request
    Map<String, int[]> reqQcEuLimits = new HashMap<>();
    Extension reqExtension = (requestedExtns == null) ? null : requestedExtns.getExtension(Extension.qCStatements);
    if (reqExtension != null) {
      ASN1Sequence seq = ASN1Sequence.getInstance(reqExtension.getParsedValue());

      final int n = seq.size();
      for (int j = 0; j < n; j++) {
        QCStatement stmt = QCStatement.getInstance(seq.getObjectAt(j));
        if (Extn.id_etsi_qcs_QcLimitValue.equals(stmt.getStatementId())) {
          MonetaryValue monetaryValue = MonetaryValue.getInstance(stmt.getStatementInfo());
          int amount = monetaryValue.getAmount().intValue();
          int exponent = monetaryValue.getExponent().intValue();
          Iso4217CurrencyCode currency = monetaryValue.getCurrency();
          String currencyS = currency.isAlphabetic()
              ? currency.getAlphabetic().toUpperCase() : Integer.toString(currency.getNumeric());
          reqQcEuLimits.put(currencyS, new int[]{amount, exponent});
        }
      }
    }

    for (int i = 0; i < expSize; i++) {
      QCStatement is = QCStatement.getInstance(extValue.getObjectAt(i));
      QcStatements.QcStatementType exp = qcStatements.getQcStatements().get(i);
      if (!is.getStatementId().getId().equals(exp.getStatementId().getOid())) {
        addViolation(failureMsg, "statmentId[" + i + "]",
            is.getStatementId().getId(), exp.getStatementId().getOid());
        continue;
      }

      if (exp.getStatementValue() == null) {
        if (is.getStatementInfo() != null) {
          addViolation(failureMsg, "statmentInfo[" + i + "]", "present", "absent");
        }
        continue;
      }

      if (is.getStatementInfo() == null) {
        addViolation(failureMsg, "statmentInfo[" + i + "]", "absent", "present");
        continue;
      }

      QcStatements.QcStatementValueType expStatementValue = exp.getStatementValue();
      try {
        if (expStatementValue.getConstant() != null) {
          byte[] expValue = expStatementValue.getConstant().getValue();
          byte[] isValue = is.getStatementInfo().toASN1Primitive().getEncoded();
          if (!Arrays.equals(isValue, expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]", hex(isValue), hex(expValue));
          }
        } else if (expStatementValue.getQcRetentionPeriod() != null) {
          String isValue = ASN1Integer.getInstance(is.getStatementInfo()).toString();
          String expValue = expStatementValue.getQcRetentionPeriod().toString();
          if (!isValue.equals(expValue)) {
            addViolation(failureMsg, "statementInfo[" + i + "]", isValue, expValue);
          }
        } else if (expStatementValue.getPdsLocations() != null) {
          Set<String> pdsLocations = new HashSet<>();
          ASN1Sequence pdsLocsSeq = ASN1Sequence.getInstance(is.getStatementInfo());
          int size = pdsLocsSeq.size();
          for (int k = 0; k < size; k++) {
            ASN1Sequence pdsLocSeq = ASN1Sequence.getInstance(pdsLocsSeq.getObjectAt(k));
            int size2 = pdsLocSeq.size();
            if (size2 != 2) {
              throw new IllegalArgumentException("sequence size is " + size2 + " but expected 2");
            }
            String url = ASN1IA5String.getInstance(pdsLocSeq.getObjectAt(0)).getString();
            String lang = ASN1PrintableString.getInstance(pdsLocSeq.getObjectAt(1)).getString();
            pdsLocations.add("url=" + url + ",lang=" + lang);
          }

          Set<String> expectedPdsLocations = new HashSet<>();
          for (QcStatements.PdsLocationType m : expStatementValue.getPdsLocations()) {
            expectedPdsLocations.add("url=" + m.getUrl() + ",lang=" + m.getLanguage());
          }

          Set<String> diffs = CheckerUtil.strInBnotInA(expectedPdsLocations, pdsLocations);
          if (CollectionUtil.isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ").append(diffs)
              .append(" are present but not expected; ");
          }

          diffs = CheckerUtil.strInBnotInA(pdsLocations, expectedPdsLocations);
          if (CollectionUtil.isNotEmpty(diffs)) {
            failureMsg.append("statementInfo[").append(i).append("]: ").append(diffs)
              .append(" are absent but are required; ");
          }
        } else if (expStatementValue.getQcEuLimitValue() != null) {
          QcStatements.QcEuLimitValueType euLimitConf = expStatementValue.getQcEuLimitValue();
          String expCurrency = euLimitConf.getCurrency().toUpperCase();
          int[] expAmountExp = reqQcEuLimits.get(expCurrency);

          QcStatements.Range2Type range = euLimitConf.getAmount();
          int value;
          if (range.getMin() == range.getMax()) {
            value = range.getMin();
          } else if (expAmountExp != null) {
            value = expAmountExp[0];
          } else {
            failureMsg.append("found no QcEuLimit for currency '").append(expCurrency).append("'; ");
            return;
          }
          String expAmount = Integer.toString(value);

          range = euLimitConf.getExponent();
          if (range.getMin() == range.getMax()) {
            value = range.getMin();
          } else if (expAmountExp != null) {
            value = expAmountExp[1];
          } else {
            failureMsg.append("found no QcEuLimit for currency '").append(expCurrency).append("'; ");
            return;
          }
          String expExponent = Integer.toString(value);

          MonetaryValue monterayValue = MonetaryValue.getInstance(is.getStatementInfo());
          Iso4217CurrencyCode currency = monterayValue.getCurrency();
          String isCurrency = currency.isAlphabetic() ? currency.getAlphabetic()
              : Integer.toString(currency.getNumeric());
          String isAmount = monterayValue.getAmount().toString();
          String isExponent = monterayValue.getExponent().toString();
          if (!isCurrency.equals(expCurrency)) {
            addViolation(failureMsg, "statementInfo[" + i + "].qcEuLimit.currency", isCurrency, expCurrency);
          }
          if (!isAmount.equals(expAmount)) {
            addViolation(failureMsg, "statementInfo[" + i + "].qcEuLimit.amount", isAmount, expAmount);
          }
          if (!isExponent.equals(expExponent)) {
            addViolation(failureMsg, "statementInfo[" + i + "].qcEuLimit.exponent", isExponent, expExponent);
          }
        } else {
          throw new IllegalStateException("statementInfo[" + i + "]should not reach here");
        }
      } catch (IOException ex) {
        failureMsg.append("statementInfo[").append(i).append("] has incorrect syntax; ");
      }
    }
  } // method checkExtnQcStatements

  void checkSmimeCapabilities(StringBuilder failureMsg, byte[] extnValue, ExtensionControl extnControl) {
    byte[] expected = caller.getSmimeCapabilities().getValue();
    if (!Arrays.equals(expected, extnValue)) {
      addViolation(failureMsg, "extension valus", hex(extnValue), hex(expected));
    }
  } // method checkSmimeCapabilities

  void checkScts(StringBuilder failureMsg, byte[] extensionValue, ExtensionControl extControl) {
    // just check the syntax
    try {
      ASN1OctetString octet = DEROctetString.getInstance(extensionValue);
      SignedCertificateTimestampList sctList = SignedCertificateTimestampList.getInstance(octet.getOctets());
      int size = sctList.getSctList().size();
      for (int i = 0; i < size; i++) {
        sctList.getSctList().get(i).getDigitallySigned().getSignatureObject();
      }
    } catch (Exception ex) {
      failureMsg.append("invalid syntax: ").append(ex.getMessage()).append("; ");
    }
  } // method checkScts

  void checkExtnSubjectAltNames(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns,
      ExtensionControl extnControl, X500Name requestedSubject) {
    XijsonCertprofile certprofile = getCertprofile();
    Set<GeneralNameMode> conf = certprofile.getSubjectAltNameModes();

    GeneralName[] requested;
    try {
      requested = getRequestedSubjectAltNames(certprofile, requestedSubject, requestedExtns);
    } catch (CertprofileException | BadCertTemplateException ex) {
      String msg = "error while derive grantedSubject from requestedSubject";
      LogUtil.warn(log, ex, msg);
      failureMsg.append(msg);
      return;
    }

    if (requested == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    GeneralName[] is = GeneralNames.getInstance(extnValue).getNames();

    GeneralName[] expected = new GeneralName[requested.length];
    for (int i = 0; i < is.length; i++) {
      try {
        expected[i] = createGeneralName(is[i], conf);
      } catch (BadCertTemplateException ex) {
        failureMsg.append("could not process ").append(i + 1).append("-th name: ").append(ex.getMessage()).append("; ");
        return;
      }
    }

    if (is.length != expected.length) {
      addViolation(failureMsg, "size of GeneralNames", is.length, expected.length);
      return;
    }

    for (int i = 0; i < is.length; i++) {
      if (!is[i].equals(expected[i])) {
        failureMsg.append(i + 1).append("-th name does not match the requested one; ");
      }
    }
  } // method checkExtnSubjectAltNames

  private GeneralName[] getRequestedSubjectAltNames(
      XijsonCertprofile certprofile, X500Name requestedSubject, Extensions requestedExtns)
      throws CertprofileException, BadCertTemplateException {
    ASN1Encodable extValue = (requestedExtns == null) ? null
        : requestedExtns.getExtensionParsedValue(Extension.subjectAlternativeName);

    Map<ASN1ObjectIdentifier, GeneralNameTag> subjectToSubjectAltNameModes =
        certprofile.extensions().getSubjectToSubjectAltNameModes();
    if (extValue == null && subjectToSubjectAltNameModes == null) {
      return null;
    }

    GeneralNames reqNames = GeneralNames.getInstance(extValue);

    Set<GeneralNameMode> subjectAltNameModes = certprofile.getSubjectAltNameModes();
    if (subjectAltNameModes == null && subjectToSubjectAltNameModes == null) {
      return reqNames.getNames();
    }

    List<GeneralName> grantedNames = new LinkedList<>();
    // copy the required attributes of Subject
    if (subjectToSubjectAltNameModes != null) {
      X500Name grantedSubject = certprofile.getSubject(requestedSubject).getGrantedSubject();

      for (Entry<ASN1ObjectIdentifier, GeneralNameTag> entry : subjectToSubjectAltNameModes.entrySet()) {
        ASN1ObjectIdentifier attrType = entry.getKey();
        GeneralNameTag tag = entry.getValue();

        RDN[] rdns = grantedSubject.getRDNs(attrType);
        if (rdns == null || rdns.length == 0) {
          rdns = requestedSubject.getRDNs(attrType);
        }

        if (rdns == null) {
          continue;
        }

        for (RDN rdn : rdns) {
          String rdnValue = X509Util.rdnValueToString(rdn.getFirst().getValue());
          switch (tag) {
            case rfc822Name:
              grantedNames.add(new GeneralName(tag.getTag(), rdnValue.toLowerCase()));
              break;
            case DNSName:
            case uniformResourceIdentifier:
            case IPAddress:
            case directoryName:
            case registeredID:
              grantedNames.add(new GeneralName(tag.getTag(), rdnValue));
              break;
            default:
              throw new IllegalStateException("should not reach here, unknown GeneralName tag " + tag);
          } // end switch (tag)
        }
      }
    }

    // copy the requested SubjectAltName entries
    if (reqNames != null) {
      GeneralName[] reqL = reqNames.getNames();
      Collections.addAll(grantedNames, reqL);
    }

    return grantedNames.isEmpty() ? null : grantedNames.toArray(new GeneralName[0]);
  } // method getRequestedSubjectAltNames

  void checkExtnSubjectDirAttrs(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns, ExtensionControl extnControl) {
    SubjectDirectoryAttributesControl conf = getCertprofile().extensions().getSubjectDirAttrsControl();
    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Encodable extInRequest = null;
    if (requestedExtns != null) {
      extInRequest = requestedExtns.getExtensionParsedValue(Extension.subjectDirectoryAttributes);
    }

    if (extInRequest == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    SubjectDirectoryAttributes requested = SubjectDirectoryAttributes.getInstance(extInRequest);
    Vector<?> reqSubDirAttrs = requested.getAttributes();
    ASN1GeneralizedTime expDateOfBirth = null;
    String expPlaceOfBirth = null;
    String expGender = null;
    Set<String> expCountryOfCitizenshipList = new HashSet<>();
    Set<String> expCountryOfResidenceList = new HashSet<>();
    Map<ASN1ObjectIdentifier, Set<ASN1Encodable>> expOtherAttrs = new HashMap<>();

    for (Object reqSubDirAttr : reqSubDirAttrs) {
      Attribute attr = Attribute.getInstance(reqSubDirAttr);
      ASN1ObjectIdentifier attrType = attr.getAttrType();
      ASN1Encodable attrVal = attr.getAttributeValues()[0];

      if (ObjectIdentifiers.DN.placeOfBirth.equals(attrType)) {
        expPlaceOfBirth = DirectoryString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.gender.equals(attrType)) {
        expGender = ASN1PrintableString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.countryOfCitizenship.equals(attrType)) {
        String country = ASN1PrintableString.getInstance(attrVal).getString();
        expCountryOfCitizenshipList.add(country);
      } else if (ObjectIdentifiers.DN.countryOfResidence.equals(attrType)) {
        String country = ASN1PrintableString.getInstance(attrVal).getString();
        expCountryOfResidenceList.add(country);
      } else {
        Set<ASN1Encodable> otherAttrVals = expOtherAttrs.computeIfAbsent(attrType, k -> new HashSet<>());
        otherAttrVals.add(attrVal);
      }
    }

    SubjectDirectoryAttributes ext = SubjectDirectoryAttributes.getInstance(extnValue);
    Vector<?> subDirAttrs = ext.getAttributes();
    String placeOfBirth = null;
    String gender = null;
    Set<String> countryOfCitizenshipList = new HashSet<>();
    Set<String> countryOfResidenceList = new HashSet<>();
    Map<ASN1ObjectIdentifier, Set<ASN1Encodable>> otherAttrs = new HashMap<>();

    List<ASN1ObjectIdentifier> attrTypes = new LinkedList<>(conf.getTypes());
    for (Object subDirAttr : subDirAttrs) {
      Attribute attr = Attribute.getInstance(subDirAttr);
      ASN1ObjectIdentifier attrType = attr.getAttrType();
      if (!attrTypes.contains(attrType)) {
        failureMsg.append("attribute of type ").append(attrType.getId()).append(" is present but not expected; ");
        continue;
      }

      ASN1Encodable[] attrs = attr.getAttributeValues();
      if (attrs.length != 1) {
        failureMsg.append("attribute of type ").append(attrType.getId())
            .append(" does not single-value value: ").append(attrs.length).append("; ");
        continue;
      }

      ASN1Encodable attrVal = attrs[0];

      if (ObjectIdentifiers.DN.placeOfBirth.equals(attrType)) {
        placeOfBirth = DirectoryString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.gender.equals(attrType)) {
        gender = ASN1PrintableString.getInstance(attrVal).getString();
      } else if (ObjectIdentifiers.DN.countryOfCitizenship.equals(attrType)) {
        String country = ASN1PrintableString.getInstance(attrVal).getString();
        countryOfCitizenshipList.add(country);
      } else if (ObjectIdentifiers.DN.countryOfResidence.equals(attrType)) {
        String country = ASN1PrintableString.getInstance(attrVal).getString();
        countryOfResidenceList.add(country);
      } else {
        Set<ASN1Encodable> otherAttrVals = otherAttrs.computeIfAbsent(attrType, k -> new HashSet<>());
        otherAttrVals.add(attrVal);
      }
    }

    if (placeOfBirth != null) {
      attrTypes.remove(ObjectIdentifiers.DN.placeOfBirth);
    }

    if (gender != null) {
      attrTypes.remove(ObjectIdentifiers.DN.gender);
    }

    if (!countryOfCitizenshipList.isEmpty()) {
      attrTypes.remove(ObjectIdentifiers.DN.countryOfCitizenship);
    }

    if (!countryOfResidenceList.isEmpty()) {
      attrTypes.remove(ObjectIdentifiers.DN.countryOfResidence);
    }

    attrTypes.removeAll(otherAttrs.keySet());

    if (!attrTypes.isEmpty()) {
      List<String> attrTypeTexts = new LinkedList<>();
      for (ASN1ObjectIdentifier oid : attrTypes) {
        attrTypeTexts.add(oid.getId());
      }
      failureMsg.append("required attributes of types ").append(attrTypeTexts).append(" are not present; ");
    }

    if (gender != null) {
      if (!(gender.equalsIgnoreCase("F") || gender.equalsIgnoreCase("M"))) {
        failureMsg.append("invalid gender: ").append(gender).append("; ");
      }
      if (!gender.equalsIgnoreCase(expGender)) {
        addViolation(failureMsg, "gender", gender, expGender);
      }
    }

    if (placeOfBirth != null) {
      if (!placeOfBirth.equals(expPlaceOfBirth)) {
        addViolation(failureMsg, "placeOfBirth", placeOfBirth, expPlaceOfBirth);
      }
    }

    if (!countryOfCitizenshipList.isEmpty()) {
      Set<String> diffs = strInBnotInA(expCountryOfCitizenshipList, countryOfCitizenshipList);
      if (CollectionUtil.isNotEmpty(diffs)) {
        failureMsg.append("countryOfCitizenship ").append(diffs).append(" are present but not expected; ");
      }

      diffs = strInBnotInA(countryOfCitizenshipList, expCountryOfCitizenshipList);
      if (CollectionUtil.isNotEmpty(diffs)) {
        failureMsg.append("countryOfCitizenship ").append(diffs).append(" are absent but are required; ");
      }
    }

    if (!countryOfResidenceList.isEmpty()) {
      Set<String> diffs = strInBnotInA(expCountryOfResidenceList, countryOfResidenceList);
      if (CollectionUtil.isNotEmpty(diffs)) {
        failureMsg.append("countryOfResidence ").append(diffs).append(" are present but not expected; ");
      }

      diffs = strInBnotInA(countryOfResidenceList, expCountryOfResidenceList);
      if (CollectionUtil.isNotEmpty(diffs)) {
        failureMsg.append("countryOfResidence ").append(diffs).append(" are absent but are required; ");
      }
    }

    if (!otherAttrs.isEmpty()) {
      for(Entry<ASN1ObjectIdentifier, Set<ASN1Encodable>> entry : otherAttrs.entrySet()) {
        ASN1ObjectIdentifier attrType = entry.getKey();
        Set<ASN1Encodable> expAttrValues = entry.getValue();
        if (expAttrValues == null) {
          failureMsg.append("attribute of type ").append(attrType.getId()).append(" is present but not requested; ");
          continue;
        }

        Set<ASN1Encodable> attrValues = otherAttrs.get(attrType);
        if (!attrValues.equals(expAttrValues)) {
          failureMsg.append("attribute of type ").append(attrType.getId()).append(" differs from the requested one; ");
        }
      }
    }
  } // method checkExtnSubjectDirAttrs

  void checkExtnSubjectInfoAccess(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns, ExtensionControl extnControl) {
    Map<ASN1ObjectIdentifier, Set<GeneralNameMode>> conf = getCertprofile().getSubjectInfoAccessModes();
    if (conf == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Encodable requestExtValue = null;
    if (requestedExtns != null) {
      requestExtValue = requestedExtns.getExtensionParsedValue(Extension.subjectInfoAccess);
    }
    if (requestExtValue == null) {
      failureMsg.append("extension is present but not expected; ");
      return;
    }

    ASN1Sequence requestSeq = ASN1Sequence.getInstance(requestExtValue);
    ASN1Sequence certSeq = ASN1Sequence.getInstance(extnValue);

    int size = requestSeq.size();

    if (certSeq.size() != size) {
      addViolation(failureMsg, "size of GeneralNames", certSeq.size(), size);
      return;
    }

    for (int i = 0; i < size; i++) {
      AccessDescription ad = AccessDescription.getInstance(requestSeq.getObjectAt(i));
      ASN1ObjectIdentifier accessMethod = ad.getAccessMethod();
      Set<GeneralNameMode> generalNameModes = conf.get(accessMethod);

      if (generalNameModes == null) {
        failureMsg.append("accessMethod in requestedExtension ")
          .append(accessMethod.getId()).append(" is not allowed; ");
        continue;
      }

      AccessDescription certAccessDesc = AccessDescription.getInstance(certSeq.getObjectAt(i));
      ASN1ObjectIdentifier certAccessMethod = certAccessDesc.getAccessMethod();

      boolean bo = Objects.equals(accessMethod, certAccessMethod);

      if (!bo) {
        addViolation(failureMsg, "accessMethod",
            (certAccessMethod == null) ? "null" : certAccessMethod.getId(),
            (accessMethod == null) ? "null" : accessMethod.getId());
        continue;
      }

      GeneralName accessLocation;
      try {
        accessLocation = createGeneralName(ad.getAccessLocation(), generalNameModes);
      } catch (BadCertTemplateException ex) {
        failureMsg.append("invalid requestedExtension: ").append(ex.getMessage()).append("; ");
        continue;
      }

      GeneralName certAccessLocation = certAccessDesc.getAccessLocation();
      if (!certAccessLocation.equals(accessLocation)) {
        failureMsg.append("accessLocation does not match the requested one; ");
      }
    }
  } // method checkExtnSUbjectInfoAccess

  void checkExtnSubjectKeyIdentifier(
      StringBuilder failureMsg, byte[] extnValue, SubjectPublicKeyInfo subjectPublicKeyInfo) {
    // subjectKeyIdentifier
    SubjectKeyIdentifier asn1 = SubjectKeyIdentifier.getInstance(extnValue);
    byte[] ski = asn1.getKeyIdentifier();

    byte[] expectedSki;
    try {
      expectedSki = getCertprofile().getSubjectKeyIdentifier(subjectPublicKeyInfo).getKeyIdentifier();
    } catch (CertprofileException e) {
      failureMsg.append("error computing expected SubjectKeyIdentifier");
      return;
    }

    if (!Arrays.equals(expectedSki, ski)) {
      addViolation(failureMsg, "SKI", hex(ski), hex(expectedSki));
    }
  } // method checkExtnSubjectKeyIdentifier

  void checkExtnTlsFeature(
      StringBuilder failureMsg, byte[] extnValue, Extensions requestedExtns, ExtensionControl extnControl) {
    TlsFeature tlsFeature = caller.getTlsFeature();
    if (tlsFeature == null) {
      caller.checkConstantExtnValue(Extn.id_pe_tlsfeature, failureMsg, extnValue, requestedExtns, extnControl);
      return;
    }

    Set<String> isFeatures = new HashSet<>();
    ASN1Sequence seq = ASN1Sequence.getInstance(extnValue);
    final int n = seq.size();
    for (int i = 0; i < n; i++) {
      ASN1Integer asn1Feature = ASN1Integer.getInstance(seq.getObjectAt(i));
      isFeatures.add(asn1Feature.getPositiveValue().toString());
    }

    Set<String> expFeatures = new HashSet<>();
    for (DescribableInt m : tlsFeature.getFeatures()) {
      expFeatures.add(Integer.toString(m.getValue()));
    }

    Set<String> diffs = strInBnotInA(expFeatures, isFeatures);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs).append(" are present but not expected; ");
    }

    diffs = strInBnotInA(isFeatures, expFeatures);
    if (CollectionUtil.isNotEmpty(diffs)) {
      failureMsg.append("features ").append(diffs).append(" are absent but are required; ");
    }
  } // method checkExtnTlsFeature

}
