// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.AdmissionExtension;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/**
 * Extension Admission.
 *
 * @author Lijun Liao
 */

public class AdmissionSyntax extends ValidatableConf {

  public static class RegistrationNumber extends ValidatableConf {

    private String regex;

    private String constant;

    public String getRegex() {
      return regex;
    }

    public void setRegex(String regex) {
      this.regex = regex;
    }

    public String getConstant() {
      return constant;
    }

    public void setConstant(String constant) {
      this.constant = constant;
    }

    @Override
    public void validate() throws InvalidConfException {
      exactOne(regex, "regex", constant, "constant");
    }

  } // class RegistrationNumber

  public static class NamingAuthorityType extends ValidatableConf {

    private DescribableOid oid;

    private String url;

    private String text;

    public DescribableOid getOid() {
      return oid;
    }

    public void setOid(DescribableOid oid) {
      this.oid = oid;
    }

    public String getUrl() {
      return url;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public String getText() {
      return text;
    }

    public void setText(String text) {
      this.text = text;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (oid == null && url == null && text == null) {
        throw new InvalidConfException("oid, url and text may not be all null");
      }
      validate(oid);
    }

  } // class NamingAuthorityType

  public static class ProfessionInfoType extends ValidatableConf {

    private NamingAuthorityType namingAuthority;

    private List<DescribableOid> professionOids;

    private List<String> professionItems;

    private RegistrationNumber registrationNumber;

    private byte[] addProfessionInfo;

    public NamingAuthorityType getNamingAuthority() {
      return namingAuthority;
    }

    public void setNamingAuthority(NamingAuthorityType namingAuthority) {
      this.namingAuthority = namingAuthority;
    }

    public List<DescribableOid> getProfessionOids() {
      if (professionOids == null) {
        professionOids = new LinkedList<>();
      }
      return professionOids;
    }

    public void setProfessionOids(List<DescribableOid> professionOids) {
      this.professionOids = professionOids;
    }

    public List<String> getProfessionItems() {
      if (professionItems == null) {
        professionItems = new LinkedList<>();
      }
      return professionItems;
    }

    public void setProfessionItems(List<String> professionItems) {
      this.professionItems = professionItems;
    }

    public RegistrationNumber getRegistrationNumber() {
      return registrationNumber;
    }

    public void setRegistrationNumber(RegistrationNumber registrationNumber) {
      this.registrationNumber = registrationNumber;
    }

    public byte[] getAddProfessionInfo() {
      return addProfessionInfo;
    }

    public void setAddProfessionInfo(byte[] addProfessionInfo) {
      this.addProfessionInfo = addProfessionInfo;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(namingAuthority, registrationNumber);
      validate(professionOids);
    }

  } // class ProfessionInfoType

  public static class AdmissionsType extends ValidatableConf {

    private byte[] admissionAuthority;

    private NamingAuthorityType namingAuthority;

    private List<ProfessionInfoType> professionInfos;

    public byte[] getAdmissionAuthority() {
      return admissionAuthority;
    }

    public void setAdmissionAuthority(byte[] admissionAuthority) {
      this.admissionAuthority = admissionAuthority;
    }

    public NamingAuthorityType getNamingAuthority() {
      return namingAuthority;
    }

    public void setNamingAuthority(NamingAuthorityType namingAuthority) {
      this.namingAuthority = namingAuthority;
    }

    public List<ProfessionInfoType> getProfessionInfos() {
      if (professionInfos == null) {
        professionInfos = new LinkedList<>();
      }
      return professionInfos;
    }

    public void setProfessionInfos(List<ProfessionInfoType> professionInfos) {
      this.professionInfos = professionInfos;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(namingAuthority);
      notEmpty(professionInfos, "professionInfos");
      validate(professionInfos);
    }

  } // class AdmissionsType

  private byte[] admissionAuthority;

  private List<AdmissionsType> contentsOfAdmissions;

  public byte[] getAdmissionAuthority() {
    return admissionAuthority;
  }

  public void setAdmissionAuthority(byte[] admissionAuthority) {
    this.admissionAuthority = admissionAuthority;
  }

  public List<AdmissionsType> getContentsOfAdmissions() {
    if (contentsOfAdmissions == null) {
      contentsOfAdmissions = new LinkedList<>();
    }
    return contentsOfAdmissions;
  }

  public void setContentsOfAdmissions(List<AdmissionsType> contentsOfAdmissions) {
    this.contentsOfAdmissions = contentsOfAdmissions;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(contentsOfAdmissions, "contentsOfAdmissions");
    validate(contentsOfAdmissions);
  }

  public AdmissionExtension.AdmissionSyntaxOption toXiAdmissionSyntax(boolean critical)
      throws CertprofileException {
    List<AdmissionExtension.AdmissionsOption> admissionsList = new LinkedList<>();
    for (AdmissionsType at : getContentsOfAdmissions()) {
      List<AdmissionExtension.ProfessionInfoOption> professionInfos = new LinkedList<>();
      for (ProfessionInfoType pi : at.getProfessionInfos()) {
        NamingAuthority namingAuthorityL3 = null;
        if (pi.getNamingAuthority() != null) {
          namingAuthorityL3 = buildNamingAuthority(pi.getNamingAuthority());
        }

        List<DescribableOid> oidTypes = pi.getProfessionOids();
        List<ASN1ObjectIdentifier> oids = null;
        if (CollectionUtil.isNotEmpty(oidTypes)) {
          oids = new LinkedList<>();
          for (DescribableOid k : oidTypes) {
            oids.add(new ASN1ObjectIdentifier(k.getOid()));
          }
        }

        RegistrationNumber rnType = pi.getRegistrationNumber();
        AdmissionExtension.RegistrationNumberOption rno = (rnType == null) ? null
            : new AdmissionExtension.RegistrationNumberOption(rnType.getRegex(), rnType.getConstant());

        professionInfos.add(new AdmissionExtension.ProfessionInfoOption(namingAuthorityL3,
                              pi.getProfessionItems(), oids, rno, pi.getAddProfessionInfo()));
      }

      GeneralName admissionAuthority = null;
      if (at.getNamingAuthority() != null) {
        admissionAuthority = GeneralName.getInstance(asn1PrimitiveFromByteArray(at.getAdmissionAuthority()));
      }

      NamingAuthority namingAuthority = null;
      if (at.getNamingAuthority() != null) {
        namingAuthority = buildNamingAuthority(at.getNamingAuthority());
      }

      admissionsList.add(new AdmissionExtension.AdmissionsOption(admissionAuthority, namingAuthority, professionInfos));
    }

    GeneralName tmpAdmissionAuthority = (admissionAuthority == null)
        ? null : GeneralName.getInstance(admissionAuthority);

    return new AdmissionExtension.AdmissionSyntaxOption(critical, tmpAdmissionAuthority, admissionsList);
  } // method toXiAdmissionSyntax

  private static ASN1Primitive asn1PrimitiveFromByteArray(byte[] encoded) throws CertprofileException {
    try {
      return ASN1Primitive.fromByteArray(encoded);
    } catch (IOException ex) {
      throw new CertprofileException(ex.getMessage(), ex);
    }
  }

  private static NamingAuthority buildNamingAuthority(NamingAuthorityType value) {
    ASN1ObjectIdentifier oid = (value.getOid() == null) ? null : new ASN1ObjectIdentifier(value.getOid().getOid());
    String url = StringUtil.isBlank(value.getUrl()) ? null : value.getUrl();
    DirectoryString text = StringUtil.isBlank(value.getText()) ? null : new DirectoryString(value.getText());
    return new NamingAuthority(oid, url, text);
  } // method buildNamingAuthority

} // class AdmissionSyntax
