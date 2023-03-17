// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.exception.BadCertTemplateException;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Control of the extension Admission (Germany national standard CommonPKI).
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.1
 */

public class AdmissionExtension {

  /**
   * Control of the Admission.
   */
  public static class AdmissionsOption {

    private final GeneralName admissionAuthority;

    private final NamingAuthority namingAuthority;

    private final List<ProfessionInfoOption> professionInfos;

    public AdmissionsOption(GeneralName admissionAuthority, NamingAuthority namingAuthority,
        List<ProfessionInfoOption> professionInfos) {
      this.admissionAuthority = admissionAuthority;
      this.namingAuthority = namingAuthority;
      this.professionInfos = Args.notEmpty(professionInfos, "professionInfos");
    }

    public GeneralName getAdmissionAuthority() {
      return admissionAuthority;
    }

    public NamingAuthority getNamingAuthority() {
      return namingAuthority;
    }

    public List<ProfessionInfoOption> getProfessionInfos() {
      return professionInfos;
    }

  } // class AdmissionsOption

  /**
   * Control of the extension Admission.
   */
  public static class AdmissionSyntaxOption {

    private final boolean critical;

    private final GeneralName admissionAuthority;

    private final List<AdmissionsOption> admissionsList;

    private final boolean inputFromRequestRequired;

    private final ExtensionValue extensionValue;

    public AdmissionSyntaxOption(
        boolean critical, GeneralName admissionAuthority, List<AdmissionsOption> admissionsList) {
      this.critical = critical;
      this.admissionAuthority = admissionAuthority;
      this.admissionsList = Args.notEmpty(admissionsList, "admissionsList");

      boolean bo = false;
      for (AdmissionsOption ao : admissionsList) {
        for (ProfessionInfoOption pio : ao.getProfessionInfos()) {
          if (pio.getRegistrationNumberOption() != null && pio.getRegistrationNumberOption().getRegex() != null) {
            bo = true;
            break;
          }
        }
        if (bo) {
          break;
        }
      }
      this.inputFromRequestRequired = bo;
      if (this.inputFromRequestRequired) {
        extensionValue = null;
        return;
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (AdmissionsOption ao : admissionsList) {
        List<ProfessionInfoOption> piList = ao.getProfessionInfos();
        ProfessionInfo[] pis = new ProfessionInfo[piList.size()];

        for (int i = 0; i < pis.length; i++) {
          ProfessionInfoOption pio = piList.get(i);
          int size = pio.getProfessionItems().size();
          DirectoryString[] professionItems = new DirectoryString[size];
          for (int j = 0; j < size; j++) {
            professionItems[j] = new DirectoryString(pio.getProfessionItems().get(j));
          }

          ASN1OctetString addProfessionInfo = null;
          if (pio.getAddProfessionalInfo() != null) {
            addProfessionInfo = new DEROctetString(pio.getAddProfessionalInfo());
          }

          String registrationNumber = null;
          if (pio.getRegistrationNumberOption() != null) {
            registrationNumber = pio.getRegistrationNumberOption().getConstant();
          }
          pis[i] = new ProfessionInfo(pio.getNamingAuthority(), professionItems,
              pio.getProfessionOids().toArray(new ASN1ObjectIdentifier[0]),
              registrationNumber, addProfessionInfo);
        }

        vec.add(new Admissions(ao.getAdmissionAuthority(), ao.getNamingAuthority(), pis));
      }

      extensionValue = new ExtensionValue(critical, new AdmissionSyntax(admissionAuthority, new DERSequence(vec)));
    }

    public GeneralName getAdmissionAuthority() {
      return admissionAuthority;
    }

    public List<AdmissionsOption> getAdmissionsList() {
      return admissionsList;
    }

    public boolean isInputFromRequestRequired() {
      return inputFromRequestRequired;
    }

    public ExtensionValue getExtensionValue(List<List<String>> registrationNumbersList)
        throws BadCertTemplateException {
      if (!this.inputFromRequestRequired) {
        return this.extensionValue;
      }

      if (CollectionUtil.isEmpty(registrationNumbersList)) {
        throw new BadCertTemplateException("registrationNumbersList may not be empty");
      }

      final int n = registrationNumbersList.size();
      if (n != this.admissionsList.size()) {
        throw new BadCertTemplateException("invalid size of Admissions in AdmissionSyntax: "
            + "is=" + n + ", expected=" + this.admissionsList.size());
      }

      // check registrationNumbers
      List<List<String>> newRegNumbersList = new ArrayList<>(this.admissionsList.size());
      for (int i = 0; i < n; i++) {
        AdmissionsOption ao = this.admissionsList.get(i);
        List<ProfessionInfoOption> pi = ao.getProfessionInfos();
        List<String> registrationNumbers = registrationNumbersList.get(i);
        final int k = registrationNumbers.size();
        if (k != pi.size()) {
          throw new BadCertTemplateException("invalid size of ProfessionInfo in Admissions["
              + i + "], is=" + k + ", expected=" + pi.size());
        }

        List<String> newRegNumbers = new ArrayList<>(k);
        newRegNumbersList.add(newRegNumbers);
        for (int j = 0; j < k; j++) {
          RegistrationNumberOption option = pi.get(j).getRegistrationNumberOption();
          if (option == null || option.getConstant() != null) {
            continue;
          }

          String regNum = registrationNumbers.get(j);
          if (regNum == null || !option.getRegex().matcher(regNum).matches()) {
            throw new BadCertTemplateException("invalid registrationNumber[" + i + "][" + j + "]: '" + regNum + "'");
          }
          newRegNumbers.add(regNum);
        }
      }

      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (int i = 0; i < this.admissionsList.size(); i++) {
        AdmissionsOption ao = this.admissionsList.get(i);
        List<ProfessionInfoOption> piList = ao.getProfessionInfos();
        ProfessionInfo[] pis = new ProfessionInfo[piList.size()];

        for (int j = 0; j < pis.length; j++) {
          ProfessionInfoOption pio = piList.get(j);
          int size = pio.getProfessionItems().size();
          DirectoryString[] professionItems = new DirectoryString[size];
          for (int k = 0; k < size; k++) {
            professionItems[k] = new DirectoryString(pio.getProfessionItems().get(k));
          }

          ASN1OctetString addProfessionInfo = null;
          if (pio.getAddProfessionalInfo() != null) {
            addProfessionInfo = new DEROctetString(pio.getAddProfessionalInfo());
          }

          RegistrationNumberOption regNumOption = pio.getRegistrationNumberOption();
          String registrationNumber = null;
          if (regNumOption != null) {
            registrationNumber = (regNumOption.getConstant() != null)
                ? regNumOption.getConstant() : newRegNumbersList.get(i).get(j);
          }

          pis[i] = new ProfessionInfo(pio.getNamingAuthority(), professionItems,
              pio.getProfessionOids().toArray(new ASN1ObjectIdentifier[0]), registrationNumber, addProfessionInfo);
        }

        vec.add(new Admissions(ao.getAdmissionAuthority(), ao.getNamingAuthority(), pis));
      }

      return new ExtensionValue(critical, new AdmissionSyntax(admissionAuthority, new DERSequence(vec)));
    } // method getExtensionValue

  } // class AdmissionSyntaxOption

  /**
   * Control of the ProfessionInfo.
   */

  public static class ProfessionInfoOption {

    private final NamingAuthority namingAuthority;

    private final List<String> professionItems;

    private final List<ASN1ObjectIdentifier> professionOids;

    private final RegistrationNumberOption registrationNumberOption;

    private byte[] addProfessionalInfo;

    public ProfessionInfoOption(
        NamingAuthority namingAuthority, List<String> professionItems, List<ASN1ObjectIdentifier> professionOids,
        RegistrationNumberOption registrationNumberOption, byte[] addProfessionalInfo) {
      this.namingAuthority = namingAuthority;
      this.professionItems = Args.notEmpty(professionItems, "professionItems");
      this.professionOids = professionOids;
      this.registrationNumberOption = registrationNumberOption;
      this.addProfessionalInfo = addProfessionalInfo;
    }

    public byte[] getAddProfessionalInfo() {
      return addProfessionalInfo;
    }

    public void setAddProfessionalInfo(byte[] addProfessionalInfo) {
      this.addProfessionalInfo = addProfessionalInfo;
    }

    public NamingAuthority getNamingAuthority() {
      return namingAuthority;
    }

    public List<String> getProfessionItems() {
      return professionItems;
    }

    public List<ASN1ObjectIdentifier> getProfessionOids() {
      return professionOids;
    }

    public RegistrationNumberOption getRegistrationNumberOption() {
      return registrationNumberOption;
    }

  } // class ProfessionInfoOption

  /**
   * Control of the RegistrationNumber.
   */
  public static class RegistrationNumberOption {

    private final Pattern regex;

    private final String constant;

    public RegistrationNumberOption(String regex, String constant) {
      if (regex != null) {
        if (constant != null) {
          throw new IllegalArgumentException("exactly one of regex and constant must be non null");
        }
        this.regex = Pattern.compile(regex);
        this.constant = null;
      } else {
        if (constant == null) {
          throw new IllegalArgumentException("exactly one of regex and constant must be non null");
        }
        this.regex = null;
        this.constant = constant;
      }
    }

    public Pattern getRegex() {
      return regex;
    }

    public String getConstant() {
      return constant;
    }

  } // class RegistrationNumberOption

}
