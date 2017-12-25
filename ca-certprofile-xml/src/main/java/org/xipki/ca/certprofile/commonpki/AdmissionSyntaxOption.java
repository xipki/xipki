/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.certprofile.commonpki;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.1
 */

public class AdmissionSyntaxOption {

    private final boolean critical;

    private final GeneralName admissionAuthority;

    private final List<AdmissionsOption> admissionsList;

    private final boolean inputFromRequestRequired;

    private final ExtensionValue extensionValue;

    public AdmissionSyntaxOption(final boolean critical, final GeneralName admissionAuthority,
            final List<AdmissionsOption> admissionsList) {
        this.critical = critical;
        this.admissionAuthority = admissionAuthority;
        this.admissionsList = ParamUtil.requireNonEmpty("admissionsList", admissionsList);

        boolean bo = false;
        for (AdmissionsOption ao : admissionsList) {
            for (ProfessionInfoOption pio : ao.professionInfos()) {
                if (pio.registrationNumberOption() != null
                        && pio.registrationNumberOption().regex() != null) {
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
            List<ProfessionInfoOption> piList = ao.professionInfos();
            ProfessionInfo[] pis = new ProfessionInfo[piList.size()];

            for (int i = 0; i < pis.length; i++) {
                ProfessionInfoOption pio = piList.get(i);
                DirectoryString[] professionItems = null;
                int size = pio.professionItems().size();
                professionItems = new DirectoryString[size];
                for (int j = 0; j < size; j++) {
                    professionItems[j] = new DirectoryString(pio.professionItems().get(j));
                }

                ASN1OctetString addProfessionInfo = null;
                if (pio.addProfessionalInfo() != null) {
                    addProfessionInfo = new DEROctetString(pio.addProfessionalInfo());
                }

                String registrationNumber = null;
                if (pio.registrationNumberOption() != null) {
                    registrationNumber = pio.registrationNumberOption().constant();
                }
                pis[i] = new ProfessionInfo(pio.namingAuthority(), professionItems,
                        pio.professionOids().toArray(new ASN1ObjectIdentifier[0]),
                        registrationNumber, addProfessionInfo);
            }

            vec.add(new Admissions(ao.admissionAuthority(), ao.namingAuthority(), pis));
        }

        extensionValue = new ExtensionValue(critical,
                new AdmissionSyntax(admissionAuthority, new DERSequence(vec)));
    }

    public GeneralName admissionAuthority() {
        return admissionAuthority;
    }

    public List<AdmissionsOption> admissionsList() {
        return admissionsList;
    }

    public boolean isInputFromRequestRequired() {
        return inputFromRequestRequired;
    }

    public ExtensionValue extensionValue(final List<List<String>> registrationNumbersList)
            throws BadCertTemplateException {
        if (!this.inputFromRequestRequired) {
            return this.extensionValue;
        }

        if (CollectionUtil.isEmpty(registrationNumbersList)) {
            throw new BadCertTemplateException("registrationNumbersList must not be empty");
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
            List<ProfessionInfoOption> pi = ao.professionInfos();
            List<String> registrationNumbers = registrationNumbersList.get(i);
            final int k = registrationNumbers.size();
            if (k != pi.size()) {
                throw new BadCertTemplateException("invalid size of ProfessionInfo in Admissions["
                        + i + "], is=" + k + ", expected=" + pi.size());
            }

            List<String> newRegNumbers = new ArrayList<>(k);
            newRegNumbersList.add(newRegNumbers);
            for (int j = 0; j < k; j++) {
                RegistrationNumberOption option = pi.get(j).registrationNumberOption();
                if (option == null || option.constant() != null) {
                    continue;
                }

                Pattern regex = option.regex();
                String regNum = registrationNumbers.get(j);
                if (regNum == null || !regex.matcher(regNum).matches()) {
                    throw new BadCertTemplateException("invalid registrationNumber[" + i + "][" + j
                            + "]: '" + regNum + "'");
                }
                newRegNumbers.add(regNum);
            }
        }

        ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i < this.admissionsList.size(); i++) {
            AdmissionsOption ao = this.admissionsList.get(i);
            List<ProfessionInfoOption> piList = ao.professionInfos();
            ProfessionInfo[] pis = new ProfessionInfo[piList.size()];

            for (int j = 0; j < pis.length; j++) {
                ProfessionInfoOption pio = piList.get(j);
                DirectoryString[] professionItems = null;
                int size = pio.professionItems().size();
                professionItems = new DirectoryString[size];
                for (int k = 0; k < size; k++) {
                    professionItems[k] = new DirectoryString(pio.professionItems().get(k));
                }

                ASN1OctetString addProfessionInfo = null;
                if (pio.addProfessionalInfo() != null) {
                    addProfessionInfo = new DEROctetString(pio.addProfessionalInfo());
                }

                RegistrationNumberOption regNumOption = pio.registrationNumberOption();
                String registrationNumber = null;
                if (regNumOption != null) {
                    if (regNumOption.constant() != null) {
                        registrationNumber = regNumOption.constant();
                    } else {
                        registrationNumber = newRegNumbersList.get(i).get(j);
                    }
                }

                pis[i] = new ProfessionInfo(pio.namingAuthority(), professionItems,
                        pio.professionOids().toArray(new ASN1ObjectIdentifier[0]),
                        registrationNumber, addProfessionInfo);
            }

            vec.add(new Admissions(ao.admissionAuthority(), ao.namingAuthority(), pis));
        }

        return new ExtensionValue(critical,
                new AdmissionSyntax(admissionAuthority, new DERSequence(vec)));
    }

}
