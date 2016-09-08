/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.certprofile.isismtt;

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
import org.xipki.commons.common.util.CollectionUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.ca.api.BadCertTemplateException;
import org.xipki.pki.ca.api.profile.ExtensionValue;

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
            for (ProfessionInfoOption pio : ao.getProfessionInfos()) {
                if (pio.getRegistrationNumberOption() != null
                        && pio.getRegistrationNumberOption().getRegex() != null) {
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
                DirectoryString[] professionItems = null;
                int size = pio.getProfessionItems().size();
                professionItems = new DirectoryString[size];
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

        extensionValue = new ExtensionValue(critical,
                new AdmissionSyntax(admissionAuthority, new DERSequence(vec)));
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

    public ExtensionValue getExtensionValue(final List<List<String>> registrationNumbersList)
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

                Pattern regex = option.getRegex();
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
            List<ProfessionInfoOption> piList = ao.getProfessionInfos();
            ProfessionInfo[] pis = new ProfessionInfo[piList.size()];

            for (int j = 0; j < pis.length; j++) {
                ProfessionInfoOption pio = piList.get(j);
                DirectoryString[] professionItems = null;
                int size = pio.getProfessionItems().size();
                professionItems = new DirectoryString[size];
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
                    if (regNumOption.getConstant() != null) {
                        registrationNumber = regNumOption.getConstant();
                    } else {
                        registrationNumber = newRegNumbersList.get(i).get(j);
                    }
                }

                pis[i] = new ProfessionInfo(pio.getNamingAuthority(), professionItems,
                        pio.getProfessionOids().toArray(new ASN1ObjectIdentifier[0]),
                        registrationNumber, addProfessionInfo);
            }

            vec.add(new Admissions(ao.getAdmissionAuthority(), ao.getNamingAuthority(), pis));
        }

        return new ExtensionValue(critical,
                new AdmissionSyntax(admissionAuthority, new DERSequence(vec)));
    }

}
