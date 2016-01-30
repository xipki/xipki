/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.qa.impl.internal;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.util.Arrays;
import org.xipki.common.util.CollectionUtil;
import org.xipki.pki.ca.certprofile.x509.jaxb.Admission;
import org.xipki.pki.ca.certprofile.x509.jaxb.OidWithDescType;

/**
 * @author Lijun Liao
 */

public class QaAdmission extends QaExtension {

    private final String registrationNumber;

    private final byte[] addProfessionInfo;

    private final List<String> professionOIDs;

    private final List<String> professionItems;

    public QaAdmission(
            final Admission jaxb) {
        this.registrationNumber = jaxb.getRegistrationNumber();
        this.addProfessionInfo = jaxb.getAddProfessionInfo();

        List<String> items = jaxb.getProfessionItem();
        if (CollectionUtil.isEmpty(items)) {
            professionItems = null;
        } else {
            professionItems = Collections.unmodifiableList(items);
        }

        List<OidWithDescType> oids = jaxb.getProfessionOid();
        if (oids == null) {
            this.professionOIDs = null;
        } else {
            List<String> list = new LinkedList<>();
            for (OidWithDescType oid : oids) {
                list.add(oid.getValue());
            }
            this.professionOIDs = Collections.unmodifiableList(list);
        }
    }

    public String getRegistrationNumber() {
        return registrationNumber;
    }

    public byte[] getAddProfessionInfo() {
        return Arrays.clone(addProfessionInfo);
    }

    public List<String> getProfessionOIDs() {
        return professionOIDs;
    }

    public List<String> getProfessionItems() {
        return professionItems;
    }

}
