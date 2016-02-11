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

package org.xipki.pki.ca.api.profile.x509;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.pki.ca.api.profile.RdnControl;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SubjectControl {

    private final Map<ASN1ObjectIdentifier, RdnControl> controls;

    private final Map<ASN1ObjectIdentifier, String> typeGroups;

    private final Map<String, Set<ASN1ObjectIdentifier>> groupTypes;

    private final Set<String> groups;

    private final List<ASN1ObjectIdentifier> types;

    public SubjectControl(
            final boolean backwardsSubject,
            final Map<ASN1ObjectIdentifier, RdnControl> controls) {
        ParamUtil.assertNotEmpty("controls", controls);

        this.controls = controls;
        this.typeGroups = new HashMap<>();
        Set<ASN1ObjectIdentifier> oidSet = controls.keySet();
        List<ASN1ObjectIdentifier> sortedOids = new ArrayList<>(controls.size());
        List<ASN1ObjectIdentifier> oids = backwardsSubject
                ? ObjectIdentifiers.getBackwardDNs()
                : ObjectIdentifiers.getForwardDNs();
        for (ASN1ObjectIdentifier oid : oids) {
            if (oidSet.contains(oid)) {
                sortedOids.add(oid);
            }
        }

        for (ASN1ObjectIdentifier oid : oidSet) {
            if (!sortedOids.contains(oid)) {
                sortedOids.add(oid);
            }
        }

        this.types = Collections.unmodifiableList(sortedOids);

        Set<String> groupSet = new HashSet<>();
        this.groupTypes = new HashMap<>();

        for (ASN1ObjectIdentifier type : controls.keySet()) {
            String group = controls.get(type).getGroup();
            if (StringUtil.isBlank(group)) {
                continue;
            }

            groupSet.add(group);
            typeGroups.put(type, group);
            Set<ASN1ObjectIdentifier> typeSet = groupTypes.get(group);
            if (typeSet == null) {
                typeSet = new HashSet<>();
                groupTypes.put(group, typeSet);
            }
            typeSet.add(type);
        }

        this.groups = Collections.unmodifiableSet(groupSet);
    } // constructor

    public RdnControl getControl(
            final ASN1ObjectIdentifier type) {
        return controls.isEmpty()
                ? SubjectDnSpec.getRdnControl(type)
                : controls.get(type);
    }

    public String getGroup(
            final ASN1ObjectIdentifier type) {
        return typeGroups.get(type);
    }

    public Set<ASN1ObjectIdentifier> getTypesForGroup(
            final String group) {
        return groupTypes.get(group);
    }

    public Set<String> getGroups() {
        return groups;
    }

    public List<ASN1ObjectIdentifier> getTypes() {
        return types;
    }

}
