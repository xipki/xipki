/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.ca.api.profile.x509;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.RdnControl;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

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

    public SubjectControl(final List<RdnControl> controls, final boolean keepRdnOrder) {
        ParamUtil.requireNonEmpty("controls", controls);
        this.typeGroups = new HashMap<>();

        List<ASN1ObjectIdentifier> sortedOids = new ArrayList<>(controls.size());
        if (keepRdnOrder) {
            for (RdnControl m : controls) {
                sortedOids.add(m.type());
            }
        } else {
            Set<ASN1ObjectIdentifier> oidSet = new HashSet<>();
            for (RdnControl m : controls) {
                oidSet.add(m.type());
            }

            List<ASN1ObjectIdentifier> oids = SubjectDnSpec.getForwardDNs();

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
        }

        this.types = Collections.unmodifiableList(sortedOids);

        Set<String> groupSet = new HashSet<>();
        this.groupTypes = new HashMap<>();
        this.controls = new HashMap<>();

        for (RdnControl control : controls) {
            ASN1ObjectIdentifier type = control.type();
            this.controls.put(type, control);
            String group = control.group();
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

    public RdnControl getControl(final ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("type", type);
        return controls.isEmpty() ? SubjectDnSpec.getRdnControl(type) : controls.get(type);
    }

    public String getGroup(final ASN1ObjectIdentifier type) {
        ParamUtil.requireNonNull("type", type);
        return typeGroups.get(type);
    }

    public Set<ASN1ObjectIdentifier> getTypesForGroup(final String group) {
        ParamUtil.requireNonNull("group", group);
        return groupTypes.get(group);
    }

    public Set<String> groups() {
        return groups;
    }

    public List<ASN1ObjectIdentifier> types() {
        return types;
    }

}
