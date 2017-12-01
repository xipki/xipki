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

package org.xipki.console.karaf.completer;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.console.karaf.AbstractDynamicEnumCompleter;
import org.xipki.security.ObjectIdentifiers;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
public class ExtKeyusageCompleter extends AbstractDynamicEnumCompleter {

    private static final Set<String> USAGES;

    static {
        Set<String> oids = new HashSet<>();
        oids.add(ObjectIdentifiers.id_kp_clientAuth.getId());
        oids.add(ObjectIdentifiers.id_kp_codeSigning.getId());
        oids.add(ObjectIdentifiers.id_kp_emailProtection.getId());
        oids.add(ObjectIdentifiers.id_kp_ipsecEndSystem.getId());
        oids.add(ObjectIdentifiers.id_kp_ipsecTunnel.getId());
        oids.add(ObjectIdentifiers.id_kp_OCSPSigning.getId());
        oids.add(ObjectIdentifiers.id_kp_serverAuth.getId());
        oids.add(ObjectIdentifiers.id_kp_timeStamping.getId());
        USAGES = Collections.unmodifiableSet(oids);
    }

    @Override
    protected Set<String> getEnums() {
        return USAGES;
    }

}
