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

package org.xipki.console.karaf.completer;

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.xipki.console.karaf.AbstractDynamicEnumCompleter;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

@Service
// CHECKSTYLE:SKIP
public class ECCurveNameCompleter extends AbstractDynamicEnumCompleter {

    @Override
    protected Set<String> getEnums() {
        Set<String> curveNames = new HashSet<>();
        Enumeration<?> names = X962NamedCurves.getNames();
        while (names.hasMoreElements()) {
            curveNames.add((String) names.nextElement());
        }

        names = SECNamedCurves.getNames();
        while (names.hasMoreElements()) {
            curveNames.add((String) names.nextElement());
        }

        names = TeleTrusTNamedCurves.getNames();
        while (names.hasMoreElements()) {
            curveNames.add((String) names.nextElement());
        }

        names = NISTNamedCurves.getNames();
        while (names.hasMoreElements()) {
            curveNames.add((String) names.nextElement());
        }

        return curveNames;
    }

}
