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

package org.xipki.ca.certprofile.internal;

import org.xipki.ca.api.profile.x509.X509Certprofile;
import org.xipki.ca.api.profile.x509.X509CertprofileFactory;
import org.xipki.ca.certprofile.XmlX509Certprofile;
import org.xipki.common.ObjectCreationException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class X509CertprofileFactoryImpl implements X509CertprofileFactory {

    @Override
    public boolean canCreateProfile(String type) {
        return "XML".equalsIgnoreCase(type);
    }

    @Override
    public X509Certprofile newCertprofile(String type) throws ObjectCreationException {
        if ("XML".equalsIgnoreCase(type)) {
            return new XmlX509Certprofile();
        } else {
            throw new ObjectCreationException("unknown certprofile type '" + type + "'");
        }
    }

}
