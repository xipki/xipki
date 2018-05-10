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

package org.xipki.security.shell.pkcs11;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "add-cert-p11",
    description = "add certificate to PKCS#11 device")
@Service
public class P11CertAddCmd extends P11SecurityAction {

  @Option(name = "--cert", required = true,
      description = "certificate file\n(required)")
  @Completion(FileCompleter.class)
  private String certFile;

  @Override
  protected Object execute0() throws Exception {
    X509Certificate cert = X509Util.parseCert(certFile);
    P11Slot slot = getSlot();
    P11ObjectIdentifier objectId = slot.addCert(cert);
    println("added certificate under " + objectId);
    return null;
  }

}
