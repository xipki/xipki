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

package org.xipki.security.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.util.IoUtil;
import org.xipki.console.karaf.completer.FilePathCompleter;
import org.xipki.security.shell.completer.KeystoreTypeCompleter;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.2.0
 */

@Command(scope = "xi", name = "import-cert",
    description = "Import certificates to a keystore")
@Service
public class ImportCertCmd extends SecurityAction {

  @Option(name = "--keystore", required = true,
      description = "Keystore file\n(required)")
  @Completion(FilePathCompleter.class)
  private String ksFile;

  @Option(name = "--type", required = true,
      description = "Type of the keystore\n(required)")
  @Completion(KeystoreTypeCompleter.class)
  private String ksType;

  @Option(name = "--password",
      description = "password of the keystore")
  private String ksPwd;

  @Option(name = "--cert", aliases = "-c", required = true, multiValued = true,
      description = "Certificate files\n(required, multi-valued)")
  @Completion(FilePathCompleter.class)
  private List<String> certFiles;

  @Override
  protected Object execute0() throws Exception {
    File realKsFile = new File(IoUtil.expandFilepath(ksFile));
    KeyStore ks = KeyStore.getInstance(ksType);
    char[] password = readPasswordIfNotSet(ksPwd);

    Set<String> aliases = new HashSet<>(10);
    if (realKsFile.exists()) {
      FileInputStream inStream = new FileInputStream(realKsFile);
      try {
        ks.load(inStream, password);
      } finally {
        inStream.close();
      }

      Enumeration<String> strs = ks.aliases();
      while (strs.hasMoreElements()) {
        aliases.add(strs.nextElement());
      }
    } else {
      ks.load(null);
    }

    for (String certFile : certFiles) {
      X509Certificate cert = X509Util.parseCert(certFile);
      String baseAlias = X509Util.getCommonName(cert.getSubjectX500Principal());
      String alias = baseAlias;
      int idx = 2;
      while (aliases.contains(alias)) {
        alias = baseAlias + "-" + (idx++);
      }
      ks.setCertificateEntry(alias, cert);
      aliases.add(alias);
    }

    ByteArrayOutputStream bout = new ByteArrayOutputStream(4096);
    ks.store(bout, password);
    saveVerbose("saved keystore to file", realKsFile, bout.toByteArray());
    return null;
  }

}
