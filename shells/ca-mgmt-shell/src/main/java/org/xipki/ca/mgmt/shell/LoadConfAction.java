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

package org.xipki.ca.mgmt.shell;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.mgmt.api.CaConfs;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.completer.DerPemCompleter;
import org.xipki.util.CollectionUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "load-conf", description = "load configuration")
@Service
public class LoadConfAction extends CaAction {

  @Option(name = "--conf-file", description = "CA system configuration file (XML or zip file")
  @Completion(FileCompleter.class)
  private String confFile;

  @Option(name = "--outform", description = "output format of the root certificates")
  @Completion(DerPemCompleter.class)
  protected String outform = "der";

  @Option(name = "--out-dir",
      description = "directory to save the root certificates")
  @Completion(FileCompleter.class)
  private String outDir = ".";

  @Override
  protected Object execute0() throws Exception {
    String msg = "configuration " + confFile;
    try {
      InputStream confStream;
      if (confFile.endsWith(".json")) {
        confStream = CaConfs.convertFileConfToZip(confFile);
      } else {
        confStream = Files.newInputStream(Paths.get(confFile));
      }

      Map<String, X509Certificate> rootCerts = caManager.loadConf(confStream);
      if (CollectionUtil.isEmpty(rootCerts)) {
        println("loaded " + msg);
      } else {
        println("loaded " + msg);
        for (String caname : rootCerts.keySet()) {
          String filename = "ca-" + caname + "." + outform.toLowerCase();
          saveVerbose("saved certificate of root CA " + caname + " to",
              new File(outDir, filename),
              encodeCrl(rootCerts.get(caname).getEncoded(), outform));
        }
      }
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not load " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

}
