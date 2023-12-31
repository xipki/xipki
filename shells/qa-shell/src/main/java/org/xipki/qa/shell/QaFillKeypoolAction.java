// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.qa.ca.FillKeytool;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;

/**
 * Shell to fill the keypool with keypairs.
 *
 * @since 6.0.0
 * @author Lijun Liao (xipki)
 */

@Command(scope = "qa", name = "fill-keypool", description = "Fill the keypool")
@Service
public class QaFillKeypoolAction extends XiAction {

  @Option(name = "--db-conf", required = true, description = "database configuration file of the keypool")
  @Completion(FileCompleter.class)
  private String dbconfFile;

  @Option(name = "--num", description = "number of keypairs for each keyspec")
  private int num = 10;

  @Option(name = "--enc-algo", description = "algorithm to encrypt the generated keypair." +
          "Valid values are AES128/GCM, AES192/GCM and AES256/GCM")
  private String encAlg = "AES128/GCM";

  @Option(name = "--password",
      description = "password to encrypt the generated keypair, as plaintext or PBE-encrypted.")
  private String passwordHint;

  private DataSourceFactory datasourceFactory;

  public QaFillKeypoolAction() {
    datasourceFactory = new DataSourceFactory();
  }

  @Override
  protected Object execute0() throws Exception {
    if (num < 1) {
      throw new IllegalCmdParamException("invalid num " + num);
    }

    char[] passwordChars = readPasswordIfNotSet(passwordHint);
    try (FillKeytool fillKeytool = new FillKeytool(datasourceFactory, dbconfFile)) {
      fillKeytool.execute(num, encAlg, passwordChars);
    }
    return null;
  }
}
