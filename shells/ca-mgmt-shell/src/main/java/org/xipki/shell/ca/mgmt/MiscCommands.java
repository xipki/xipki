// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.mgmt.CaConfs;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.IoUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Misc actions to manage CA.
 *
 * @author Lijun Liao (xipki)
 */
public class MiscCommands {
  @Command(name = "export-conf", description = "export configuration to zip file",
      mixinStandardHelpOptions = true)
  static class ExportConfCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--conf-file", required = true, description = "zip output file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Option(names = "--ca", description = "CA names to export")
    @Completion(CaCompleters.CaNameCompleter.class)
    private List<String> caNames;

    @Override
    public void run() {
      try (InputStream in = client().exportConf(caNames)) {
        saveVerbose("exported configuration to file", confFile,
            IoUtil.readAllBytesAndClose(in));
      } catch (Exception ex) {
        throw new RuntimeException("could not export configuration: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "load-conf", description = "load configuration", mixinStandardHelpOptions = true)
  static class LoadConfCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "JSON or zip configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        InputStream confStream = confFile.endsWith(".json")
            ? CaConfs.convertFileConfToZip(confFile)
            : Files.newInputStream(Paths.get(confFile));
        client().loadConfAndClose(confStream);
        println("loaded configuration " + confFile);
      } catch (Exception ex) {
        throw new RuntimeException("could not load configuration: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "notify-change", description = "notify the change of CA system",
      mixinStandardHelpOptions = true)
  static class NotifyChangeCommand extends CaMgmtUtil.CaMgmtCommand {

    @Override
    public void run() {
      try {
        client().notifyCaChange();
        println("notified the change of CA system");
      } catch (Exception ex) {
        throw new RuntimeException("could not notify change: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "republish", description = "republish certificates",
      mixinStandardHelpOptions = true)
  public static class RepublishCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    @Option(names = "--ca", required = true, description = "CA name or all")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--publisher", required = true, description = "publisher names or all")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Override
    public void run() {
      try {
        boolean allPublishers = false;
        for (String publisherName : publisherNames) {
          if ("all".equalsIgnoreCase(publisherName)) {
            allPublishers = true;
            break;
          }
        }

        List<String> names = allPublishers ? null : publisherNames;
        String effectiveCa = "all".equalsIgnoreCase(caName) ? null : caName;
        client().republishCertificates(effectiveCa, names, numThreads);
        println("republished certificates");
      } catch (Exception ex) {
        throw new RuntimeException("could not republish certificates: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "restart-ca", description = "restart CA", mixinStandardHelpOptions = true)
  static class RestartCaCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Override
    public void run() {
      try {
        client().restartCa(name);
        println("restarted CA " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not restart CA " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "restart", description = "restart CA system", mixinStandardHelpOptions = true)
  static class RestartCommand extends CaMgmtUtil.CaMgmtCommand {

    @Override
    public void run() {
      try {
        CaMgmtClient client = client();
        client.restartCaSystem();
        StringBuilder sb = new StringBuilder("restarted CA system\n");
        appendNames(sb, "successful CAs", client.getSuccessfulCaNames());
        appendNames(sb, "failed CAs", client.getFailedCaNames());
        appendNames(sb, "inactive CAs", client.getInactiveCaNames());
        println(sb.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not restart CA system: " + ex.getMessage(), ex);
      }
    }

    private void appendNames(StringBuilder sb, String label, Set<String> names) {
      sb.append("  ").append(label).append(":\n");
      if (CollectionUtil.isEmpty(names)) {
        sb.append("    -\n");
        return;
      }

      List<String> sorted = new ArrayList<>(names);
      Collections.sort(sorted);
      for (String name : sorted) {
        sb.append("    ").append(name).append('\n');
      }
    }
  }

  @Command(name = "system-status", description = "show CA system status",
      mixinStandardHelpOptions = true)
  static class SystemStatusCommand extends CaMgmtUtil.CaMgmtCommand {

    @Override
    public void run() {
      try {
        CaSystemStatus status = client().getCaSystemStatus();
        println(status == null ? "status is null" : status.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get system status: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-token-info-p11", description = "list objects in PKCS#11 device of the CA",
      mixinStandardHelpOptions = true)
  static class CaTokenInfoP11Command extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--verbose", "-v"}, description = "show verbose object information")
    private boolean verbose;

    @Option(names = "--module", description = "PKCS#11 module name")
    private String moduleName = "default";

    @Option(names = "--slot", description = "slot index")
    private Integer slotIndex;

    @Override
    public void run() {
      try {
        println(client().getTokenInfoP11(moduleName, slotIndex, verbose));
      } catch (Exception ex) {
        throw new RuntimeException("could not get PKCS#11 token info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "unlock", description = "unlock CA system", mixinStandardHelpOptions = true)
  static class UnlockCommand extends CaMgmtUtil.CaMgmtCommand {

    @Override
    public void run() {
      try {
        client().unlockCa();
        println("unlocked CA system, call restart to restart CA system");
      } catch (Exception ex) {
        throw new RuntimeException("could not unlock CA system: " + ex.getMessage(), ex);
      }
    }
  }
}
