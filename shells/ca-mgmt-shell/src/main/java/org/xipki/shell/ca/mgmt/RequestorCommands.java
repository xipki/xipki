// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.codec.Base64;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.IoUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Actions to manage requestors.
 *
 * @author Lijun Liao (xipki)
 */
public class RequestorCommands {
  @Command(name = "careq-add", description = "add requestor to CA",
      mixinStandardHelpOptions = true)
  public static class CareqAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--requestor", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String requestorName;

    @Option(names = "--permission", required = true, description = "permissions")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(names = "--profile", description = "profiles or all")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profiles;

    @Override
    public void run() {
      try {
        CaHasRequestorEntry entry = new CaHasRequestorEntry(
            new NameId(null, requestorName), new Permissions(permissions), profiles);
        client().addRequestorToCa(entry, caName);
        println("added requestor " + requestorName + " to CA " + caName);
      } catch (Exception ex) {
        throw new RuntimeException("could not add requestor to CA: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "careq-info", description = "show information of requestor in CA",
      mixinStandardHelpOptions = true)
  static class CareqInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    public void run() {
      try {
        Set<CaHasRequestorEntry> entries = client().getRequestorsForCa(caName);
        if (CollectionUtil.isEmpty(entries)) {
          println("no requestor for CA " + caName + " is configured");
          return;
        }

        StringBuilder sb = new StringBuilder("requestors trusted by CA ")
            .append(caName).append('\n');
        for (CaHasRequestorEntry entry : entries) {
          sb.append("----------\n").append(entry).append('\n');
        }
        println(sb.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get requestors for CA: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "careq-rm", description = "remove requestor from CA",
      mixinStandardHelpOptions = true)
  public static class CareqRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--requestor", required = true, description = "requestor names")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private List<String> requestorNames;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        for (String requestorName : requestorNames) {
          if (force || confirmAction("Do you want to remove requestor " + requestorName
              + " from CA " + caName)) {
            client().removeRequestorFromCa(requestorName, caName);
            println("removed requestor " + requestorName + " from CA " + caName);
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove requestor from CA: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "requestor-add", description = "add requestor", mixinStandardHelpOptions = true)
  public static class RequestorAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "requestor name")
    private String name;

    @Option(names = "--cert", required = true, description = "requestor certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      try {
        byte[] cert = X509Util.parseCert(IoUtil.read(certFile)).getEncoded();
        RequestorEntry entry = new RequestorEntry(new NameId(null, name),
            RequestorEntry.TYPE_CERT, Base64.encodeToString(cert));
        client().addRequestor(entry);
        println("added CMP requestor " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not add requestor " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "requestor-info", description = "show information of requestor",
      mixinStandardHelpOptions = true)
  static class RequestorInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(names = {"--verbose", "-v"}, description = "show requestor information verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        if (name == null) {
          println(CaMgmtUtil.formatNames("requestor", client().getRequestorNames()));
          return;
        }

        RequestorEntry entry = Optional.ofNullable(client().getRequestor(name))
            .orElseThrow(() -> new CaMgmtException("could not find requestor '" + name + "'"));
        println(entry.toString(verbose));
      } catch (Exception ex) {
        throw new RuntimeException("could not get requestor info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "requestor-rm", description = "remove requestor", mixinStandardHelpOptions = true)
  public static class RequestorRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove CMP requestor " + name)) {
          client().removeRequestor(name);
          println("removed CMP requestor " + name);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove requestor " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "requestor-up", description = "update requestor", mixinStandardHelpOptions = true)
  public static class RequestorUpCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(names = "--cert", required = true, description = "requestor certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      try {
        String conf = Base64.encodeToString(X509Util.parseCert(IoUtil.read(certFile)).getEncoded());
        client().changeRequestor(name, RequestorEntry.TYPE_CERT, conf);
        println("updated requestor " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not update requestor " + name + ": "
            + ex.getMessage(), ex);
      }
    }
  }
}
