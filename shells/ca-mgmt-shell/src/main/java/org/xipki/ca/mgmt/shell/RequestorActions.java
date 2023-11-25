// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.util.Base64;
import org.xipki.util.IoUtil;

import java.util.*;

/**
 * Actions to manage requestors.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class RequestorActions {

  @Command(scope = "ca", name = "careq-add", description = "add requestor to CA")
  @Service
  public static class CareqAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String requestorName;

    @Option(name = "--permission", required = true, multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", multiValued = true, description = "profile name or 'all' for all profiles")
    @Completion(CaCompleters.ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0() throws Exception {
      CaHasRequestorEntry entry = new CaHasRequestorEntry(new NameId(null, requestorName));
      entry.setProfiles(profiles);
      entry.setPermissions(new Permissions(permissions));

      String msg = "requestor " + requestorName + " to CA " + caName;
      try {
        caManager.addRequestorToCa(entry, caName);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class CareqAdd

  @Command(scope = "ca", name = "careq-info", description = "show information of requestor in CA")
  @Service
  public static class CareqInfo extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      StringBuilder sb = new StringBuilder();

      Set<CaHasRequestorEntry> entries = caManager.getRequestorsForCa(caName);
      if (isNotEmpty(entries)) {
        sb.append("requestors trusted by CA ").append(caName).append("\n");
        for (CaHasRequestorEntry entry : entries) {
          sb.append("----------\n").append(entry).append("\n");
        }
      } else {
        sb.append("no requestor for CA ").append(caName).append(" is configured");
      }
      println(sb.toString());
      return null;
    } // method execute0

  } // class CareqInfo

  @Command(scope = "ca", name = "careq-rm", description = "remove requestor from CA")
  @Service
  public static class CareqRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true, multiValued = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private List<String> requestorNames;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      for (String requestorName : requestorNames) {
        String msg = "requestor " + requestorName + " from CA " + caName;
        if (force || confirm("Do you want to remove " + msg, 3)) {
          try {
            caManager.removeRequestorFromCa(requestorName, caName);
            println("removed " + msg);
          } catch (CaMgmtException ex) {
            throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
          }
        }
      }

      return null;
    } // method execute0

  } // class CareqRm

  @Command(scope = "ca", name = "requestor-add", description = "add requestor")
  @Service
  public static class RequestorAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "requestor name")
    private String name;

    @Option(name = "--cert", required = true, description = "requestor certificate file"
        + "(exactly one of cert and password must be specified).")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      X509Cert cert = X509Util.parseCert(IoUtil.read(certFile));
      RequestorEntry entry = new RequestorEntry(new NameId(null, name), RequestorEntry.TYPE_CERT,
            Base64.encodeToString(cert.getEncoded()));

      String msg = "CMP requestor " + name;

      try {
        caManager.addRequestor(entry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class RequestorAdd

  @Command(scope = "ca", name = "requestor-info", description = "show information of requestor")
  @Service
  public static class RequestorInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v", description = "show requestor information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();

      if (name == null) {
        Set<String> names = caManager.getRequestorNames();
        int size = names.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1").append(" requestor is configured\n");
        } else {
          sb.append(size).append(" requestors are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
      } else {
        RequestorEntry entry = Optional.ofNullable(caManager.getRequestor(name))
            .orElseThrow(() -> new CmdFailure("could not find requestor '" + name + "'"));
        sb.append(entry.toString(verbose));
      }

      println(sb.toString());
      return null;
    } // method execute0

  } // class RequestorInfo

  @Command(scope = "ca", name = "requestor-rm", description = "remove requestor")
  @Service
  public static class RequestorRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "CMP requestor " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeRequestor(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class RequestorRm

  @Command(scope = "ca", name = "requestor-up", description = "update requestor")
  @Service
  public static class RequestorUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    protected String name;

    @Option(name = "--cert", required = true, description = "requestor certificate file")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Override
    protected Object execute0() throws Exception {
      // check if the certificate is valid
      String msg = "requestor " + name;

      String conf = Base64.encodeToString(X509Util.parseCert(IoUtil.read(certFile)).getEncoded());

      try {
        caManager.changeRequestor(name, RequestorEntry.TYPE_CERT, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class RequestorUp

}
