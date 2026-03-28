// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;
import org.xipki.ca.certprofile.xijsonv1.conf.V1XijsonCertprofileType;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Actions to manage certificate profiles.
 *
 * @author Lijun Liao (xipki)
 */
public class ProfileCommands {
  @Command(name = "caprofile-add", description = "add certificate profile to CA",
      mixinStandardHelpOptions = true)
  public static class CaprofileAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--profile", required = true, description = "profile name[:alias1,alias2]")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profileNameAliasesList;

    @Override
    public void run() {
      try {
        for (String profileNameAliases : profileNameAliasesList) {
          client().addCertprofileToCa(profileNameAliases, caName);
          println("associated certificate profile " + profileNameAliases + " to CA " + caName);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not associate profile to CA: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "caprofile-info",
      description = "show information of certificate profile in given CA",
      mixinStandardHelpOptions = true)
  static class CaprofileInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    public void run() {
      try {
        Set<CaProfileEntry> entries = client().getCertprofilesForCa(caName);
        if (CollectionUtil.isEmpty(entries)) {
          println("no profile for CA " + caName + " is configured");
          return;
        }

        StringBuilder sb = new StringBuilder("certificate profiles supported by CA ")
            .append(caName).append('\n');
        for (CaProfileEntry entry : entries) {
          sb.append('\t').append(entry.profileName());
          List<String> aliases = entry.profileAliases();
          if (CollectionUtil.isNotEmpty(aliases)) {
            sb.append(aliases.size() == 1 ? " (alias " : " (aliases ");
            for (String alias : aliases) {
              sb.append(alias).append(", ");
            }
            sb.delete(sb.length() - 2, sb.length());
            sb.append(')');
          }
          sb.append('\n');
        }
        println(sb.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get profiles for CA: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "caprofile-rm", description = "remove certificate profile from CA",
      mixinStandardHelpOptions = true)
  public static class CaprofileRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--profile", required = true, description = "certificate profile names")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profileNames;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        for (String profileName : profileNames) {
          if (force || confirmAction("Do you want to remove certificate profile "
              + profileName + " from CA " + caName)) {
            client().removeCertprofileFromCa(profileName, caName);
            println("removed certificate profile " + profileName + " from CA " + caName);
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove profile from CA: "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "profile-add", description = "add certificate profile",
      mixinStandardHelpOptions = true)
  public static class ProfileAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = "--type", description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    private String type = "xijson";

    @Option(names = "--conf", description = "certificate profile configuration")
    private String conf;

    @Option(names = "--conf-file", description = "certificate profile configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        String effectiveConf = CaMgmtUtil.loadOptionalText(conf, confFile);
        client().addCertprofile(new CertprofileEntry(new NameId(null, name), type, effectiveConf));
        println("added certificate profile " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not add profile " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "profile-export", description = "export certificate profile configuration",
      mixinStandardHelpOptions = true)
  static class ProfileExportCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = {"--out", "-o"}, required = true, description = "output file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        CertprofileEntry entry = Optional.ofNullable(client().getCertprofile(name))
            .orElseThrow(() -> new CaMgmtException("no certificate profile named "
                + name + " is defined"));
        if (StringUtil.isBlank(entry.conf())) {
          println("cert profile does not have conf");
        } else {
          saveVerbose("saved cert profile configuration to", confFile,
              StringUtil.toUtf8Bytes(entry.conf()));
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not export profile configuration: "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "simple-profile-info",
      description = "show simple information of certificate profile",
      mixinStandardHelpOptions = true)
  static class SimpleProfileInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = {"--verbose", "-v"}, description = "show certificate profile verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        if (name == null) {
          println(CaMgmtUtil.formatNames("profile", client().getCertprofileNames()));
          return;
        }

        org.xipki.ca.api.mgmt.SimpleProfileInfo entry =
            Optional.ofNullable(client().getSimpleCertprofileInfo(name))
                .orElseThrow(() -> new CaMgmtException(
                "no certificate profile named '" + name + "' is configured"));
        println(entry.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get simple profile info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "profile-info", description = "show information of certificate profile",
      mixinStandardHelpOptions = true)
  static class ProfileInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = {"--verbose", "-v"}, description = "show certificate profile verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        if (name == null) {
          println(CaMgmtUtil.formatNames("profile", client().getCertprofileNames()));
          return;
        }

        CertprofileEntry entry = Optional.ofNullable(client().getCertprofile(name))
            .orElseThrow(() -> new CaMgmtException(
                "no certificate profile named '" + name + "' is configured"));
        println(entry.toString(verbose));
      } catch (Exception ex) {
        throw new RuntimeException("could not get profile info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "profile-rm", description = "remove certificate profile",
      mixinStandardHelpOptions = true)
  public static class ProfileRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove certificate profile " + name)) {
          client().removeCertprofile(name);
          println("removed certificate profile " + name);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove profile " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "profile-up", description = "update certificate profile",
      mixinStandardHelpOptions = true)
  public static class ProfileUpCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = "--type", description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    private String type;

    @Option(names = "--conf", description = "certificate profile configuration or null")
    private String conf;

    @Option(names = "--conf-file", description = "certificate profile configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        if (type == null && conf == null && confFile == null) {
          throw new IllegalArgumentException("nothing to update");
        }
        String effectiveConf = CaMgmtUtil.loadOptionalText(conf, confFile);
        client().changeCertprofile(name, type, effectiveConf);
        println("updated certificate profile " + name);
      } catch (Exception ex) {
        throw new RuntimeException("could not update profile " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "convert-profile",
      description = "convert the profile file to the up-to-date format",
      mixinStandardHelpOptions = true)
  static class ConvertProfileCommand extends ShellBaseCommand {

    @Option(names = "--in", required = true, description = "input certificate profile file")
    @Completion(FilePathCompleter.class)
    private String inFile;

    @Option(names = "--out", required = true, description = "output file")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        Path inPath = Paths.get(inFile);
        JsonMap json = JsonParser.parseMap(inPath, true);
        Object subject = json.getObject("subject");

        byte[] outBytes;
        if (subject instanceof JsonList) {
          outBytes = Files.readAllBytes(inPath);
        } else {
          XijsonCertprofileType conf = V1XijsonCertprofileType.parse(json).toV2();
          outBytes = StringUtil.toUtf8Bytes(JsonBuilder.toPrettyJson(conf.toCodec()));
        }

        IoUtil.save(outFile, outBytes);
        println("converted profile file to " + outFile);
      } catch (Exception ex) {
        throw new RuntimeException("could not convert profile: " + ex.getMessage(), ex);
      }
    }
  }
}
