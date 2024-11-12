// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Utility class to initialize {@link PasswordResolver}.
 *
 * @author Lijun Liao (xipki)
 */

public class Passwords {

  private static final ConcurrentLinkedQueue<PasswordResolver> resolvers = new ConcurrentLinkedQueue<>();

  private static boolean initialized = false;
  private static PasswordResolverException initError;

  private Passwords() {
  }

  private static synchronized void init() {
    if (initialized) {
      return;
    }

    try {
      Properties sysProps = System.getProperties();
      String confFile = sysProps.getProperty("XIPKI_PASSWORD_CFG");
      if (confFile == null) {
        String xipkiBase = sysProps.getProperty("XIPKI_BASE");
        if (xipkiBase == null) {
          xipkiBase = "xipki";
        }

        Path p = Paths.get(xipkiBase, "security", "password.cfg");
        if (Files.exists(p)) {
          confFile = p.toString();
        }
      }

      List<PasswordResolver> resolvers = new LinkedList<>();
      resolvers.add(new OBFPasswordResolver());

      String pbeCallback = null;
      Integer pbeIterationCount = null;

      if (confFile != null) {
        confFile = solveVariables(confFile, 0, sysProps);
        Properties passwordCfg = new Properties();
        try (FileReader reader = new FileReader(confFile)) {
          passwordCfg.load(reader);

          for (String propName : passwordCfg.stringPropertyNames()) {
            if (propName.startsWith("passwordResolver.")) {
              String value = solveVariables(passwordCfg.getProperty(propName).trim(), 0, sysProps);
              int idx = value.indexOf(' ');
              String resolverClassName = (idx == -1) ? value : value.substring(0, idx);
              String resolverConf = (idx == -1) ? null : value.substring(idx + 1);

              PasswordResolver resolver;
              try {
                resolver = (PasswordResolver) Class.forName(resolverClassName).getDeclaredConstructor().newInstance();
              } catch (ReflectiveOperationException ex) {
                throw new PasswordResolverException("error caught while initializing PasswordResolver "
                    + resolverClassName + ": " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
              }

              resolver.init(resolverConf);
              resolvers.add(resolver);
            }
          }

          String text = passwordCfg.getProperty("pbeCallback");
          if (text != null && !text.isEmpty()) {
            pbeCallback = solveVariables(text, 0, sysProps);
            if (pbeCallback.startsWith("FILE file=")) {
              // adapt the path of configured file
              String file = pbeCallback.substring("FILE file=".length());
              if (file.startsWith("~/")) {
                file = System.getProperty("user.home") + file.substring(1);
              }

              Path filePath = Paths.get(file);
              if (!filePath.isAbsolute()) {
                Path confFileParent = Paths.get(confFile).getParent();
                if (confFileParent != null) {
                  file = Paths.get(confFileParent.toString(), file).toString();
                }
              }

              pbeCallback = "FILE file=" + file;
            }
          }

          text = passwordCfg.getProperty("pbeIterationCount");
          if (text != null && !text.isEmpty()) {
            pbeIterationCount = Integer.parseInt(solveVariables(text, 0, sysProps));
          }
        }
      }

      // PBE
      String pbeConf = "";
      if (pbeCallback != null) {
        pbeConf += "callback=" + pbeCallback.replace(",", "\\,").replace("=", "\\=");
      }

      if (pbeIterationCount != null) {
        if (!pbeConf.isEmpty()) {
          pbeConf += ",";
        }
        pbeConf += "iterationCount=" + pbeIterationCount;
      }

      PBEPasswordResolver pbe = new PBEPasswordResolver();
      pbe.init(pbeConf);
      resolvers.add(pbe);

      Passwords.resolvers.addAll(resolvers);
    } catch (PasswordResolverException ex) {
      initError = ex;
    } catch (Exception ex) {
      initError = new PasswordResolverException(ex);
    } finally {
      initialized = true;
    }
  }

  public static char[] resolvePassword(String passwordHint) throws PasswordResolverException {
    if (passwordHint == null) {
      return null;
    }

    int index = passwordHint.indexOf(':');
    if (index == -1) {
      return passwordHint.toCharArray();
    }

    init();
    if (initError != null) {
      throw initError;
    }

    String protocol = passwordHint.substring(0, index);

    for (PasswordResolver resolver : resolvers) {
      if (resolver.canResolveProtocol(protocol)) {
        return resolver.resolvePassword(passwordHint);
      }
    }

    if (OBFPasswordService.PROTOCOL_OBF.equalsIgnoreCase(protocol)
        || PBEPasswordService.PROTOCOL_PBE.equalsIgnoreCase(protocol)) {
      throw new PasswordResolverException("could not find password resolver to resolve password "
          + "of protocol '" + protocol + "'");
    } else {
      return passwordHint.toCharArray();
    }

  }

  public static String protectPassword(String protocol, char[] password) throws PasswordResolverException {
    init();
    if (initError != null) {
      throw initError;
    }

    for (PasswordResolver resolver : resolvers) {
      if (resolver.canResolveProtocol(protocol)) {
        return resolver.protectPassword(password);
      }
    }

    throw new PasswordResolverException("could not find password resolver to protect password "
        + "of protocol '" + protocol + "'");
  }

  private static String solveVariables(String line, int offset, Properties properties) {
    if (offset + 4 >= line.length()) {
      return line;
    }

    int startIndex = line.indexOf("${", offset);
    if (startIndex == -1) {
      return line;
    }

    int endIndex = line.indexOf("}", startIndex + 2);
    if (endIndex == -1) {
      return line;
    }

    String variable = line.substring(startIndex, endIndex + 1);
    String name = variable.substring(2, variable.length() - 1);
    boolean isEnv = false;
    if (name.startsWith("env:")) {
      isEnv = true;
      name = name.substring(4);
    } else if (name.startsWith("sys:")) {
      name = name.substring(4);
    }
    String value = isEnv ? System.getenv(name) : properties.getProperty(name);

    int newOffset;
    if (value != null) {
      line = line.substring(0, startIndex) + value + line.substring(endIndex + 1);
      newOffset = startIndex + value.length() + 1;
    } else {
      newOffset = endIndex + 1;
    }

    return solveVariables(line, newOffset, properties);
  }

  private static class OBFPasswordResolver implements PasswordResolver {

    public OBFPasswordResolver() {
    }

    @Override
    public void init(String conf) throws PasswordResolverException {
      if (conf != null && !conf.isEmpty()) {
        throw new PasswordResolverException("non-empty conf is not allowed");
      }
    }

    @Override
    public boolean canResolveProtocol(String protocol) {
      return OBFPasswordService.PROTOCOL_OBF.equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint) {
      return OBFPasswordService.deobfuscate(passwordHint).toCharArray();
    }

    @Override
    public String protectPassword(char[] password) {
      return OBFPasswordService.obfuscate(new String(password));
    }

  } // class OBF

  private static class PBEPasswordResolver implements PasswordResolver {

    private char[] masterPassword;

    private final Object masterPasswordLock = new Object();

    private PasswordCallback masterPasswordCallback;

    private int iterationCount = 2000;

    public PBEPasswordResolver() {
    }

    @Override
    public void init(String conf) throws PasswordResolverException {
      String callback = "PBE-GUI";
      if (conf != null && !conf.isEmpty()) {
        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.value("callback");
        if (str != null && !str.isEmpty()) {
          callback = str;
        }

        str = pairs.value("iterationCount");
        if (str != null && !str.isEmpty()) {
          iterationCount = Integer.parseInt(str);
          if (iterationCount < 1000) {
            throw new PasswordResolverException("iterationCount less than 1000 is not allowed");
          }
        }
      }

      this.masterPasswordCallback = getPasswordCallback(callback);
    }

    protected char[] getMasterPassword(String encryptedPassword) throws PasswordResolverException {
      synchronized (masterPasswordLock) {
        if (masterPassword == null) {
          if (masterPasswordCallback == null) {
            throw new PasswordResolverException("masterPasswordCallback is not initialized");
          }
          this.masterPassword = masterPasswordCallback.getPassword("Please enter the master password",
              encryptedPassword);
        }
        return masterPassword;
      }
    }

    @Override
    public boolean canResolveProtocol(String protocol) {
      return PBEPasswordService.PROTOCOL_PBE.equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(String passwordHint) throws PasswordResolverException {
      return PBEPasswordService.decryptPassword(getMasterPassword(passwordHint), passwordHint);
    }

    @Override
    public String protectPassword(char[] password) throws PasswordResolverException {
      return PBEPasswordService.encryptPassword(PBEAlgo.PBEWithHmacSHA256AndAES_256, iterationCount,
          getMasterPassword(null), password);
    }

  } // class PBEPasswordResolver

  private static class FilePasswordCallback implements PasswordCallback {

    private String passwordFile;

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
      if (passwordFile == null) {
        throw new PasswordResolverException("please initialize me first");
      }

      String passwordHint = null;
      try (BufferedReader reader = Files.newBufferedReader(Paths.get(passwordFile))) {
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.trim();
          if (Args.isNotBlank(line) && !line.startsWith("#")) {
            passwordHint = line;
            break;
          }
        }
      } catch (IOException ex) {
        throw new PasswordResolverException("could not read file " + passwordFile, ex);
      }

      if (passwordHint == null) {
        throw new PasswordResolverException("no password is specified in file " + passwordFile);
      }

      return (Args.startsWithIgnoreCase(passwordHint, OBFPasswordService.PROTOCOL_OBF + ":"))
          ? OBFPasswordService.deobfuscate(passwordHint).toCharArray()
          : passwordHint.toCharArray();
    } // method getPassword

    @Override
    public void init(String conf) throws PasswordResolverException {
      Args.notBlank(conf, "conf");
      ConfPairs pairs = new ConfPairs(conf);
      passwordFile = pairs.value("file");
      if (Args.isBlank(passwordFile)) {
        throw new PasswordResolverException("invalid configuration " + conf + ", no file is specified");
      }
    }

  }

  private static class GuiPasswordCallback implements PasswordCallback {

    private int quorum = 1;

    private int tries = 3;

    protected boolean isPasswordValid(char[] password, String testToken) {
      return true;
    }

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
      String tmpPrompt = prompt;
      if (Args.isBlank(tmpPrompt)) {
        tmpPrompt = "Password required";
      }

      for (int i = 0; i < tries; i++) {
        char[] password;
        if (quorum == 1) {
          password = Optional.ofNullable(SecurePasswordInputPanel.readPassword(tmpPrompt))
              .orElseThrow(() -> new PasswordResolverException("user has cancelled"));
        } else {
          char[][] passwordParts = new char[quorum][];
          for (int j = 0; j < quorum; j++) {
            String promptPart = tmpPrompt + " (part " + (j + 1) + "/" + quorum + ")";
            passwordParts[j] = Optional.ofNullable(SecurePasswordInputPanel.readPassword(promptPart))
                .orElseThrow(() -> new PasswordResolverException("user has cancelled"));
          }
          password = Args.merge(passwordParts);
        }

        if (isPasswordValid(password, testToken)) {
          return password;
        }
      }

      throw new PasswordResolverException("Could not get the password after " + tries + " tries");
    }

    @Override
    public void init(String conf) throws PasswordResolverException {
      if (Args.isBlank(conf)) {
        quorum = 1;
        return;
      }

      ConfPairs pairs = new ConfPairs(conf);
      String str = pairs.value("quorum");
      quorum = Integer.parseInt(str);
      if (quorum < 1 || quorum > 10) {
        throw new PasswordResolverException("quorum " + quorum + " is not in [1,10]");
      }

      str = pairs.value("tries");
      if (Args.isNotBlank(str)) {
        int intValue = Integer.parseInt(str);
        if (intValue > 0) {
          this.tries = intValue;
        }
      }
    }

  }

  private static class OBFPasswordCallback implements PasswordCallback {

    private char[] password;

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
      return Optional.ofNullable(password)
          .orElseThrow(() -> new PasswordResolverException("please initialize me first"));
    }

    @Override
    public void init(String conf) {
      Args.notBlank(conf, "conf");
      this.password = OBFPasswordService.deobfuscate(conf).toCharArray();
    }

  }

  private static class PBEGuiPasswordCallback extends GuiPasswordCallback {

    @Override
    protected boolean isPasswordValid(char[] password, String testToken) {
      if (Args.isBlank(testToken)) {
        return true;
      }
      try {
        PBEPasswordService.decryptPassword(password, testToken);
        return true;
      } catch (PasswordResolverException ex) {
        return false;
      }
    }

  }

  private static PasswordCallback getPasswordCallback(String passwordCallback) throws PasswordResolverException {
    String type;
    String conf = null;

    int delimIndex = passwordCallback.indexOf(' ');
    if (delimIndex == -1) {
      type = passwordCallback;
    } else {
      type = passwordCallback.substring(0, delimIndex);
      conf = passwordCallback.substring(delimIndex + 1);
    }

    PasswordCallback pwdCallback;
    switch (type.toUpperCase(Locale.ROOT)) {
      case "FILE":
        pwdCallback = new FilePasswordCallback();
        break;
      case "GUI":
        pwdCallback = new GuiPasswordCallback();
        break;
      case "PBE-GUI":
        pwdCallback = new PBEGuiPasswordCallback();
        break;
      case OBFPasswordService.PROTOCOL_OBF:
        pwdCallback = new OBFPasswordCallback();
        if (conf != null && !Args.startsWithIgnoreCase(conf, OBFPasswordService.PROTOCOL_OBF + ":")) {
          conf = OBFPasswordService.PROTOCOL_OBF + ":" + conf;
        }
        break;
      default:
        if (type.startsWith("java:")) {
          String className = type.substring(5);
          try {
            pwdCallback = (PasswordCallback) Passwords.class.getClassLoader()
                .loadClass(className).getConstructor().newInstance();
          } catch (Exception e) {
            throw new PasswordResolverException("error creating PasswordCallback of type '" + type + "'");
          }
        } else {
          throw new PasswordResolverException("invalid callback type " + type);
        }
    }

    try {
      pwdCallback.init(conf);
    } catch (PasswordResolverException ex) {
      throw new IllegalArgumentException("invalid passwordCallback configuration "
          + passwordCallback + ", " + ex.getClass().getName() + ": " + ex.getMessage());
    }

    return pwdCallback;
  }

}
