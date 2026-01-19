// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Native PKCS#11 module loader.
 *
 * @author Lijun Liao (xipki)
 */

public class NativePKCS11Loader {

  private static final Logger log =
      LoggerFactory.getLogger(NativePKCS11Loader.class);

  /**
   * Indicates, if the static linking and initialization of the library is
   * already done.
   */
  private static boolean linkedAndInitialized;

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module;
   * e.g. "slbck.dll". Tries to load the PKCS#11 wrapper native library from
   * the class path (jar file) or library path.
   *
   * @return An instance of Module that is connected to the given PKCS#11
   *         module.
   */
  public static PKCS11 newPKCS11() {
    ensureLinkedAndInitialized();
    return new NativePKCS11();
  }

  /**
   * This method ensures that the library is linked to this class and that it
   * is initialized. Tries to load the PKCS#11 wrapper native library from the
   * library or the class path (jar file).
   */
  private static synchronized void ensureLinkedAndInitialized() {
    if (!linkedAndInitialized) {
      try {
        System.loadLibrary("pkcs11wrapper");
      } catch (UnsatisfiedLinkError e) {
        try {
          loadWrapperFromJar();
        } catch (IOException ioe) {
          throw new UnsatisfiedLinkError(
              "no pkcs11wrapper in library path or jar file. "
                  + ioe.getMessage());
        }
      }
      linkedAndInitialized = NativePKCS11.initializeLibrary();
    }
  }

  /**
   * Tries to load the PKCS#11 wrapper native library included in the class
   * path (jar file). If loaded from the jar file and wrapperDebugVersion is
   * true, uses the included debug version. The found native library is copied
   * to the temporary-file directory and loaded from there.
   *
   * @throws IOException
   *         if the wrapper native library for the system's architecture can't
   *         be found in the jar file or if corresponding native library can't
   *         be written to temporary directory
   */
  private static void loadWrapperFromJar() throws IOException {
    final String PKCS11_TEMP_DIR = "PKCS11_TEMP_DIR";

    String osName   = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    String archName = System.getProperty("os.arch").toLowerCase(Locale.ROOT);

    String libName;
    String system;
    List<String> archPaths = new ArrayList<>(3);
    if (osName.contains("mac")) {
      system  = "macosx";
      libName = "libpkcs11wrapper.jnilib";
      archPaths.add("universal");
    } else if (osName.contains("win")) {
      system  = "windows";
      libName = "pkcs11wrapper.dll";
      if (archName.contains("aarch64") || archName.contains("arm64")) {
        archPaths.add("arm64");
      } else if (archName.contains("64")) {
        archPaths.add("x86_64");
      } else if (archName.contains("32") || archName.contains("86")) {
        archPaths.add("x86");
      } else {
        archPaths.add("x86_64");
        archPaths.add("x86");
        archPaths.add("arm64");
      }
    } else {
      system  = "linux";
      libName = "libpkcs11wrapper.so";

      if (archName.contains("aarch64") || archName.contains("arm64")) {
        archPaths.add("arm64");
      } else if (archName.contains("riscv")) {
          archPaths.add("riscv64");
      } else if (archName.contains("64")) {
        archPaths.add("x86_64");
      } else if (archName.contains("32") || archName.contains("86")) {
        archPaths.add("x86");
      } else {
        archPaths.add("x86_64");
        archPaths.add("arm64");
        archPaths.add("x86");
        archPaths.add("riscv64");
      }
    }

    String propValue = System.getProperty(PKCS11_TEMP_DIR, null);
    File tempWrapperDir = null;
    if (propValue != null && !propValue.isEmpty()) {
      tempWrapperDir = new File(propValue);

      if (!tempWrapperDir.exists()) {
        throw new IOException("Specified local temp directory '"
            + propValue + "' does not exist!");
      }
    }

    ClassLoader classLoader = NativePKCS11Loader.class.getClassLoader();
    boolean success = false;
    for (String archPath : archPaths) {
      String jarFilePath = "natives/" + system + "/" + archPath + "/" + libName;

      try (InputStream wrapperLibrary =
               classLoader.getResourceAsStream(jarFilePath)) {
        if (wrapperLibrary == null) {
          log.error("found no native library file {}", jarFilePath);
          continue;
        }

        File tempWrapperFile =
            File.createTempFile(libName, null, tempWrapperDir);
        if (!tempWrapperFile.canWrite()) {
          throw new IOException("Can't copy wrapper native library to local " +
              "temporary directory - no write permission in " +
              tempWrapperFile.getAbsolutePath());
        }

        tempWrapperFile.deleteOnExit();

        log.info("PKCS11Module.loadWrapperFromJar: copy file {} " +
            "to a temporary file", jarFilePath);

        Files.copy(wrapperLibrary, tempWrapperFile.toPath(),
            StandardCopyOption.REPLACE_EXISTING);

        try {
          System.load(tempWrapperFile.getAbsolutePath());
          log.info("Using the library " + jarFilePath);
          success = true;
          break;
        } catch (UnsatisfiedLinkError e) {
          tempWrapperFile.delete();
        }
      }
    }

    if (!success) {
      throw new IOException("No suitable wrapper native library found " +
          "in jar file. " + osName + " " + archName + " not supported.");
    }
  }

}
