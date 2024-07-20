// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * File utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.2.0
 */

public class FileUtils {

  private FileUtils() {
  }

  /**
   * Copied from the apache commons io project.
   *
   * <p>Deletes a directory recursively.
   *
   * @param directory - directory to delete
   * @throws IOException in case deletion is unsuccessful
   * @throws IllegalArgumentException if {@code directory} does not exist or is not a directory
   */
  public static void deleteDirectory(File directory) throws IOException {
    if (!directory.exists()) {
      return;
    }

    if (!isSymlink(directory)) {
      cleanDirectory(directory);
    }

    if (!directory.delete()) {
      throw new IOException("Unable to delete directory " + directory + ".");
    }
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Determines whether the specified file is a Symbolic Link rather than an actual file.
   *
   * <p>Will not return true if there is a Symbolic Link anywhere in the path,
   * only if the specific file is.
   *
   * <p>For code that runs on Java 1.7 or later, use the following method instead:
   * <br>
   * {@code boolean java.nio.file.Files.isSymbolicLink(Path path)}
   * @param file - the file to check
   * @return true if the file is a Symbolic Link
   * @throws IOException if an IO error occurs while checking the file
   * @since 2.0.0
   */
  private static boolean isSymlink(File file) throws IOException {
    Args.notNull(file, "file");

    if (System.getProperty("os.name").toLowerCase().startsWith("windows")) {
      return false;
    }

    File fileInCanonicalDir = (file.getParent() == null) ? file
        : new File(file.getParentFile().getCanonicalFile(), file.getName());

    return !fileInCanonicalDir.getCanonicalFile().equals(fileInCanonicalDir.getAbsoluteFile());
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Cleans a directory without deleting it.
   *
   * @param directory - directory to clean
   * @throws IOException in case cleaning is unsuccessful
   * @throws IllegalArgumentException if {@code directory} does not exist or is not a directory
   */
  private static void cleanDirectory(File directory) throws IOException {
    if (!directory.exists()) {
      throw new IllegalArgumentException(directory + " does not exist");
    }

    if (!directory.isDirectory()) {
      throw new IllegalArgumentException(directory + " is not a directory");
    }

    final File[] files = directory.listFiles();
    // null if security restricted
    if (files == null) {
      throw new IOException("Failed to list contents of " + directory);
    }

    IOException exception = null;
    for (final File file : files) {
      try {
        forceDelete(file);
      } catch (final IOException ioe) {
        exception = ioe;
      }
    }

    if (null != exception) {
      throw exception;
    }
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Deletes a file. If file is a directory, delete it and all subdirectories.
   *
   * <p>The difference between File.delete() and this method are:
   * <ul>
   * <li>A directory to be deleted does not have to be empty.</li>
   * <li>You get exceptions when a file or directory may not be deleted.
   *        (java.io.File methods returns a boolean)</li>
   * </ul>
   *
   * @param file - file or directory to delete, may not be {@code null}
   * @throws NullPointerException if the directory is {@code null}
   * @throws FileNotFoundException if the file was not found
   * @throws IOException in case deletion is unsuccessful
   */
  static void forceDelete(File file) throws IOException {
    if (file.isDirectory()) {
      deleteDirectory(file);
      return;
    }

    final boolean filePresent = file.exists();
    if (!file.delete()) {
      if (!filePresent) {
        throw new FileNotFoundException("File does not exist: " + file);
      }
      throw new IOException("Unable to delete file: " + file);
    }
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Internal copy file method.
   * This caches the original file length, and an IOException will be thrown
   * if the output file length is different from the current input file length.
   * So it may fail if the file changes size.
   * It may also fail with "IllegalArgumentException: Negative size" if the
   * input file is truncated part way
   * through copying the data and the new file size is less than the current position.
   *
   * @param srcFile - the validated source file, may not be {@code null}
   * @param destFile - the validated destination file, may not be {@code null}
   * @param preserveFileDate whether to preserve the file date
   * @throws IOException if an error occurs
   * @throws IOException if the output file length is not the same as the input
   *     file length after the copy completes
   * @throws IllegalArgumentException "Negative size" if the file is truncated so that the size
   *     is less than the position
   */
  public static void copyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
    if (destFile.exists() && destFile.isDirectory()) {
      throw new IOException("Destination '" + destFile + "' exists but is a directory");
    }

    Files.copy(srcFile.toPath(), destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    if (preserveFileDate) {
      destFile.setLastModified(srcFile.lastModified());
    }
  }

  public static void copyDirectory(File srcDir, File destDir) throws IOException {
    copyDirectory(srcDir, destDir, null, true, null);
  }

  /**
   * Copied from the apache commons io project
   *
   * <p>Internal copy directory method.
   *
   * @param srcDir - the validated source directory, may not be {@code null}
   * @param destDir - the validated destination directory, may not be {@code null}
   * @param filter - the filter to apply, null means copy all directories and files
   * @param preserveFileDate - whether to preserve the file date
   * @param exclusionList - List of files and directories to exclude from the copy, may be null
   * @throws IOException if an error occurs
   * @since 1.1
   */
  private static void copyDirectory(File srcDir, File destDir, FileFilter filter,
      boolean preserveFileDate, List<String> exclusionList) throws IOException {
    // recurse
    final File[] srcFiles = (filter == null)
        ? srcDir.listFiles()
        : srcDir.listFiles(filter);
    if (srcFiles == null) {
      // null if abstract pathname does not denote a directory, or if an I/O error occurs
      throw new IOException("Failed to list contents of " + srcDir);
    }

    if (destDir.exists()) {
      if (!destDir.isDirectory()) {
        throw new IOException("Destination '" + destDir + "' exists but is not a directory");
      }
    } else {
      if (!destDir.mkdirs() && !destDir.isDirectory()) {
        throw new IOException("Destination '" + destDir + "' directory cannot be created");
      }
    }

    if (!destDir.canWrite()) {
      throw new IOException("Destination '" + destDir + "' cannot be written to");
    }

    for (final File srcFile : srcFiles) {
      final File dstFile = new File(destDir, srcFile.getName());
      if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
        if (srcFile.isDirectory()) {
          copyDirectory(srcFile, dstFile, filter, preserveFileDate, exclusionList);
        } else {
          copyFile(srcFile, dstFile, preserveFileDate);
        }
      }
    }

    // Do this last, as the above has probably affected directory metadata
    if (preserveFileDate) {
      destDir.setLastModified(srcDir.lastModified());
    }
  }

}
