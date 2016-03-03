// #THIRDPARTY# Apache commons-io

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.commons.console.karaf.intern;

import java.io.Closeable;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.List;

public class FileUtils {

    /**
     * The file copy buffer size (30 MB)
     */
    private static final long FILE_COPY_BUFFER_SIZE = 1024L * 1024 * 30;

    private FileUtils() {
    }

    /**
     * Copied from the apache commons io project
     *
     * Deletes a directory recursively.
     *
     * @param directory - directory to delete
     * @throws IOException in case deletion is unsuccessful
     * @throws IllegalArgumentException if {@code directory} does not exist or is not a directory
     */
    public static void deleteDirectory(
            final File directory)
    throws IOException {
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
     * Determines whether the specified file is a Symbolic Link rather than an actual file.
     * <p>
     * Will not return true if there is a Symbolic Link anywhere in the path,
     * only if the specific file is.
     * <p>
     * <b>Note:</b> the current implementation always returns {@code false} if the system
     * is detected as Windows using {@link FilenameUtils#isSystemWindows()}
     * <p>
     * For code that runs on Java 1.7 or later, use the following method instead:
     * <br>
     * {@code boolean java.nio.file.Files.isSymbolicLink(Path path)}
     * @param file - the file to check
     * @return true if the file is a Symbolic Link
     * @throws IOException if an IO error occurs while checking the file
     * @since 2.0.0
     */
    public static boolean isSymlink(
            final File file)
    throws IOException {
        if (file == null) {
            throw new NullPointerException("File must not be null");
        }
        if (Configuration.isWindows()) {
            return false;
        }
        File fileInCanonicalDir = null;
        if (file.getParent() == null) {
            fileInCanonicalDir = file;
        } else {
            final File canonicalDir = file.getParentFile().getCanonicalFile();
            fileInCanonicalDir = new File(canonicalDir, file.getName());
        }

        return !fileInCanonicalDir.getCanonicalFile().equals(
                fileInCanonicalDir.getAbsoluteFile());
    }

    /**
     * Copied from the apache commons io project
     *
     * Cleans a directory without deleting it.
     *
     * @param directory - directory to clean
     * @throws IOException in case cleaning is unsuccessful
     * @throws IllegalArgumentException if {@code directory} does not exist or is not a directory
     */
    public static void cleanDirectory(
            final File directory)
    throws IOException {
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
     * Deletes a file. If file is a directory, delete it and all sub-directories.
     * <p>
     * The difference between File.delete() and this method are:
     * <ul>
     * <li>A directory to be deleted does not have to be empty.</li>
     * <li>You get exceptions when a file or directory must not be deleted.
     *        (java.io.File methods returns a boolean)</li>
     * </ul>
     *
     * @param file - file or directory to delete, must not be {@code null}
     * @throws NullPointerException if the directory is {@code null}
     * @throws FileNotFoundException if the file was not found
     * @throws IOException in case deletion is unsuccessful
     */
    public static void forceDelete(
            final File file)
    throws IOException {
        if (file.isDirectory()) {
            deleteDirectory(file);
        } else {
            final boolean filePresent = file.exists();
            if (!file.delete()) {
                if (!filePresent) {
                    throw new FileNotFoundException("File does not exist: " + file);
                }
                throw new IOException("Unable to delete file: " + file);
            }
        }
    }

    /**
     * Copied from the apache commons io project
     *
     * Internal copy file method.
     * This caches the original file length, and an IOException will be thrown
     * if the output file length is different from the current input file length.
     * So it may fail if the file changes size.
     * It may also fail with "IllegalArgumentException: Negative size" if the
     * input file is truncated part way
     * through copying the data and the new file size is less than the current position.
     *
     * @param srcFile - the validated source file, must not be {@code null}
     * @param destFile - the validated destination file, must not be {@code null}
     * @param preserveFileDate whether to preserve the file date
     * @throws IOException if an error occurs
     * @throws IOException if the output file length is not the same as the input
     *     file length after the copy completes
     * @throws IllegalArgumentException "Negative size" if the file is truncated so that the size
     *     is less than the
     * position
     */
    public static void copyFile(
            final File srcFile,
            final File destFile,
            final boolean preserveFileDate)
    throws IOException {
        if (destFile.exists() && destFile.isDirectory()) {
            throw new IOException("Destination '" + destFile + "' exists but is a directory");
        }

        FileInputStream fis = null;
        FileOutputStream fos = null;
        FileChannel input = null;
        FileChannel output = null;
        try {
            fis = new FileInputStream(srcFile);
            fos = new FileOutputStream(destFile);
            input = fis.getChannel();
            output = fos.getChannel();
            final long size = input.size(); // See IO-386
            long pos = 0;
            long count = 0;
            while (pos < size) {
                final long remain = size - pos;
                count = (remain > FILE_COPY_BUFFER_SIZE)
                        ? FILE_COPY_BUFFER_SIZE
                        : remain;
                final long bytesCopied = output.transferFrom(input, pos, count);
                if (bytesCopied == 0) {
                    // IO-385 - can happen if file is truncated after caching the size
                    break; // ensure we don't loop forever
                }
                pos += bytesCopied;
            }
        } finally {
            closeQuietly(output, fos, input, fis);
        }

        final long srcLen = srcFile.length(); // See IO-386
        final long dstLen = destFile.length(); // See IO-386
        if (srcLen != dstLen) {
            throw new IOException("Failed to copy full contents from '"
                    + srcFile + "' to '" + destFile + "' Expected length: " + srcLen
                    + " Actual: " + dstLen);
        }
        if (preserveFileDate) {
            destFile.setLastModified(srcFile.lastModified());
        }
    }

    public static void copyDirectory(
            final File srcDir,
            final File destDir)
    throws IOException {
        copyDirectory(srcDir, destDir, null, true, null);
    }

    /**
     * Copied from the apache commons io project
     *
     * Internal copy directory method.
     *
     * @param srcDir - the validated source directory, must not be {@code null}
     * @param destDir - the validated destination directory, must not be {@code null}
     * @param filter - the filter to apply, null means copy all directories and files
     * @param preserveFileDate - whether to preserve the file date
     * @param exclusionList - List of files and directories to exclude from the copy, may be null
     * @throws IOException if an error occurs
     * @since 1.1
     */
    public static void copyDirectory(
            final File srcDir,
            final File destDir,
            final FileFilter filter,
            final boolean preserveFileDate,
            final List<String> exclusionList)
    throws IOException {
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
                throw new IOException("Destination '" + destDir
                        + "' exists but is not a directory");
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

    /**
     * Copied from the apache commons io project
     *
     * @param closeables
     */
    public static void closeQuietly(
            final Closeable... closeables) {
        if (closeables == null) {
            return;
        }
        for (final Closeable closeable : closeables) {
            doCloseQuietly(closeable);
        }
    }

    private static void doCloseQuietly(
            final Closeable closable) {
        if (closable == null) {
            return;
        }

        try {
            closable.close();
        } catch (Throwable th) {
        }
    }

}
