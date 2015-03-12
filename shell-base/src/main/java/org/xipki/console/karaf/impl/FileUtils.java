/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.console.karaf.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.xipki.console.karaf.impl.completer.Configuration;

/**
 * @author Lijun Liao
 */

public class FileUtils
{

    /**
     * Deletes a directory recursively.
     *
     * @param directory  directory to delete
     * @throws IOException in case deletion is unsuccessful
     * @throws IllegalArgumentException if {@code directory} does not exist or is not a directory
     */
    public static void deleteDirectory(final File directory)
    throws IOException
    {
        if (directory.exists() == false)
        {
            return;
        }

        if (isSymlink(directory) == false)
        {
            cleanDirectory(directory);
        }

        if (directory.delete() == false)
        {
            throw new IOException("Unable to delete directory " + directory + ".");
        }
    }

    /**
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
     * @param file the file to check
     * @return true if the file is a Symbolic Link
     * @throws IOException if an IO error occurs while checking the file
     * @since 2.0
     */
    public static boolean isSymlink(final File file)
    throws IOException
    {
        if (file == null)
        {
            throw new NullPointerException("File must not be null");
        }
        if (Configuration.isWindows())
        {
            return false;
        }
        File fileInCanonicalDir = null;
        if (file.getParent() == null)
        {
            fileInCanonicalDir = file;
        } else
        {
            final File canonicalDir = file.getParentFile().getCanonicalFile();
            fileInCanonicalDir = new File(canonicalDir, file.getName());
        }

        return false == fileInCanonicalDir.getCanonicalFile().equals(fileInCanonicalDir.getAbsoluteFile());
    }

    /**
     * Cleans a directory without deleting it.
     *
     * @param directory directory to clean
     * @throws IOException in case cleaning is unsuccessful
     * @throws IllegalArgumentException if {@code directory} does not exist or is not a directory
     */
    public static void cleanDirectory(final File directory)
    throws IOException
    {
        if (directory.exists() == false)
        {
            throw new IllegalArgumentException(directory + " does not exist");
        }

        if (directory.isDirectory() == false)
        {
            throw new IllegalArgumentException(directory + " is not a directory");
        }

        final File[] files = directory.listFiles();
        if (files == null)
        {  // null if security restricted
            throw new IOException("Failed to list contents of " + directory);
        }

        IOException exception = null;
        for (final File file : files)
        {
            try
            {
                forceDelete(file);
            } catch (final IOException ioe)
            {
                exception = ioe;
            }
        }

        if (null != exception)
        {
            throw exception;
        }
    }

    /**
     * Deletes a file. If file is a directory, delete it and all sub-directories.
     * <p>
     * The difference between File.delete() and this method are:
     * <ul>
     * <li>A directory to be deleted does not have to be empty.</li>
     * <li>You get exceptions when a file or directory cannot be deleted.
     *      (java.io.File methods returns a boolean)</li>
     * </ul>
     *
     * @param file  file or directory to delete, must not be {@code null}
     * @throws NullPointerException if the directory is {@code null}
     * @throws FileNotFoundException if the file was not found
     * @throws IOException in case deletion is unsuccessful
     */
    public static void forceDelete(final File file)
    throws IOException
    {
        if (file.isDirectory())
        {
            deleteDirectory(file);
        } else
        {
            final boolean filePresent = file.exists();
            if (file.delete() == false)
            {
                if (filePresent == false)
                {
                    throw new FileNotFoundException("File does not exist: " + file);
                }
                throw new IOException("Unable to delete file: " + file);
            }
        }
    }

}
