/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

import java.io.File;
import java.nio.charset.Charset;

/**
 * Provides access to configuration values.
 *
 * @author Lijun Liao
 */

public class Configuration
{
    public static String getLineSeparator()
    {
        return System.getProperty("line.separator");
    }

    public static File getUserHome()
    {
        return new File(System.getProperty("user.home"));
    }

    public static String getOsName()
    {
        return System.getProperty("os.name").toLowerCase();
    }

    public static boolean isWindows()
    {
        return getOsName().startsWith("windows");
    }

    public static String getFileEncoding()
    {
        return System.getProperty("file.encoding");
    }

    /**
     * Get the default encoding.  Will first look at the LC_CTYPE environment variable, then the input.encoding
     * system property, then the default charset according to the JVM.
     *
     * @return The default encoding to use when none is specified.
     */
    public static String getEncoding()
    {
        // LC_CTYPE is usually in the form en_US.UTF-8
        String envEncoding = extractEncodingFromCtype(System.getenv("LC_CTYPE"));
        if (envEncoding != null)
        {
            return envEncoding;
        }
        return System.getProperty("input.encoding", Charset.defaultCharset().name());
    }

    /**
     * Parses the LC_CTYPE value to extract the encoding according to the POSIX standard, which says that the LC_CTYPE
     * environment variable may be of the format <code>[language[_territory][.codeset][@modifier]]</code>
     *
     * @param ctype The ctype to parse, may be null
     * @return The encoding, if one was present, otherwise null
     */
    static String extractEncodingFromCtype(String ctype)
    {
        if (ctype != null && ctype.indexOf('.') > 0)
        {
            String encodingAndModifier = ctype.substring(ctype.indexOf('.') + 1);
            if (encodingAndModifier.indexOf('@') > 0)
            {
                return encodingAndModifier.substring(0, encodingAndModifier.indexOf('@'));
            } else
            {
                return encodingAndModifier;
            }
        }
        return null;
    }
}
