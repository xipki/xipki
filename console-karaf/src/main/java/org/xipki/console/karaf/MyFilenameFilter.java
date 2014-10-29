/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.console.karaf;

import java.io.File;
import java.io.FilenameFilter;
import java.util.regex.Pattern;

/**
 * @author Lijun Liao
 */

class MyFilenameFilter implements FilenameFilter
{
    private static final Pattern ignorePattern;

    static
    {
        String ignoreRegex = System.getProperty("org.xipki.console.ignore.regex");
        if(ignoreRegex == null)
        {
            if(Configuration.isWindows() == false)
            {
                ignoreRegex = "\\..*";
            }
        }

        if(ignoreRegex == null || ignoreRegex.isEmpty())
        {
            ignorePattern = null;
        }
        else
        {
            ignorePattern = Pattern.compile(ignoreRegex);
        }
    }

    @Override
    public boolean accept(File dir, String name)
    {
        if(ignorePattern == null)
        {
            return true;
        }

        return ignorePattern.matcher(name).matches() == false;
    }

}
