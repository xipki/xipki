/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.api.profile;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.xipki.security.common.ParamChecker;

public class OriginalProfileConf {
    private static final String SubjectKeyIdentifier = "SubjectKeyIdentifier";
    private static final String AuthorityKeyIdentifier = "AuthorityKeyIdentifier";
    private static final String AuthorityInfoAccess = "AuthorityInfoAccess";
    private static final String CRLDisributionPoints = "CRLDisributionPoints";

    private final String profileName;

    private boolean subjectKeyIdentifierSpecified = false;
    private ExtensionOccurrence subjectKeyIdentifier;

    private boolean authorityKeyIdentifierSpecified = false;

    private ExtensionOccurrence authorityKeyIdentifier;

    private boolean authorityInfoAccessSpecified = false;
    private ExtensionOccurrence authorityInfoAccess;

    private boolean cRLDisributionPointsSpecified = false;
    private ExtensionOccurrence cRLDisributionPoints;

    public OriginalProfileConf(String profileName)
    {
        ParamChecker.assertNotEmpty("profileName", profileName);
        this.profileName = profileName;
    }

    public void setSubjectKeyIdentifier(ExtensionOccurrence subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.subjectKeyIdentifierSpecified = true;
    }

    public void setAuthorityKeyIdentifier(ExtensionOccurrence authorityKeyIdentifier) {
        this.authorityKeyIdentifier = authorityKeyIdentifier;
        this.authorityKeyIdentifierSpecified = true;
    }

    public void setAuthorityInfoAccess(ExtensionOccurrence authorityInfoAccess) {
        this.authorityInfoAccess = authorityInfoAccess;
        this.authorityInfoAccessSpecified = true;
    }

    public void setCRLDisributionPoints(ExtensionOccurrence cRLDisributionPoints) {
        this.cRLDisributionPoints = cRLDisributionPoints;
        this.cRLDisributionPointsSpecified = true;
    }

    public static OriginalProfileConf getInstance(String encoded)
    throws ParseException
    {
        try{
            StringTokenizer st = new StringTokenizer(encoded, ";");
            Map<String, String> keyValues = new HashMap<String, String>();
            while(st.hasMoreTokens())
            {
                String token = st.nextToken();
                StringTokenizer st2 = new StringTokenizer(token, "=");

                String key = st2.nextToken();
                String value = st2.nextToken();
                keyValues.put(key, value);
            }

            String profileName = keyValues.get("name");
            if(profileName == null || profileName.isEmpty())
            {
                throw new ParseException("profile name is not set or is empty", 0);
            }
            OriginalProfileConf conf = new OriginalProfileConf(profileName);

            String control = keyValues.get(SubjectKeyIdentifier);
            if(control != null)
            {
                ExtensionOccurrence occurence = extractExtensionControl(control);
                conf.setSubjectKeyIdentifier(occurence);
            }

            control = keyValues.get(AuthorityKeyIdentifier);
            if(control != null)
            {
                ExtensionOccurrence occurence = extractExtensionControl(control);
                conf.setAuthorityKeyIdentifier(occurence);
            }

            control = keyValues.get(AuthorityInfoAccess);
            if(control != null)
            {
                ExtensionOccurrence occurence = extractExtensionControl(control);
                conf.setAuthorityInfoAccess(occurence);
            }

            control = keyValues.get(CRLDisributionPoints);
            if(control != null)
            {
                ExtensionOccurrence occurence = extractExtensionControl(control);
                conf.setCRLDisributionPoints(occurence);
            }

            return conf;
        } catch(ParseException e)
        {
            throw e;
        } catch(Exception e)
        {
            throw new ParseException("invalid configuration " + encoded, 0);
        }


    }

    private static ExtensionOccurrence extractExtensionControl(String control)
    throws ParseException
    {
        StringTokenizer st = new StringTokenizer(control, ",");
        String token = st.nextToken();

        boolean required;
        if("NONE".equalsIgnoreCase(token))
        {
            return null;
        }
        else if("REQUIRED".equalsIgnoreCase(token))
        {
            required = true;
        }
        else if("OPTIONAL".equalsIgnoreCase(token))
        {
            required = false;
        }
        else
        {
            throw new ParseException("invalid control: " + control, 0);
        }

        boolean critical = false;
        if(st.hasMoreTokens())
        {
            token = st.nextToken();
            if("CRITICAL".equalsIgnoreCase(token))
            {
                critical = true;
            }
            else
            {
                throw new ParseException("invalid control: " + control, 0);
            }
        }

        return ExtensionOccurrence.getInstance(required, critical);
    }

    public String getEncoded()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name=").append(profileName).append(";");

        if(subjectKeyIdentifierSpecified)
        {
            addExtensionControl(sb, SubjectKeyIdentifier, subjectKeyIdentifier);
        }

        if(authorityKeyIdentifierSpecified)
        {
            addExtensionControl(sb, AuthorityKeyIdentifier, authorityKeyIdentifier);
        }

        if(authorityInfoAccessSpecified)
        {
            addExtensionControl(sb, AuthorityInfoAccess, authorityInfoAccess);
        }

        if(cRLDisributionPointsSpecified)
        {
            addExtensionControl(sb, CRLDisributionPoints, cRLDisributionPoints);
        }
        return sb.substring(0, sb.length()-1);
    }

    private static void addExtensionControl(StringBuilder sb, String extensionName, ExtensionOccurrence extensionControl)
    {
        sb.append(extensionName).append("=");
        if(extensionControl == null)
        {
            sb.append("NONE");
        }
        else
        {
            sb.append(extensionControl.isRequired()  ? "REQUIRED" : "OPTIONAL");
            if(extensionControl.isCritical())
            {
                sb.append(",CRITICAL");
            }
        }
        sb.append(";");
    }

    public String getProfileName() {
        return profileName;
    }

    public ExtensionOccurrence getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    public ExtensionOccurrence getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    public ExtensionOccurrence getAuthorityInfoAccess() {
        return authorityInfoAccess;
    }

    public ExtensionOccurrence getCRLDisributionPoints() {
        return cRLDisributionPoints;
    }

    public boolean isSubjectKeyIdentifierSpecified() {
        return subjectKeyIdentifierSpecified;
    }

    public boolean isAuthorityKeyIdentifierSpecified() {
        return authorityKeyIdentifierSpecified;
    }

    public boolean isAuthorityInfoAccessSpecified() {
        return authorityInfoAccessSpecified;
    }

    public boolean iscRLDisributionPointsSpecified() {
        return cRLDisributionPointsSpecified;
    }

    @Override
    public String toString()
    {
        return getEncoded();
    }


}
