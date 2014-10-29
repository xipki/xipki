/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.api;

/**
 * @author Lijun Liao
 */

public class RemoveExpiredCertsResult
{
    private int numOfCerts;
    private long expiredAt;
    private String userLike;
    private String certProfile;

    public int getNumOfCerts()
    {
        return numOfCerts;
    }

    public void setNumOfCerts(int numOfCerts)
    {
        this.numOfCerts = numOfCerts;
    }

    public long getExpiredAt()
    {
        return expiredAt;
    }

    public void setExpiredAt(long expiredAt)
    {
        this.expiredAt = expiredAt;
    }

    public String getUserLike()
    {
        return userLike;
    }

    public void setUserLike(String userLike)
    {
        this.userLike = userLike;
    }

    public String getCertProfile()
    {
        return certProfile;
    }

    public void setCertProfile(String certProfile)
    {
        this.certProfile = certProfile;
    }

}
