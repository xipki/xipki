-- The tables CAData and CertificateData of EJBCA CE, with their indexes, unchanged from
-- https://raw.githubusercontent.com/Keyfactor/ejbca-ce/main/doc/sql-scripts/create-tables-ejbca-postgres.sql
-- https://raw.githubusercontent.com/Keyfactor/ejbca-ce/main/doc/sql-scripts/create-index-ejbca.sql
-- (EJBCA CE, LGPL 2.1). Run in H2 with MODE=PostgreSQL.

CREATE TABLE CAData (
    cAId INT4 NOT NULL,
    data TEXT NOT NULL,
    expireTime INT8 NOT NULL,
    name TEXT,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    status INT4 NOT NULL,
    subjectDN TEXT,
    updateTime INT8 NOT NULL,
    PRIMARY KEY (cAId)
);

CREATE TABLE CertificateData (
    fingerprint TEXT NOT NULL,
    base64Cert TEXT,
    cAFingerprint TEXT,
    certificateProfileId INT4 NOT NULL,
    endEntityProfileId INT4,
    crlPartitionIndex INT4,
    expireDate INT8 NOT NULL,
    issuerDN TEXT NOT NULL,
    notBefore INT8,
    invalidityDate INT8,
    revocationDate INT8 NOT NULL,
    revocationReason INT4 NOT NULL,
    rowProtection TEXT,
    rowVersion INT4 NOT NULL,
    serialNumber TEXT NOT NULL,
    status INT4 NOT NULL,
    subjectAltName TEXT,
    subjectDN TEXT NOT NULL,
    subjectKeyId TEXT,
    accountBindingId TEXT,
    tag TEXT,
    type INT4 NOT NULL,
    updateTime INT8 NOT NULL,
    username TEXT,
    certificateRequest TEXT,
    PRIMARY KEY (fingerprint)
);

CREATE UNIQUE INDEX cadata_idx1 ON CAData (name);

CREATE INDEX certificatedata_idx2 ON CertificateData (username);
CREATE INDEX certificatedata_idx4 ON CertificateData (subjectDN);
CREATE INDEX certificatedata_idx5 ON CertificateData (type);
CREATE INDEX certificatedata_idx6 ON CertificateData (issuerDN,status,revocationDate);
CREATE INDEX certificatedata_idx7 ON CertificateData(certificateProfileId);
CREATE INDEX certificatedata_idx11 ON CertificateData (subjectKeyId);
CREATE UNIQUE INDEX certificatedata_idx12 ON CertificateData (serialNumber, issuerDN);
CREATE INDEX certificatedata_idx15 ON CertificateData (issuerDN,notBefore);
CREATE INDEX certificatedata_idx16 ON CertificateData (issuerDN,revocationDate);
CREATE INDEX certificatedata_idx17 ON CertificateData (issuerDN, status, crlPartitionIndex);
CREATE INDEX certificatedata_idx18 ON CertificateData (issuerDN, status, crlPartitionIndex, revocationDate);
CREATE INDEX certificatedata_idx_serial ON CertificateData (serialNumber);
CREATE INDEX certificatedata_idx_eab ON CertificateData (accountBindingId);
