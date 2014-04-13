SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

DROP SCHEMA IF EXISTS `ca` ;
CREATE SCHEMA IF NOT EXISTS `ca` DEFAULT CHARACTER SET utf8 COLLATE utf8_bin ;
USE `ca` ;

-- -----------------------------------------------------
-- Table `certprofile`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `certprofile` ;

CREATE  TABLE IF NOT EXISTS `certprofile` (
  `name` VARCHAR(45) NOT NULL ,
  `type` VARCHAR(100) NOT NULL ,
  `conf` VARCHAR(4000) NULL DEFAULT NULL COMMENT 'profile data, depends on the type' ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `responder`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `responder` ;

CREATE  TABLE IF NOT EXISTS `responder` (
  `name` VARCHAR(45) NOT NULL ,
  `type` VARCHAR(100) NOT NULL ,
  `conf` VARCHAR(4000) NULL DEFAULT NULL ,
  `cert` VARCHAR(2000) NULL DEFAULT NULL ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `crlsigner`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `crlsigner` ;

CREATE  TABLE IF NOT EXISTS `crlsigner` (
  `name` VARCHAR(45) NOT NULL ,
  `signer_type` VARCHAR(100) NOT NULL ,
  `signer_conf` VARCHAR(4000) NULL ,
  `signer_cert` VARCHAR(2000) NULL ,
  `period` INT NOT NULL COMMENT 'minutes. 0 indicates no CRL will be generated automatically.' ,
  `overlap` INT NOT NULL COMMENT 'minutes' ,
  `include_certs_in_crl` SMALLINT NOT NULL DEFAULT 0 ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `ca`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `ca` ;

CREATE  TABLE IF NOT EXISTS `ca` (
  `name` VARCHAR(45) NOT NULL ,
  `next_serial` INT NULL DEFAULT NULL ,
  `status` VARCHAR(10) NOT NULL COMMENT 'valid values: pending, enabled, disabled' ,
  `subject` VARCHAR(200) NOT NULL ,
  `crl_uris` VARCHAR(100) NULL DEFAULT NULL ,
  `ocsp_uris` VARCHAR(100) NULL DEFAULT NULL ,
  `max_validity` SMALLINT NOT NULL ,
  `cert` VARCHAR(2000) NOT NULL ,
  `signer_type` VARCHAR(100) NOT NULL ,
  `signer_conf` VARCHAR(4000) NOT NULL ,
  `crlsigner_name` VARCHAR(45) NULL ,
  `allow_duplicate_key` SMALLINT NOT NULL DEFAULT 1 ,
  `allow_duplicate_subject` SMALLINT NOT NULL DEFAULT 1 ,
  `permissions` VARCHAR(100) NOT NULL ,
  `num_crls` SMALLINT NOT NULL DEFAULT 30 ,
  PRIMARY KEY (`name`) ,
  INDEX `fk_ca_crlsigner1_idx` (`crlsigner_name` ASC) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) ,
  CONSTRAINT `fk_ca_crlsigner1`
    FOREIGN KEY (`crlsigner_name` )
    REFERENCES `crlsigner` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `requestor`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `requestor` ;

CREATE  TABLE IF NOT EXISTS `requestor` (
  `name` VARCHAR(45) NOT NULL ,
  `cert` VARCHAR(2000) NOT NULL ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `ca_has_certprofile`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `ca_has_certprofile` ;

CREATE  TABLE IF NOT EXISTS `ca_has_certprofile` (
  `ca_name` VARCHAR(45) NOT NULL ,
  `certprofile_name` VARCHAR(45) NOT NULL ,
  PRIMARY KEY (`ca_name`, `certprofile_name`) ,
  INDEX `fk_ca_has_certprofile_certprofile1_idx` (`certprofile_name` ASC) ,
  INDEX `fk_ca_has_certprofile_ca1_idx` (`ca_name` ASC) ,
  CONSTRAINT `fk_ca_has_certprofile_ca1`
    FOREIGN KEY (`ca_name` )
    REFERENCES `ca` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ca_has_certprofile_certprofile1`
    FOREIGN KEY (`certprofile_name` )
    REFERENCES `certprofile` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `ca_has_requestor`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `ca_has_requestor` ;

CREATE  TABLE IF NOT EXISTS `ca_has_requestor` (
  `ca_name` VARCHAR(45) NOT NULL ,
  `requestor_name` VARCHAR(45) NOT NULL ,
  `ra` SMALLINT NOT NULL ,
  `permissions` VARCHAR(100) NULL ,
  `profiles` VARCHAR(200) NULL ,
  PRIMARY KEY (`ca_name`, `requestor_name`) ,
  INDEX `fk_ca_has_cmprequestor_cmprequestor1_idx` (`requestor_name` ASC) ,
  INDEX `fk_ca_has_cmprequestor_ca1_idx` (`ca_name` ASC) ,
  CONSTRAINT `fk_ca_has_cmprequestor_ca1`
    FOREIGN KEY (`ca_name` )
    REFERENCES `ca` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ca_has_cmprequestor_cmprequestor1`
    FOREIGN KEY (`requestor_name` )
    REFERENCES `requestor` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `cainfo`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `cainfo` ;

CREATE  TABLE IF NOT EXISTS `cainfo` (
  `id` INT NOT NULL ,
  `subject` VARCHAR(200) NOT NULL ,
  `cert` VARCHAR(2000) NOT NULL ,
  `sha1_fp_cert` CHAR(40) NOT NULL ,
  PRIMARY KEY (`id`) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `requestorinfo`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `requestorinfo` ;

CREATE  TABLE IF NOT EXISTS `requestorinfo` (
  `id` INT NOT NULL ,
  `subject` VARCHAR(200) NOT NULL ,
  `cert` VARCHAR(2000) NULL ,
  `sha1_fp_cert` CHAR(40) NULL ,
  PRIMARY KEY (`id`) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `user`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `user` ;

CREATE  TABLE IF NOT EXISTS `user` (
  `id` INT NOT NULL ,
  `name` VARCHAR(200) NOT NULL ,
  PRIMARY KEY (`id`) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `certprofileinfo`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `certprofileinfo` ;

CREATE  TABLE IF NOT EXISTS `certprofileinfo` (
  `id` INT NOT NULL ,
  `name` VARCHAR(45) NOT NULL ,
  PRIMARY KEY (`id`) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `cert`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `cert` ;

CREATE  TABLE IF NOT EXISTS `cert` (
  `id` INT NOT NULL ,
  `cainfo_id` INT NOT NULL ,
  `serial` INT NOT NULL ,
  `certprofileinfo_id` INT NOT NULL ,
  `requestorinfo_id` INT NULL ,
  `subject` VARCHAR(200) NOT NULL ,
  `last_update` INT NOT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `notbefore` INT NOT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `notafter` INT NOT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `revocated` SMALLINT NOT NULL ,
  `rev_reason` SMALLINT NULL DEFAULT NULL ,
  `rev_time` INT NULL DEFAULT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `rev_invalidity_time` INT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `user_id` INT NULL ,
  `sha1_fp_pk` CHAR(40) NOT NULL ,
  `sha1_fp_subject` CHAR(40) NOT NULL COMMENT 'SHA1 fingerprint of the canonicalized subject' ,
  PRIMARY KEY (`id`) ,
  INDEX `fk_cert_cainfo1_idx` (`cainfo_id` ASC) ,
  INDEX `fk_cert_requestorinfo1_idx` (`requestorinfo_id` ASC) ,
  INDEX `fk_cert_user1_idx` (`user_id` ASC) ,
  INDEX `fk_cert_certprofileinfo1_idx` (`certprofileinfo_id` ASC) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) ,
  CONSTRAINT `fk_cert_cainfo1`
    FOREIGN KEY (`cainfo_id` )
    REFERENCES `cainfo` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_cert_requestorinfo1`
    FOREIGN KEY (`requestorinfo_id` )
    REFERENCES `requestorinfo` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_cert_user1`
    FOREIGN KEY (`user_id` )
    REFERENCES `user` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_cert_certprofileinfo1`
    FOREIGN KEY (`certprofileinfo_id` )
    REFERENCES `certprofileinfo` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `rawcert`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rawcert` ;

CREATE  TABLE IF NOT EXISTS `rawcert` (
  `cert_id` INT NOT NULL ,
  `sha1_fp` VARCHAR(40) NOT NULL ,
  `cert` VARCHAR(2000) NOT NULL COMMENT 'Base64 encoded certificate' ,
  PRIMARY KEY (`cert_id`) ,
  CONSTRAINT `fk_rawcert_cert1`
    FOREIGN KEY (`cert_id` )
    REFERENCES `cert` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `cmpcontrol`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `cmpcontrol` ;

CREATE  TABLE IF NOT EXISTS `cmpcontrol` (
  `name` VARCHAR(45) NOT NULL ,
  `require_confirm_cert` SMALLINT NOT NULL ,
  `message_time_bias` INT NOT NULL COMMENT 'seconds' ,
  `confirm_wait_time` INT NOT NULL COMMENT 'seconds' ,
  `send_ca_cert` SMALLINT NOT NULL ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `environment`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `environment` ;

CREATE  TABLE IF NOT EXISTS `environment` (
  `name` VARCHAR(45) NOT NULL ,
  `value` VARCHAR(200) NULL ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `publisher`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `publisher` ;

CREATE  TABLE IF NOT EXISTS `publisher` (
  `name` VARCHAR(45) NOT NULL ,
  `type` VARCHAR(100) NOT NULL ,
  `conf` VARCHAR(5000) NULL ,
  PRIMARY KEY (`name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `ca_has_publisher`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `ca_has_publisher` ;

CREATE  TABLE IF NOT EXISTS `ca_has_publisher` (
  `ca_name` VARCHAR(45) NOT NULL ,
  `publisher_name` VARCHAR(45) NOT NULL ,
  PRIMARY KEY (`ca_name`, `publisher_name`) ,
  INDEX `fk_ca_has_publisher_publisher1_idx` (`publisher_name` ASC) ,
  INDEX `fk_ca_has_publisher_ca1_idx` (`ca_name` ASC) ,
  CONSTRAINT `fk_ca_has_publisher_ca1`
    FOREIGN KEY (`ca_name` )
    REFERENCES `ca` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_ca_has_publisher_publisher1`
    FOREIGN KEY (`publisher_name` )
    REFERENCES `publisher` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `crl`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `crl` ;

CREATE  TABLE IF NOT EXISTS `crl` (
  `id` INT NOT NULL AUTO_INCREMENT ,
  `cainfo_id` INT NOT NULL ,
  `crl_number` INT NOT NULL ,
  `thisUpdate` INT NOT NULL ,
  `nextUpdate` INT NULL ,
  `crl` BLOB NOT NULL ,
  PRIMARY KEY (`id`) ,
  INDEX `fk_crl_cainfo1_idx` (`cainfo_id` ASC) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) ,
  CONSTRAINT `fk_crl_cainfo1`
    FOREIGN KEY (`cainfo_id` )
    REFERENCES `cainfo` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `caalias`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `caalias` ;

CREATE  TABLE IF NOT EXISTS `caalias` (
  `name` VARCHAR(45) NOT NULL ,
  `ca_name` VARCHAR(45) NOT NULL ,
  PRIMARY KEY (`name`, `ca_name`) ,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) ,
  INDEX `fk_servletname_ca1_idx` (`ca_name` ASC) ,
  UNIQUE INDEX `ca_name_UNIQUE` (`ca_name` ASC) ,
  CONSTRAINT `fk_servletname_ca1`
    FOREIGN KEY (`ca_name` )
    REFERENCES `ca` (`name` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
