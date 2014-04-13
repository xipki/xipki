SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

DROP SCHEMA IF EXISTS `ocsp` ;
CREATE SCHEMA IF NOT EXISTS `ocsp` DEFAULT CHARACTER SET utf8 COLLATE utf8_bin ;
USE `ocsp` ;

-- -----------------------------------------------------
-- Table `issuer`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `issuer` ;

CREATE  TABLE IF NOT EXISTS `issuer` (
  `id` INT NOT NULL ,
  `subject` VARCHAR(200) NOT NULL ,
  `sha1_fp_name` CHAR(40) NOT NULL ,
  `sha1_fp_key` CHAR(40) NOT NULL ,
  `sha224_fp_name` CHAR(56) NOT NULL ,
  `sha224_fp_key` CHAR(56) NOT NULL ,
  `sha256_fp_name` CHAR(64) NOT NULL ,
  `sha256_fp_key` CHAR(64) NOT NULL ,
  `sha384_fp_name` CHAR(96) NOT NULL ,
  `sha384_fp_key` CHAR(96) NOT NULL ,
  `sha512_fp_name` CHAR(128) NOT NULL ,
  `sha512_fp_key` CHAR(128) NOT NULL ,
  `sha1_fp_cert` CHAR(40) NOT NULL ,
  `cert` VARCHAR(2000) NOT NULL ,
  PRIMARY KEY (`id`) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `certprofile`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `certprofile` ;

CREATE  TABLE IF NOT EXISTS `certprofile` (
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
  `issuer_id` INT NOT NULL ,
  `serial` INT NOT NULL ,
  `certprofile_id` INT NOT NULL ,
  `subject` VARCHAR(200) NOT NULL ,
  `last_update` INT NOT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `notbefore` INT NOT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `notafter` INT NOT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `revocated` SMALLINT NOT NULL ,
  `rev_reason` SMALLINT NULL DEFAULT NULL ,
  `rev_time` INT NULL DEFAULT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  `rev_invalidity_time` INT NULL COMMENT 'seconds since January 1, 1970, 00:00:00 GMT' ,
  PRIMARY KEY (`id`) ,
  INDEX `fk_cert_cainfo1` (`issuer_id` ASC) ,
  INDEX `fk_cert_certprofile1` (`certprofile_id` ASC) ,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) ,
  CONSTRAINT `fk_cert_cainfo1`
    FOREIGN KEY (`issuer_id` )
    REFERENCES `issuer` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_cert_certprofile1`
    FOREIGN KEY (`certprofile_id` )
    REFERENCES `certprofile` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `rawcert`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `rawcert` ;

CREATE  TABLE IF NOT EXISTS `rawcert` (
  `cert_id` INT NOT NULL ,
  `cert` VARCHAR(2000) NOT NULL COMMENT 'Base64 encoded certificate' ,
  PRIMARY KEY (`cert_id`) ,
  CONSTRAINT `fk_rawcert_cert1`
    FOREIGN KEY (`cert_id` )
    REFERENCES `cert` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `certhash`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `certhash` ;

CREATE  TABLE IF NOT EXISTS `certhash` (
  `cert_id` INT NOT NULL ,
  `sha1_fp` CHAR(40) NOT NULL ,
  `sha224_fp` CHAR(56) NOT NULL ,
  `sha256_fp` CHAR(64) NOT NULL ,
  `sha384_fp` CHAR(96) NOT NULL ,
  `sha512_fp` CHAR(128) NOT NULL ,
  PRIMARY KEY (`cert_id`) ,
  INDEX `fk_certhash_cert1` (`cert_id` ASC) ,
  CONSTRAINT `fk_certhash_cert1`
    FOREIGN KEY (`cert_id` )
    REFERENCES `cert` (`id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
