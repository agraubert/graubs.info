begin;

create database if not exists graubs;

use graubs;

create table if not exists lookup (
  short_code varchar(127) primary key not null,
  destination text not null
);

create table if not exists requests (
  ID bigint unsigned primary key auto_increment,
  time datetime,
  host varchar(255),
  agent_hash char(44),
  method varchar(8),
  ip varchar(40),
  url_path varchar(512),
  endpoint varchar(64),
  length int unsigned,
  response_time int unsigned,
  response_code smallint unsigned
);

create table if not exists csrf (
  ID bigint unsigned auto_increment primary key,
  token char(44) not null,
  form varchar(128) not null,
  ip varchar(40) not null,
  expires datetime not null,
  agent_hash char(44)
);

create table if not exists auth (
  token char(128) primary key
);

create table if not exists files (
  privkey char(108) primary key,
  pubkey char(44) not null,
  filesize bigint,
  sha256 char(64)
);

commit;
