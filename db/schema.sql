begin;

create database if not exists graubsio;

use graubsio;

create table if not exists lookup (
  short_code varchar(127) primary key not null,
  destination text not null
);

create table if not exists requests (
  ID bigint unsigned primary key auto_increment,
  time datetime,
  host varchar(255),
  agent text,
  method varchar(8),
  container enum("internal", "external", "client", "other"),
  ip varchar(40),
  url_path varchar(512),
  endpoint varchar(64),
  length int unsigned,
  response_time int unsigned,
  response_code smallint unsigned
);

commit;
