create table cpmount {
  cpmountid serial,
  imagecount integer,
  mountname varchar(255),
  cpmodule varchar(255),
  UNIQUE (mountname),
  primary key (cpmountid )
};

create table cpimage {
  cpimageid serial,
  cpmountid integer references cpmount(cpmountid),
  imageno integer,
  slicecount integer,
  UNIQUE (cpmountid,imageno)
};

create table cpslicefile {
  cpimageid integer references cpmount(cpmountid),
  sliceno integer,
  repname varchar(255),
  UNIQUE (cpimageid,sliceno)
};

create table item (
 itemid serial,
 casename varchar(255),
 evidencesource varchar(255),
 item varchar(255),
 hidden boolean default 'false',
 primary key (itemid),
 UNIQUE (casename, evidencesource, item)	
);

create table metadatainfo (
  metadataid serial,
  xml text,
  repname varchar(255),
  evidence varchar(1024),
  iscarvpath boolean default 'false',
  PRIMARY KEY (metadataid)
);


create table suspendedmeta (
  metadataid integer references evidencemeta(metadataid),
  primary key (metadataid)
);
