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

create table metastoreentity( 
  id serial,	
  repname varchar(255),
  refcount int,
  content text,
  CONSTRAINT metastoreentityprimkey PRIMARY KEY(id) 		
);


create table evidencestoreentity (
  id serial,
  repname varchar(255),
  iscarvpath boolean default 'false'
  CONSTRAINT evidencestoreeentityprimkey PRIMARY KEY(id)
);

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
  metadataid integer references metastoreentity(id),
  dataid integer references evidencestoreentity(id),
  evidence varchar(1024),
  itemid integer references item(itemid),
  PRIMARY KEY (metadataid)
);


create table suspendedmeta (
  metadataid integer references metastoreentity(id),
  primary key (metadataid)
);
