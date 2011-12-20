
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
CONSTRAINT evidencestoreeentityprimkey PRIMARY KEY(id)
);

create table item (

 itemid serial,
 casename varchar(255),
 evidencesource varchar(255),
 item varchar(255),
 hidden boolean default 'false',
 created timestamp default now(),
 primary key (itemid),
 UNIQUE (casename, evidencesource, item)	
);


create table metadatainfo (

metadataid integer references metastoreentity(id),
dataid integer references evidencestoreentity(id),
evidence varchar(1024),
location varchar(4096) default '[being processed]',
itemid integer references item(itemid),
PRIMARY KEY (metadataid)
);

-- create table rowlocation (
--   id serial,
--   metadataid integer references metastoreentity,
--   meta varchar(4096)
-- );

create table rowsha1 (
  id serial,
  metadataid integer references metastoreentity,
  meta varchar(44)
);

create table suspendedmeta (
metadataid integer references metastoreentity(id),
primary key (metadataid)
);
