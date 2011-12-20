//The Open Computer Forensics Library
//Copyright (C) KLPD 2003..2006  <ocfa@dnpa.nl>
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
						
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sstream>
#include <errno.h>
#include "string.h"
#include <boost/lexical_cast.hpp>
#include "ConcreteStoreEntity.hpp"
#include "store/AbstractRepository.hpp"
#include "DigestPairFactory.hpp"

namespace ocfa {
  namespace store {
    using namespace std;
    
    gid_t ConcreteStoreEntity::OcfaGroup = static_cast<gid_t>(-1); // the repository can update this value with the 'real' ocfagroupid
    const int max_buffer_length = 1 * 1024 * 1024;

    std::string dereferenceSymLinks(std::string path) {
        char dereferenced[PATH_MAX+1];
        ssize_t lastderef=1;
        std::string rval=path;
        while (lastderef != -1) {
           lastderef=readlink(path.c_str(), dereferenced, PATH_MAX+1);
           if (lastderef != -1) {
              std::string newrval=std::string(dereferenced,lastderef);
              if (newrval == rval) {
                 return rval;
              }
              rval=newrval;
           }
        }
        return rval;
    }

    bool isRegularFile(string f){
      struct stat buf;
      if (stat(f.c_str(), &buf) == 0) {
        if (S_ISLNK(buf.st_mode) != 0) {
            ocfa::misc::OcfaLogger::Instance()->syslog(LOG_WARNING,"isRegularFile:") << "stat does not recursively dereference symbolic links,assuming isRegularFile=true  for " << f << std::endl;
            return true;
        }
	return (S_ISREG(buf.st_mode) != 0);
      }
      else
	return false;
    }
    
    //JCW:CODEREVIEW:Moet hier invulling komen?
    // JBS yes! will do as soon as things start working again.
    bool compareFiles(const string &, const string &){
      
      return true;
    }
    

    ConcreteStoreEntity::ConcreteStoreEntity(string root): 
	    OcfaObject("ConcreteStoreEntity", "store"), 
	    d_root(root),
	    d_digest(0), 
	    d_fd(-1), 
	    d_opened(false), 
	    d_handle(""), 
	    d_storename(""),
            d_needsTailwrite(false),
            d_writecount(0),
            d_sparsecount(0) 
    {
	    ocfaLog(LOG_INFO,"StoreEntity constructor");
	    //d_repostype = ocfa::misc::OcfaConfig::Instance()->getValue("repositorytype");
    }

    ConcreteStoreEntity::~ConcreteStoreEntity(){
      if (d_digest) delete d_digest;
    }

    void ConcreteStoreEntity::initDigest(){
      if (!d_digest) 
      ocfa::DigestPairFactory::createDigestPair(&d_digest);
      ocfaLog(LOG_DEBUG, "Digestpair created.");
      if (!d_digest)
	throw OcfaException("Could not create digestpair", this);
    }

    void ConcreteStoreEntity::openStream(off_t datasize){
      // get a filedescriptor for temp file 
      if (d_fd >= 0){
	throw OcfaException("ConcreteStoreEntity allready open", this);
      }
      ocfaLog(LOG_INFO, "Stream opened");
      createFile();
      ocfaLog(LOG_INFO, "Temporary file created");
      if (d_fd < 0){
	throw OcfaException("Could not retrieve filedescriptor", this);
      }
      initDigest();
      d_opened = true;
    }

    void ConcreteStoreEntity::writeStream(const char *buf, unsigned int len){
      if (d_fd < 0){
	throw OcfaException("ConcreteStoreEntity not open for writing",this);
      }
      unsigned int index=0; 
      bool sparse=true;
      for (index=0;((index<len) && sparse);index++){
         if (buf[index]) sparse=false;
      }
      d_writecount++;
      if (sparse == false) {
         ssize_t written=write(d_fd, buf, len);
         if ((unsigned int)written != len) {
            if (written != -1) {
              getLogStream(LOG_CRIT) << "Trying to write " << len << "to ConcreteStoreEntity, but only " << written << " bytes written." << std::endl;
              throw OcfaException("Problem writing to ConcreteStoreEntity, write action truncated, disk full ?",this);
            }
            getLogStream(LOG_CRIT) << "Problem writing to repository, write returned error, errno=" << errno << std::endl;
            switch (errno) {
	      case EFAULT: throw OcfaException("Problem writing to ConcreteStoreEntity, EFAULT, bad buffer given to writeStream",this);
	      case EFBIG: throw OcfaException("Problem writing to ConcreteStoreEntity, EFBIG, consult your unix system administrator about the  used filesystem for the repository.",this);
	      case EINTR: throw OcfaException("Problem writing to ConcreteStoreEntity, EINTR, interupted by signal",this);
	      case EIO: throw OcfaException("Problem writing to ConcreteStoreEntity, EIO, Disk hardware problem",this);
	      case ENOSPC: throw OcfaException("Problem writing to ConcreteStoreEntity, ENOSPC, DISK FULL !!!",this);
	      default: throw OcfaException("Problem writing to ConcreteStoreEntity, consult system log for details.",this);
            } 
         }
         d_digest->update(buf, len);
         d_needsTailwrite=false;  //No sparse data at the end of the file.
      } else {
         d_sparsecount++;
         lseek64(d_fd,len,SEEK_CUR); //Simply move the file handle forward len bytes.
         d_digest->update(buf, len);
         d_needsTailwrite=true; //mark that there is sparse data at the end of the file. 
      }
    }

    void ConcreteStoreEntity::closeStream(){
      if (d_fd < 0){
	throw OcfaException("ConcreteStoreEntity not open for writing", this);
      }
      getLogStream(LOG_NOTICE) << "Closing entity, written " << d_writecount << " times with a sparsecount of " << d_sparsecount << std::endl; 
      if (d_needsTailwrite) { //If the last data in the file was assumed sparse and not written yet.
          lseek64(d_fd,-1,SEEK_CUR); //Move the file handle back one byte.
          char nullbyte=0;
          ssize_t written=write(d_fd,&nullbyte,1); //And write a single character to the file.
          if (written != 1) {
            if (written != -1) {
              getLogStream(LOG_CRIT) << "Trying to write 1 byte to ConcreteStoreEntity, but only " << written << " bytes written." << std::endl;
              throw OcfaException("Problem writing to ConcreteStoreEntity, write action truncated, disk full ?",this);
            }
            getLogStream(LOG_CRIT) << "Problem writing to repository, write returned error, errno=" << errno << std::endl;
            switch (errno) {
	      case EFAULT: throw OcfaException("Problem writing to ConcreteStoreEntity, EFAULT, bad buffer given to writeStream",this);
	      case EFBIG: throw OcfaException("Problem writing to ConcreteStoreEntity, EFBIG, consult your unix system administrator about the  used filesystem for the repository.",this);
	      case EINTR: throw OcfaException("Problem writing to ConcreteStoreEntity, EINTR, interupted by signal",this);
	      case EIO: throw OcfaException("Problem writing to ConcreteStoreEntity, EIO, Disk hardware problem",this);
	      case ENOSPC: throw OcfaException("Problem writing to ConcreteStoreEntity, ENOSPC, DISK FULL !!!",this);
	      default: throw OcfaException("Problem writing to ConcreteStoreEntity, consult system log for details.",this);
            } 
          }
      }
      d_digest->final();
      ::close(d_fd);
      d_fd = -1;
      d_opened = false;
      renameToSHA1();
    }


    // split SHA1 into dirs and filename
    // 
    // The path returned is relative to d_root
    string ConcreteStoreEntity::splitSHA1(const string &SHA1, vector<string> &dirs, string &filename){

      if (SHA1.size() != 40){
	throw OcfaException("Not a valid SHA1 hash", this);
      }

      // parts is used as a template how we want the string to be split up;
      // in this case 2 chars / 2 chars / <rest of string (denoted by -1)>
      int parts[] = {2,2,-1};
  
      string path = "/";
      // first the dirs ...
      unsigned int i,j;
      for (i = 0, j = 0; parts[i] > 0; i++){
	dirs.push_back( SHA1.substr(j,parts[i]));
        path += dirs[i]+"/";
	j += parts[i];
      }
      // .. and what's left
  
      filename = SHA1.substr(j,SHA1.size()-j);
      return path + filename;
    }

    string ConcreteStoreEntity::createPath(const vector<string> &dirs) const {

      string path = d_root + "/";
      for (unsigned int i = 0; i < dirs.size(); i++){
	path += dirs[i] + "/";
	mkdir(path.c_str(), 0755);
      }
      return path;  
    }


    // Note: returns path including repository root
    string ConcreteStoreEntity::renameToSHA1() {
      // try to create path like /AB/CDE/FGH/<rest of sha1>
  
      if (!d_digest)
	calcDigest(d_storename);

      ocfaLog(LOG_INFO,"Trying to rename " + d_storename);
      
      string SHA1 = d_digest->getSHA1();

      
      vector<string>   dirs;
      string filename;
      string partnewname = splitSHA1(SHA1, dirs, filename);
      string fullnewname = d_root + "/" + partnewname;  
      createPath(dirs);
  
      string oldName = d_root + "/" + d_storename;

      if (isRegularFile(fullnewname)){
	// it looks like the file allready existed. 
	// Compare the contents
	if (store::compareFiles(fullnewname, d_storename)){
	  // makes sense since the hashes are the same
	  // nothing to be done, except unlink the original
	  ocfaLog(LOG_INFO, string("Trying to unlink ") + oldName);
	
	  if (unlink(oldName.c_str()) != 0){

	    ocfaLog(LOG_ERR, string("cannot unlink ") + oldName);
	  }

	} else {
	  // hmm, same hash but different contents. We should note this
	  throw OcfaException("Different files with same SHA1 hash encountered", this);
	}
      }
      else {
	// the new file did not exist, so we simple rename the temporary file.
	ocfaLog(LOG_DEBUG, string("trying to rename ") + oldName + " to " + fullnewname); 
	if (rename(oldName.c_str(), fullnewname.c_str()) == 0){
	  
	} else {
	  ocfaLog(LOG_ERR, "Rename from " + oldName + " to " + fullnewname + " failed. Trying copy");
	  //throw OcfaException("Cannot rename "  + oldName + "to "
	  //		      + fullnewname);
	  
	  // a quick fix to copy a file instead of renaming when repository is over more partitions
	  ifstream oldfile(oldName.c_str(), ios::binary);
	  ofstream newfile(fullnewname.c_str(), ios::binary);
          // check if streams are open
          if(oldfile.is_open() && newfile.is_open()) {
	     newfile << oldfile.rdbuf();
	     newfile.close();
	     oldfile.close();
          } else {
             getLogStream(LOG_ERR) << "Copy from " << oldName << " to " << fullnewname << " failed. Out of options. Please fix Hardware";
             throw OcfaException("Cannot copy "  + oldName + "to "  + fullnewname);
          }
          if (unlink(oldName.c_str()) != 0){
             ocfaLog(LOG_ERR, string("cannot unlink after copying: ") + oldName);
          }
	  
	}   
      }
      d_storename =  partnewname;
      return fullnewname; 
    
    }

    void ConcreteStoreEntity::setHandle(ocfa::misc::OcfaHandle handle){
       d_handle = handle;
    }

    // calculate digest of file.
    bool ConcreteStoreEntity::calcDigest(string target){
      int fd = open(target.c_str(),O_RDONLY); 
      if (fd < 0){
	throw OcfaException("Could not open " + target, this);
      } 
      int len = 0;
      char buf[2048];
      initDigest();
      off_t offset=0;
      while ((len = ::read(fd, buf, 2048))){
        if (len == -1) {
           throw OcfaException("Error reading from file " + target + " at offset " + boost::lexical_cast< std::string > (offset) , this);
        } else {
           offset+=len;
	   d_digest->update(buf, len);
        }
      }
      d_digest->final();
      close(fd);
      fd = -1;
      return true;
    }


    // set a link to target
    string ConcreteStoreEntity::setLink(const string &target, linktype lt,ocfa::misc::DigestPair **dph){
      if (dph) {
        ocfa::misc::DigestPair *dp=*dph;
        if (dp) {
          ocfaLog(LOG_NOTICE, string("Supplied digest for setLink ignored, functionality not yet implemented in store lib\n"));  
          delete dp;
          dp=NULL;
        }
      }
      std::string realtarget=target;
      if (lt==soft) {
         realtarget=dereferenceSymLinks(target);
      }
      // calc the digest of the target 
      calcDigest(realtarget);
      ocfaLog(LOG_DEBUG, string("creating link for ") + realtarget); 
      // from SHA1, create a filepath and filename
      string SHA1 = d_digest->getSHA1();
      vector<string> dirs;
      string filename = "";
      string tmpstorename = splitSHA1(SHA1, dirs, filename);  
      createPath(dirs);
      string path = d_root + "/";
      for (unsigned int i = 0; i < dirs.size(); i++){
	path += dirs[i] + "/";
      }
      path += filename;
      int linkval;
      if (isRegularFile(path)){ // check for existence of path, since it allready could be in the repository
	// it exists. Check whether contents of target and path are the same
	if (!compareFiles(realtarget, path)){

	  throw OcfaException(string("different files with same SHA1") + realtarget
			      + " " + path, this);
	  // FIXME:not the same contents but the same hash -> throw exception
	  // JBS: Or fix it so that a new name is invented.
	}
      }
      else {
	if (lt == hard){
	  
	  ocfaLog(LOG_DEBUG, "creating hard link");
	  linkval = link(realtarget.c_str(), path.c_str());
	} else {
	  
	  ocfaLog(LOG_DEBUG, "creating soft link");
	  linkval = symlink(realtarget.c_str(), path.c_str());
	}
	if (linkval != 0) {
          std::string err="undefined";
          switch(errno){ 
             case EACCES: err="EACCES";break;
             case EEXIST: err="EEXIST";break;
             case EFAULT: err="EFAULT";break;
             case EIO:    err="EIO";break;
             case ELOOP:  err="ELOOP";break;
             case EMLINK: err="EMLINK";break;
             case ENAMETOOLONG: err="ENAMETOOLONG";break;
             case ENOENT: err="ENOENT";break;
             case ENOMEM : err="ENOMEM";break;
             case ENOSPC: err="ENOSPC";break;
             case ENOTDIR: err="ENOTDIR";break;
             case EPERM: err="EPERM";break;
             case EROFS: err="EROFS";break;
             case EXDEV: err="EXDEV";break;
             default: err="unexpected value";
          }
          getLogStream(LOG_CRIT) << "Problem with creating link, errno=" << errno <<  "(" << err << ")" <<std::endl;
          getLogStream(LOG_CRIT) << "  * path=" << path << std::endl;
          getLogStream(LOG_CRIT) << "  * target=" << realtarget << std::endl;
          if (isRegularFile(path)) {
              getLogStream(LOG_CRIT) << "Hmm, " << path << " does exist now afterall, racecondition" << std::endl;
              if (!compareFiles(realtarget, path)){
                  throw OcfaException(string("different files with same SHA1") + realtarget
                               + " " + path, this);
              }
          } else {
              getLogStream(LOG_CRIT) << path << " does exist after second check, not just a simple racecondition" << std::endl;
              if (ocfa::misc::OcfaConfig::Instance()->getValue("ignoresymlinkerror") != "true") {
               throw OcfaException(string("Cannot create a symlink to ") + path, this);
              }
          }
        }

	  
	
      }
      d_storename =  tmpstorename;
      AbstractRepository::Instance()->setHandle(*this); //JBS WARNING CHECKTHIS
      return d_root + "/" + d_storename;
    }
    
    // set hardlink to target based on SHA1 of target
    // if target needs to be 'moved into repository', the user should delete the target himself
    // returns name of link
    string ConcreteStoreEntity::setHardLink(const string &target,ocfa::misc::DigestPair **dp){
	return setLink(target, hard,dp);
      }
      
      // set softlink to target based on SHA1 of target
      // returns name of softlink
      string ConcreteStoreEntity::setSoftLink(const string &target,ocfa::misc::DigestPair **dp){
	return setLink(target, soft,dp);
    }

    /**
     * 
     * returns the path relative to the repository.
     *
     */
    Filename ConcreteStoreEntity::getStoreName() const {

      return d_storename;
    }

    /**
     * returns the absolute filepath for this file.
     *
     */
    Filename ConcreteStoreEntity::getAsFilePath() const {

      return d_root + "/" + getStoreName();
    }

    // open file descriptor for writing a new file
    bool ConcreteStoreEntity::createFile(){
      if (d_fd != -1)
	throw OcfaException("File descriptor still open");   
      string tmpstr(d_root + "/" + "metase_XXXXXX");
      char *stemp = new char[tmpstr.length() + 1];
      strcpy(stemp, tmpstr.c_str());
      
      d_fd = mkstemp(stemp);
      // Set the filepermissions
      setPermissions(d_fd);

      // set the store name to the file minus d_root.
      d_storename = string(stemp).substr(d_root.length() + 1);
      delete []stemp;

      if (d_fd != -1) 
	return true;
      else 
	throw OcfaException ("Create file failed"); 
      return true;
    }

    misc::OcfaHandle ConcreteStoreEntity::getHandle(){
      return d_handle;
    }


    /**
     * 
     * Size has been changed from the original so that lstat is used instead of fsstat. This
     * is done because of the new fsstat and because I'd rather not want a dependency between fsstat and
     * the store.
     *
     */
    off_t ConcreteStoreEntity::size() const {
       
      if (getStoreName() == ""){
	
	ocfaLog(LOG_ERR, "Exception: trying to retrieve a size without a filepath");
	throw OcfaException("No size given", this);
      }
      else {

	struct stat filestat;
	string storePath = d_root + "/" + getStoreName();
	if (stat(storePath.c_str(), &filestat) < 0){

	  throw OcfaException("cannot stat " + storePath);
	}

      	off_t mysize=filestat.st_size;

        getLogStream(LOG_DEBUG) << "size() computed: " << mysize << endl;

	return mysize;
      }
    }

    /**
     * reads a maximum of count bytes into buffer. 
     * @param buffer the buffer into which the bytes should be read. It should be at
     * least count bytes large.
     * @param count the maximum amount of bytes to be read into the buffer.
     */
    size_t ConcreteStoreEntity::read(void *buffer, size_t count) {

      if (getStoreName() == ""){

	throw OcfaException("No storename wasexists for this storeentity", this);
      }

      if (d_fd == -1) {		// file is closed, open it
	d_fd = open((d_root + "/" + getStoreName()).c_str(), O_RDONLY);
	if (d_fd <= 0) {

	  ocfaLog(LOG_ERR, "ConcreteStoreEntity::read(buffer,count) Error opening file: " + d_root + "/" + getStoreName());
	  return 0;
	}
      }
      int rval =::read(d_fd, buffer, count);
      //write(0, buffer, count);
      if (rval == 0) {		// EOF, close fd and reset
	close(d_fd);
	d_fd = -1;
      }
   
      return rval;
    }	  

    /**
     * returns an input stream from the storeentity.
     * Difference with 0.3
     * 1. Everytime a new stream is created (wasn't sure if needed).
     *
     */
    std::istream *ConcreteStoreEntity::getAsIstream()  {

      if (getStoreName() == ""){

	ocfaLog(LOG_ERR, "No storefilenamd exists in getAsIstream");
	throw OcfaException("no file name exists for this file");
      }
      ifstream *ifs = new ifstream((d_root + "/" + getStoreName()).c_str());
      if(ifs->is_open()) {
         return ifs;

      } else {
         ocfaLog(LOG_ERR, "is_open returns false getAsIstream");
         return 0;
      }
      //return new ifstream((d_root + "/" + getStoreName()).c_str());
    }


    /**
     * sets the digestpair of a storeentity.
     *
     */
    void ConcreteStoreEntity::setDigestPair(DigestPair **inDigestPair){

      d_digest = *inDigestPair;
    }
  }
}



