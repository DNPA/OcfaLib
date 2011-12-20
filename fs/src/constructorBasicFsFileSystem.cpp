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
						
#include <BasicFsFileSystem.hpp>
#include <misc/Scalar.hpp>
using namespace std;
using namespace ocfa::misc;
extern "C"
{
  ocfa::fs::BasicFsFileSystem * constructor (std::map<std::string,ocfa::misc::Scalar> *attributes)
  {
    bool ro=false;
    if ((*attributes)["ro"].asUTF8() == "true") ro=true;
    string charset=(*attributes)["charset"].asUTF8();
    dev_t dev=(*attributes)["device"].asInt();
    string mountpoint=(*attributes)["mountpoint"].asUTF8();
    string fstype=(*attributes)["fstype"].asUTF8();
    string devicefile=(*attributes)["devicefile"].asUTF8();
    
    ocfa::fs::BasicFsFileSystem * fs =
      new ocfa::fs::BasicFsFileSystem (ro, charset, dev, mountpoint, 
				       fstype, devicefile);
    return fs;
  }
}
