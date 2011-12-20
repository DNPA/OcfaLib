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
						
#ifndef INCLUDED_CASTSTRATEGY_HPP
#define INCLUDED_CASTSTRATEGY_HPP
#include "OcfaObject.hpp"
#include "misc.hpp"
#include"misc/syslog_level.hpp"
#include<string>
#include<map>
#include<vector>
#include<iostream>
#include"ace/SOCK_Stream.h"

//using namespace ocfa::misc;
using namespace ocfa;

class InstanceInfo {
public:
  // sent messages, reply time, socket etc
  InstanceInfo(std::string instname, ACE_SOCK_Stream *s);
  InstanceInfo(const InstanceInfo &i);

  InstanceInfo &operator=(const InstanceInfo &i);
  ACE_SOCK_Stream *getSockStream() const;
  std::string getInstName() const;

protected:
  
  ACE_SOCK_Stream *_s;
  std::string _instname;

};


class CastFacade: public OcfaObject {
public:
  CastFacade();
  ~CastFacade();
  void registerInstance(std::string instance, ACE_SOCK_Stream *s);
  ACE_SOCK_Stream *unregisterInstance(std::string instance);
  bool subscribeChannel(std::string instance, std::string topic);
  bool setMethod(std::string , std::string );
  std::vector<InstanceInfo *> broadcast(std::string sender = "");
  std::vector<InstanceInfo *> anycast(std::string topic);
  std::vector<InstanceInfo *> multicast(std::string topic);
  std::vector<InstanceInfo *> unicast(std::string instname);

protected:
  CastFacade(const CastFacade &);
  CastFacade &operator=(const CastFacade &);
  std::map<std::string, InstanceInfo *> registeredmodules;
  std::map<std::string, std::vector<std::string> * > channels; // <topic, <members>>
};

#endif
