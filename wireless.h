#ifndef __WIRELESS_H__
#define __WIRELESS_H__

#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>

#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/time.h>

#include "wlstruct.h"

using namespace std;

class wireless {
private:
	pcap_t *handle;
	map< string, WL_Element * > beacon;
	map< string, WL_Element * > stat;
	string interface;

public:
	wireless(pcap_t *handle, char *argv);
	virtual ~wireless() {
		if(handle)
			pcap_close(handle);
	}

	void airodump();

private:
	void parse(RadioTap *radiotap, uint32_t len);
	long long tickCount()
	{
		struct timeval te; 
		gettimeofday(&te, NULL);
		long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
		return milliseconds;
	}
};

#endif
