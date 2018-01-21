#ifndef __WIRELESS_H__
#define __WIRELESS_H__

#include <map>

#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/errno.h>

#include "wlstruct.h"

using namespace std;

class wireless {
private:
	pcap_t *handle;
	map< BssID, WL_Element * > wlinfo;

public:
	wireless(pcap_t *handle);
	virtual ~wireless() {
		if(handle)
			pcap_close(handle);
	}

	void airodump();

private:
	void parse(RadioTap *radiotap, uint32_t len);
};

#endif
