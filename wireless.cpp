#include "wireless.h"

wireless::wireless(pcap_t *handle) : handle(handle) { }

void wireless::airodump() {
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res;

	while(1){   /* Grab a packet */
		if(pcap_datalink(handle) != DLT_IEEE802_11_RADIO){
			printf("no wireless(%d)\n", pcap_datalink(handle));
			continue;
		}

		res = pcap_next_ex(handle, &header, (const u_char **)&packet);
		if(res <= 0)
			continue;

		parse((RadioTap *)packet, header->len);
		system("clear");

		map<BssID, WL_Element *> probe, beacon;

		for(map<BssID, WL_Element *>::iterator iter = wlinfo.begin(); iter != wlinfo.end(); iter++){
			WL_Element *element = ((WL_Element *)((*iter).second));
			uint16_t subtype = element->subtype;

			if(subtype == BEACON_SUBTYPE_PROBE){
				probe[iter->first] = iter->second;
			}
			else if(subtype == BEACON_SUBTYPE_FRAME){
				beacon[iter->first] = iter->second;
			}
		}

		printf("BSSID\t\t\tPWR\tBeacons\t#Data, #/s\tCH\tMB\tENC\tCIPHER\tAUTH\tESSID\n");
		for(map<BssID, WL_Element *>::iterator iter = beacon.begin(); iter != beacon.end(); iter++){
			WL_Element *element = ((WL_Element *)((*iter).second));
			char *enc = "OPN";
			if(element->enc == ENC_AES)
				enc = "WPA2";

			char *cipher = "";
			if(element->cipher == CIPHER_CCMP)
				cipher = "CCMP";

			char *auth = "";
			if(element->auth == AUTH_PSK)
				auth = "PSK";
			
			uint8_t *ptr= (uint8_t *)&(*iter).first;
			int i;
			for(i = 0; i < 5; i++)
				printf("%02x:", ptr[i] & 0xff);

			printf("%02x\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t",
					ptr[i] & 0xff,
					element->power,
					element->beacons,
					element->data,
					0,
					element->channel,
					(char)element->mb,
					enc,
					cipher,
					auth);
			if(element->ssidlen == 0)
				printf("<Length:0>\n");
			else{
				printf("%s\n", element->ssid);
			}
		}
		puts("");
		for(map<BssID, WL_Element *>::iterator iter = probe.begin(); iter != probe.end(); iter++){
			WL_Element *element = ((WL_Element *)((*iter).second));
			char *enc = "OPN";
			if(element->enc == ENC_AES)
				enc = "WPA2";

			char *cipher = "";
			if(element->cipher == CIPHER_CCMP)
				cipher = "CCMP";

			char *auth = "";
			if(element->auth == AUTH_PSK)
				auth = "PSK";

			uint8_t *ptr= (uint8_t *)&(*iter).first;
			int i;
			for(i = 0; i < 5; i++)
				printf("%02x:", ptr[i] & 0xff);

			printf("%02x\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t",
					ptr[i] & 0xff,
					element->power,
					element->beacons,
					element->data,
					0,
					element->channel,
					0,
					enc,
					cipher,
					auth);
			if(element->ssidlen == 0)
				printf("<Length:0>\n");
			else{
				printf("%s\n", element->ssid);
			}
		}	
	}
}

void wireless::parse(RadioTap *radiotap, uint32_t len) {
	uint32_t curlen = 0;
	
	Beacon *beacon = (Beacon *)((char *)radiotap + radiotap->length);

	curlen += radiotap->length;
	curlen += sizeof(Beacon);

	uint8_t type = BEACON_CONTROL_TYPE(beacon->control);
	uint8_t subtype = BEACON_CONTROL_SUBTYPE(beacon->control);

	BssID bssid;
	memcpy(&bssid, beacon->bssid, 6);

	map<BssID, WL_Element *>::iterator result = wlinfo.find(bssid);
	WL_Element *element = NULL;
	
	if(result == wlinfo.end()){
		element = new WL_Element;
	} else {
		element = result->second;
	}
	

    if(type == BEACON_TYPE_MANAGEMENT && subtype == BEACON_SUBTYPE_FRAME){
		element->beacons++;
	}
	else if(type == BEACON_TYPE_DATA){
		element->data++;
	}


	RadioTapDetail *detail;
	uint32_t size = 0;
	char *dptr = (char *)radiotap->flags + sizeof(radiotap->flags);

	detail = IS_RADIOTAP_TSFT(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_TSFT] : NULL;
	if(detail != NULL){	size += detail->size; }

	detail = IS_RADIOTAP_FLAGS(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_FLAGS] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_RATE(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_RATE] : NULL;
	if(detail != NULL){
		uint8_t rate;
		memcpy(&rate, dptr + size, detail->align);
		if(rate * 5 >= 0x80)
			element->mb = 0xff;
		else element->mb = rate * 5 / 10;
		size += detail->size;
	}
	
	detail = IS_RADIOTAP_CHANNEL(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_CHANNEL] : NULL;
	if(detail != NULL){
		uint16_t freq;
		memcpy(&freq, dptr + size, detail->align);
		element->channel = (freq - 2412) / 5 + 1;

		size += detail->size;
	}
	
	detail = IS_RADIOTAP_FHSS(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_FHSS] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_ANTENA_SIGNAL(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_ANTENA_SIGNAL] : NULL;
	if(detail != NULL){ 
		memcpy(&element->power, dptr + size, detail->align);
		size += detail->size;
	}
	
	detail = IS_RADIOTAP_ANTENA_NOISE(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_ANTENA_NOISE] : NULL;
	if(detail != NULL){ size += detail->size; }
	
	detail = IS_RADIOTAP_LOCK_QUAL(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_LOCK_QUAL] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_TX_ATTENU(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_TX_ATTENU] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_DB_TX_ATTENU(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_DB_TX_ATTENU] : NULL;
	if(detail != NULL){ size += detail->size; }
	
	detail = IS_RADIOTAP_DBM_TX_POWER(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_DBM_TX_POWER] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_ANTENA(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_ANTENA] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_DB_ANTENA_SIGNAL(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_DB_ANTENA_SIGNAL] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_DB_ANTENA_NOISE(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_DB_ANTENA_NOISE] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_RX_FLAGS(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_RX_FLAGS] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_MCS_INFORMATION(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_MCS_INFORMATION] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_AMPDU_STATUS(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_AMPDU_STATUS] : NULL;
	if(detail != NULL){ size += detail->size; }

	detail = IS_RADIOTAP_VHT_INFORMATION(radiotap->flags[0]) == 1 ? &rtDetail[RADIOTAP_VHT_INFORMATION] : NULL;
	if(detail != NULL){ size += detail->size; }

	if(type == BEACON_TYPE_MANAGEMENT){
		if(subtype == BEACON_SUBTYPE_PROBE || subtype == BEACON_SUBTYPE_FRAME){
			ManageFixed *fixed = (ManageFixed *)((char *)beacon + sizeof(Beacon));
			FrameTag *tag = (FrameTag *)((char *)fixed + sizeof(ManageFixed));
			TagRSNInfo *rsn;
			RSNCipher *rsncipher;

			for(uint32_t i = curlen; i <= len; i += tag->length){
				switch(tag->num){
					case TAG_SSID:
						memset(element->ssid, 0, SSID_MAX_LENGTH);
						memcpy(element->ssid, tag->data, tag->length);
						element->ssid[tag->length] = 0;
						element->ssidlen = tag->length;
						break;
					case TAG_RSN_INFORMATION:
						rsn = (TagRSNInfo *)tag->data;
						rsncipher = (RSNCipher *)((char *)rsn + sizeof(TagRSNInfo));
						element->enc = rsn->pairwise.type;
						element->cipher = rsn->pairwise.type;
						element->auth = rsncipher->type;
					case TAG_DS:
						//element->channel = tag->data[0];
						break;
					default:
						break;
				}
				tag = (FrameTag *)((char *)tag + 2 + tag->length);
			}

			element->type = type;
			element->subtype = subtype;
			wlinfo[bssid] = element;
		}
	}
}
