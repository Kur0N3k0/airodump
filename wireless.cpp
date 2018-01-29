#include "wireless.h"

wireless::wireless(pcap_t *handle, char *argv) : handle(handle), interface(argv) { }

uint64_t tick;

void wireless::airodump() {
	int channels[] = { 1, 7, 13, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12 };
	static int chidx;
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res;

	if(tick == 0)
		tick = tickCount();

	if(pcap_datalink(handle) != DLT_IEEE802_11_RADIO){
		printf("no wireless(%d)\n", pcap_datalink(handle));
		exit(-1);
	}

	while(1){   /* Grab a packet */
		res = pcap_next_ex(handle, &header, (const u_char **)&packet);

		if(tickCount() - tick >= 250){
			string cmd = "iwconfig ";
			cmd += interface;
			cmd += " channel ";
			
			stringstream ss;
			ss << channels[chidx];
			cmd += ss.str();
			chidx = (chidx + 1) % (sizeof(channels) / sizeof(int));

			tick = tickCount();

			system(cmd.c_str());
		}

		if(res <= 0)
			continue;

		printf("\033[2J");
		cout << "[Ch. " << channels[chidx] << "]" << endl;

		parse((RadioTap *)packet, header->len);

		// BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
		cout << "BSSID\t\t\tPWR\tBeacons\t#Data\t#/s\tCH\tMB\tENC\tCIPHER\tAUTH\tESSID" << endl;
		string enc, cipher, auth;
		for(map<string, WL_Element *>::iterator iter = beacon.begin(); iter != beacon.end(); iter++){
			WL_Element *element = ((WL_Element *)((*iter).second));
			if(element == NULL)
				continue;
			
			enc = "OPN";
			if(element->enc == ENC_AES)
				enc = "WPA2";

			cipher = "";
			if(element->cipher == CIPHER_CCMP)
				cipher = "CCMP";

			auth = "";
			if(element->auth == AUTH_PSK)
				auth = "PSK";
			
			int i;
			string key = iter->first;
			for(i = 10; i > 0; i -= 2)
				printf("%c%c:", key[i], key[i + 1]);

			printf("%c%c\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t",
					key[i], key[i + 1],
					element->power,
					element->beacons,
					element->data,
					0,
					element->channel,
					(char)element->mb,
					enc.c_str(),
					cipher.c_str(),
					auth.c_str());
			if(element->ssidlen == 0)
				printf("<Length:0>\n");
			else{
				printf("%s\n", element->ssid);
			}
		}
		puts("");
		//BSSID              STATION            PWR   Rate    Lost    Frames  Probe
		cout << "BSSID\t\t\tSTATIONS\t\tPWR\tRate\tLost\tFrames\tProbe" << endl;
		for(map<string, WL_Element *>::iterator iter = stat.begin(); iter != stat.end(); iter++){
			WL_Element *element = ((WL_Element *)((*iter).second));
			if(element == NULL){
				cout << "element is null" << endl;
				continue;
			}
			string key = iter->first;
			string bssid = "", station = "";
			int i;
			for(i = 10; i > 0; i -= 2){
				bssid += key[i];
			    bssid += key[i + 1];
				bssid += ":";
			}
			bssid += key[i];
			bssid += key[i + 1];

			for(i = key.length() - 2; i > 12; i -= 2){
				station += key[i];
				station += key[i + 1];
				station += ":";
			}
			station += key[i];
			station += key[i + 1];

			printf("%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
					bssid.c_str(),
					station.c_str(),
					element->power,
					0,
					0,
					element->data,
					0);
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

	if(type == BEACON_TYPE_DATA){
		Data *data = (Data *)beacon;
		BssID bssid;
		memcpy(&bssid, data->receiver, 6);

		BssID station;
		memcpy(&station, data->transmitter, 6);

		string bkey;
		stringstream ss;
		ss << hex << setfill('0') << setw(12) << bssid;
		bkey = ss.str();

		WL_Element *element = this->beacon[bkey];
		if(element == NULL)
			return;
		element->data++;

		if(subtype == 0)
			return;
		
		stringstream ss2;
		ss2 << hex << setfill('0') << setw(12) << station;
		bkey += ss2.str();
		element = this->stat[bkey];
		if(element == NULL){
			element = new WL_Element;
			this->stat[bkey] = element;
		}
		element->data++;
	}
	else if(type == BEACON_TYPE_MANAGEMENT){
		if(subtype == BEACON_SUBTYPE_FRAME){
			BssID bssid;
			memcpy(&bssid, beacon->bssid, 6);

			string bkey;
			stringstream ss;
			ss << hex << setfill('0') << setw(12) << bssid;
			bkey = ss.str();

			WL_Element *element = this->beacon[bkey];
			if(element == NULL){
				element = new WL_Element;

				if(!memcmp(beacon->receiver, "\xff\xff\xff\xff\xff\xff", 6)){
					this->beacon[bkey] = element;
				}
				else {
					BssID station;
					memcpy(&station, beacon->receiver, 6);
					ss << station;
					bkey = ss.str();
					this->stat[bkey] = element;
				}
			}

			if(IS_RADIOTAP_ANTENA_SIGNAL(radiotap->flags[0])){
				element->power = radiotap->signal2;
			}

			/*for(int i = 0 ; i < 2; i++){
				for(int k = 0; k < 16; k++){
					printf("%02x ", (*((char*)beacon + i * 16 + k)) & 0xff);
				}
				printf("\n");
			}*/
			element->beacons++;
			//getchar();

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
						element->channel = tag->data[0];
						break;
					default:
						break;
				}
				tag = (FrameTag *)((char *)tag + 2 + tag->length);
			}

			element->type = type;
			element->subtype = subtype;
		}
	}
}
