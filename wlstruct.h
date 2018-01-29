#ifndef __WLSTRUCT_H__
#define __WLSTRUCT_H__

#include <stdint.h>

using namespace std;

typedef uint64_t BssID;

#define SSID_MAX_LENGTH 0xff
typedef struct WL_ELEMENT {
	char power;
	uint32_t channel;
	uint32_t ssidlen;
	uint8_t ssid[SSID_MAX_LENGTH];
	uint8_t station[SSID_MAX_LENGTH];
	uint32_t beacons;
	uint8_t mb;
	uint8_t enc;
	uint8_t cipher;
	uint8_t auth;
	uint32_t data;
	uint16_t type;
	uint16_t subtype;
} WL_Element;

#define BEACON_CONTROL_VERSION(x)	((x) & 0x03)
#define BEACON_CONTROL_TYPE(x)		(((x) & 0x0c) >> 0x02)
#define BEACON_CONTROL_SUBTYPE(x)	(((x) & 0xf0) >> 0x04)

#define BEACON_TYPE_MANAGEMENT			0x00
#define BEACON_SUBTYPE_PROBE			0x05
#define BEACON_SUBTYPE_FRAME			0x08

#define BEACON_TYPE_DATA				0x02

typedef struct BEACON {
	uint8_t control;
	uint8_t flags;
	uint16_t duration;
	uint8_t receiver[6];
	uint8_t transmitter[6];
	uint8_t bssid[6];
	uint16_t frse;
} Beacon;

typedef struct DATA {
	uint8_t control;
	uint8_t flags;
	uint16_t duration;
	uint8_t receiver[6];
	uint8_t transmitter[6];
	uint8_t source[6];
} Data;

#define RADIOTAP_TSFT					0x00
#define RADIOTAP_FLAGS				    0x01
#define RADIOTAP_RATE			        0x02
#define RADIOTAP_CHANNEL	            0x03
#define RADIOTAP_FHSS	                0x04
#define RADIOTAP_ANTENA_SIGNAL		    0x05
#define RADIOTAP_ANTENA_NOISE			0x06
#define RADIOTAP_LOCK_QUAL				0x07
#define RADIOTAP_TX_ATTENU				0x08
#define RADIOTAP_DB_TX_ATTENU			0x09
#define RADIOTAP_DBM_TX_POWER			0x0a
#define RADIOTAP_ANTENA					0x0b
#define RADIOTAP_DB_ANTENA_SIGNAL		0x0c
#define RADIOTAP_DB_ANTENA_NOISE		0x0d
#define RADIOTAP_RX_FLAGS				0x0e
#define RADIOTAP_CHANNEL_PLUS			0x0f
#define RADIOTAP_MCS_INFORMATION		0x10
#define RADIOTAP_AMPDU_STATUS			0x11
#define RADIOTAP_VHT_INFORMATION		0x12
#define RADIOTAP_RESERVED				0x13
#define RADIOTAP_NS_NEXT				0x14
#define RADIOTAP_VENDOR_NS_NEXT			0x15
#define RADIOTAP_EXT					0x16

typedef struct RADIOTAP_DETAIL {
	uint8_t opt;
	uint32_t align;
	uint32_t size;
	uint8_t use;
} RadioTapDetail;

#ifndef __RTDETAIL__
RadioTapDetail rtDetail[] = {
	{
		.opt = RADIOTAP_TSFT,
		.align = 8,
		.size = 8
	},
	{
		.opt = RADIOTAP_FLAGS,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_RATE,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_CHANNEL,
		.align = 2,
		.size = 4
	},
	{
		.opt = RADIOTAP_FHSS,
		.align = 2,
		.size = 2
	},
	{
		.opt = RADIOTAP_ANTENA_SIGNAL,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_ANTENA_NOISE,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_LOCK_QUAL,
		.align = 2,
		.size = 2
	},
	{
		.opt = RADIOTAP_TX_ATTENU,
		.align = 2,
		.size = 2
	},
	{
		.opt = RADIOTAP_DB_TX_ATTENU,
		.align = 2,
		.size = 2
	},
	{
		.opt = RADIOTAP_DBM_TX_POWER,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_ANTENA,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_DB_ANTENA_SIGNAL,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_DB_ANTENA_NOISE,
		.align = 1,
		.size = 1
	},
	{
		.opt = RADIOTAP_RX_FLAGS,
		.align = 2,
		.size = 2
	},
	{
		.opt = RADIOTAP_CHANNEL_PLUS,
		.align = 0xffffffff,
		.size = 0xffffffff
	},
	{
		.opt = RADIOTAP_MCS_INFORMATION,
		.align = 1,
		.size = 3
	},
	{
		.opt = RADIOTAP_AMPDU_STATUS,
		.align = 4,
		.size = 8
	},
	{
		.opt = RADIOTAP_VHT_INFORMATION,
		.align = 2,
		.size = 12
	}
};
#endif

#define IS_RADIOTAP_TSFT(x)					(((x) >> 0x00) & 0x01)
#define IS_RADIOTAP_FLAGS(x)				(((x) >> 0x01) & 0x01)
#define IS_RADIOTAP_RATE(x)					(((x) >> 0x02) & 0x01)
#define IS_RADIOTAP_CHANNEL(x)				(((x) >> 0x03) & 0x01)
#define IS_RADIOTAP_FHSS(x)					(((x) >> 0x04) & 0x01)
#define IS_RADIOTAP_ANTENA_SIGNAL(x)		(((x) >> 0x05) & 0x01)
#define IS_RADIOTAP_ANTENA_NOISE(x)			(((x) >> 0x06) & 0x01)
#define IS_RADIOTAP_LOCK_QUAL(x)			(((x) >> 0x07) & 0x01)
#define IS_RADIOTAP_TX_ATTENU(x)			(((x) >> 0x08) & 0x01)
#define IS_RADIOTAP_DB_TX_ATTENU(x)			(((x) >> 0x09) & 0x01)
#define IS_RADIOTAP_DBM_TX_POWER(x)			(((x) >> 0x0a) & 0x01)
#define IS_RADIOTAP_ANTENA(x)				(((x) >> 0x0b) & 0x01)
#define IS_RADIOTAP_DB_ANTENA_SIGNAL(x)		(((x) >> 0x0c) & 0x01)
#define IS_RADIOTAP_DB_ANTENA_NOISE(x)		(((x) >> 0x0d) & 0x01)
#define IS_RADIOTAP_RX_FLAGS(x)				(((x) >> 0x0e) & 0x01)
#define IS_RADIOTAP_CHANNEL_PLUS(x)			(((x) >> 0x12) & 0x01)
#define IS_RADIOTAP_MCS_INFORMATION(x)		(((x) >> 0x13) & 0x01)
#define IS_RADIOTAP_AMPDU_STATUS(x)			(((x) >> 0x14) & 0x01)
#define IS_RADIOTAP_VHT_INFORMATION(x)		(((x) >> 0x15) & 0x01)
#define IS_RADIOTAP_RESERVED(x)				(((x) >> 0x16) & 0xfffffff)
#define IS_RADIOTAP_NS_NEXT(x)				(((x) >> 0x1d) & 0x01)
#define IS_RADIOTAP_VENDOR_NS_NEXT(x)		(((x) >> 0x1e) & 0x01)
#define IS_RADIOTAP_EXT(x)					(((x) >> 0x1f) & 0x01)

typedef struct RadioTap {
	uint8_t revision;
	uint8_t pad;
	uint16_t length;
	uint32_t flags[2];
	uint64_t macstamp;
	uint8_t flags2;
	uint8_t drate;
	uint16_t freq;
	uint16_t cflags;
	uint16_t signal;
	uint16_t rxflags;
	uint8_t signal2;
} RadioTap;

enum radiotap_flags {
	RADIOTAP_F_CFP = 0x01,
	RADIOTAP_F_SHORTPRE = 0x02,
	RADIOTAP_F_WEP = 0x04,
	RADIOTAP_F_FRAG = 0x08,
	RADIOTAP_F_FCS = 0x10,
	RADIOTAP_F_DATAPAD = 0x20,
	RADIOTAP_F_BADFCS = 0x40,
};

/* for RADIOTAP_CHANNEL */
enum radiotap_channel_flags {
	CHAN_CCK = 0x0020,
	CHAN_OFDM = 0x0040,
	CHAN_2GHZ = 0x0080,
	CHAN_5GHZ = 0x0100,
	CHAN_DYN = 0x0400,
	CHAN_HALF = 0x4000,
	CHAN_QUARTER = 0x8000,
};

/* for RADIOTAP_RX_FLAGS */
enum radiotap_rx_flags {
	RADIOTAP_F_RX_BADPLCP = 0x0002,
};

/* for RADIOTAP_TX_FLAGS */
enum radiotap_tx_flags {
	RADIOTAP_F_TX_FAIL = 0x0001,
	RADIOTAP_F_TX_CTS = 0x0002,
	RADIOTAP_F_TX_RTS = 0x0004,
	RADIOTAP_F_TX_NOACK = 0x0008,
};

/* for RADIOTAP_MCS "have" flags */
enum radiotap_mcs_have {
	RADIOTAP_MCS_HAVE_BW = 0x01,
	RADIOTAP_MCS_HAVE_MCS = 0x02,
	RADIOTAP_MCS_HAVE_GI = 0x04,
	RADIOTAP_MCS_HAVE_FMT = 0x08,
	RADIOTAP_MCS_HAVE_FEC = 0x10,
	RADIOTAP_MCS_HAVE_STBC = 0x20,
};

enum radiotap_mcs_flags {
	RADIOTAP_MCS_BW_MASK = 0x03,
	RADIOTAP_MCS_BW_20 = 0,
	RADIOTAP_MCS_BW_40 = 1,
	RADIOTAP_MCS_BW_20L = 2,
	RADIOTAP_MCS_BW_20U = 3,

	RADIOTAP_MCS_SGI = 0x04,
	RADIOTAP_MCS_FMT_GF = 0x08,
	RADIOTAP_MCS_FEC_LDPC = 0x10,
	RADIOTAP_MCS_STBC_MASK = 0x60,
	RADIOTAP_MCS_STBC_1 = 1,
	RADIOTAP_MCS_STBC_2 = 2,
	RADIOTAP_MCS_STBC_3 = 3,
	RADIOTAP_MCS_STBC_SHIFT = 5,
};

/* for RADIOTAP_AMPDU_STATUS */
enum radiotap_ampdu_flags {
	RADIOTAP_AMPDU_REPORT_ZEROLEN = 0x0001,
	RADIOTAP_AMPDU_IS_ZEROLEN = 0x0002,
	RADIOTAP_AMPDU_LAST_KNOWN = 0x0004,
	RADIOTAP_AMPDU_IS_LAST = 0x0008,
	RADIOTAP_AMPDU_DELIM_CRC_ERR = 0x0010,
	RADIOTAP_AMPDU_DELIM_CRC_KNOWN = 0x0020,
};

/* for RADIOTAP_VHT */
enum radiotap_vht_known {
	RADIOTAP_VHT_KNOWN_STBC = 0x0001,
	RADIOTAP_VHT_KNOWN_TXOP_PS_NA = 0x0002,
	RADIOTAP_VHT_KNOWN_GI = 0x0004,
	RADIOTAP_VHT_KNOWN_SGI_NSYM_DIS = 0x0008,
	RADIOTAP_VHT_KNOWN_LDPC_EXTRA_OFDM_SYM = 0x0010,
	RADIOTAP_VHT_KNOWN_BEAMFORMED = 0x0020,
	RADIOTAP_VHT_KNOWN_BANDWIDTH = 0x0040,
	RADIOTAP_VHT_KNOWN_GROUP_ID = 0x0080,
	RADIOTAP_VHT_KNOWN_PARTIAL_AID = 0x0100,
};

enum radiotap_vht_flags {
	RADIOTAP_VHT_FLAG_STBC = 0x01,
	RADIOTAP_VHT_FLAG_TXOP_PS_NA = 0x02,
	RADIOTAP_VHT_FLAG_SGI = 0x04,
	RADIOTAP_VHT_FLAG_SGI_NSYM_M10_9 = 0x08,
	RADIOTAP_VHT_FLAG_LDPC_EXTRA_OFDM_SYM = 0x10,
	RADIOTAP_VHT_FLAG_BEAMFORMED = 0x20,
};

enum radiotap_vht_coding {
	RADIOTAP_CODING_LDPC_USER0 = 0x01,
	RADIOTAP_CODING_LDPC_USER1 = 0x02,
	RADIOTAP_CODING_LDPC_USER2 = 0x04,
	RADIOTAP_CODING_LDPC_USER3 = 0x08,
};

/* for RADIOTAP_TIMESTAMP */
enum radiotap_timestamp_unit_spos {
	RADIOTAP_TIMESTAMP_UNIT_MASK = 0x000F,
	RADIOTAP_TIMESTAMP_UNIT_MS = 0x0000,
	RADIOTAP_TIMESTAMP_UNIT_US = 0x0001,
	RADIOTAP_TIMESTAMP_UNIT_NS = 0x0003,
	RADIOTAP_TIMESTAMP_SPOS_MASK = 0x00F0,
	RADIOTAP_TIMESTAMP_SPOS_BEGIN_MDPU = 0x0000,
	RADIOTAP_TIMESTAMP_SPOS_PLCP_SIG_ACQ = 0x0010,
	RADIOTAP_TIMESTAMP_SPOS_EO_PPDU = 0x0020,
	RADIOTAP_TIMESTAMP_SPOS_EO_MPDU = 0x0030,
	RADIOTAP_TIMESTAMP_SPOS_UNKNOWN = 0x00F0,
};

enum radiotap_timestamp_flags {
	RADIOTAP_TIMESTAMP_FLAG_64BIT = 0x00,
	RADIOTAP_TIMESTAMP_FLAG_32BIT = 0x01,
	RADIOTAP_TIMESTAMP_FLAG_ACCURACY = 0x02,
};



#define TAG_SSID					0x00
#define TAG_SUPPORTED_RATE			0x01
#define TAG_DS						0x03
#define TAG_TRAFFIC_INDICATION_MAP	0x05
#define TAG_ERP_INFORMATION			0x2a
#define TAG_HT_CAPABILITY			0x2d
#define TAG_RSN_INFORMATION         0x30
#define TAG_EXTENDED_SUPPORTED_RATE	0x32
#define TAG_HT_INFORMATION			0x3d

#pragma pack(push, 1)
typedef struct ManageFixed {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t capainfo;
} ManageFixed;
#pragma pack(pop)

#define TAG_MAX_LENGTH 0xff

#pragma pack(push, 1)
typedef struct FrameTag {
	uint8_t num;
	uint8_t length;
	char data[TAG_MAX_LENGTH];
} FrameTag;
#pragma pack(pop)

#define ENC_AES			0x04
#define CIPHER_CCMP		0x04
#define AUTH_PSK			0x02

typedef struct RSNCipher {
	uint8_t oui[3];
	uint8_t type;
} RSNCipher;

#pragma pack(push, 1)
typedef struct TagRSNInfo {
	uint16_t version;
	
	RSNCipher group;

	uint16_t pw_count;
	RSNCipher pairwise;

	uint16_t akm_count;
} TagRSAInfo;
#pragma pack(pop)

#endif
