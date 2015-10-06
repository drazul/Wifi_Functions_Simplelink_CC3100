/*!
    \file
 
    \brief     Library for common wifi functions. Header
*/

#ifndef WIFI_FUNCTIONS_H
#define WIFI_FUNCTIONS_H


#include "simplelink.h"
#include "sl_common.h"
#include <rtems.h>
#include <stdlib.h>

#define SL_STOP_TIMEOUT        0xFFFF

#define IS_PING_DONE(status_variable) GET_STATUS_BIT(status_variable, STATUS_BIT_PING_DONE)

/* Application specific status/error codes */
typedef enum{

    DEVICE_NOT_IN_STATION_MODE = -0x7D0,   
    LAN_CONNECTION_FAILED = -0x7D0, 
    SNTP_SEND_ERROR = DEVICE_NOT_IN_STATION_MODE - 1,
    SNTP_RECV_ERROR = SNTP_SEND_ERROR - 1,
    SNTP_SERVER_RESPONSE_ERROR = SNTP_RECV_ERROR - 1,

	STATUS_BIT_PING_DONE = 31,

    STATUS_CODE_MAX = -0xBB8

} e_AppStatusCodes;

typedef enum {

	NOT_CONNECTED = 0,
	MODE_AP = 1,
	MODE_STATION = 2

} ConnectionMode;

typedef struct {

	_i8 ssid_name[32];
	_i8 password[32];
	_u8 security;
	_u32 channel;
	ConnectionMode mode;

} WifiConnectionState;

int generateAP(char* ssid_name, char* password, _u8 security, int channel);
_i32 connectToAP(char* ssid_name, char* password, _u8 security);
_i32 wlanSetMode(int new_mode);

_i32 setWlanPower(_u8 power);
_i32 setPowerPolicy(_u8 policy);
_i32 sleepWlanDevice(int time);

_i32 configureSimpleLinkToDefaultState();

void pingToConnectedDevice(int interval, int size, int request_timeout, int ping_attemp);
void ping(int interval, int size, int request_timeout, int ping_attemp, _u32 ip);

void waitClients();

void prettyIPv4(_u32 val, _u8* returnIP);
void printPrettyIPv4_u32(_u32 ip);
void printPrettyIPv4_char(_u8* ip);

void printPrettyMAC(_u8 *macAddressVal);

void printWifiParams(WifiConnectionState state);

int disconnectFromAP();

void getOwnMAC(_u8 *macAddressVal);
void setOwnMAC(_u8 *macAddress);

_u32 getOwnIP();
_u32 getHostIP();
_u32 getStationIP();

int scanWifi(int scan_table_size, int channel, int timeout, Sl_WlanNetworkEntry_t *netEntries);
int scanWifiRestoreState(int scan_table_size, int channel, int timeout, Sl_WlanNetworkEntry_t *netEntries);
int getLessSaturatedChannel();

WifiConnectionState getWifiState();
void setWifiState(WifiConnectionState state);

_i16 saveCurrentProfile();
_i16 saveProfile(char* ssid_name, char* password, _u8 security, int channel);
_i16 getProfile(_i16 index, WifiConnectionState *profile);

_i16 restoreProfile(int index);

#endif
