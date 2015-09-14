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

#define MAX_BUF_SIZE    48

#define TIME2013        3565987200       /* 43 years + 11 days of leap years */
#define YEAR2013        2013

#define SEC_IN_MIN      60
#define SEC_IN_HOUR     3600
#define SEC_IN_DAY      86400

#define GMT_TIME_ZONE_HR    0
#define GMT_TIME_ZONE_MIN   00

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

int disconnectFromAP();

_u8 getOwnMAC(_u8 *macAddressVal);
void setOwnMAC(_u8 *macAddress);

_u32 getOwnIP();
_u32 getHostIP();
_u32 getStationIP();

int scanWifi(int scan_table_size, int channel, Sl_WlanNetworkEntry_t *netEntries);
int getLessSaturatedChannel();



#endif
