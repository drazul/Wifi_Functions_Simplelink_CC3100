/*!
    \file

    \brief     Library for common wifi functions. Header
*/

#ifndef WifiFunctions_H
#define WifiFunctions_H


#include <simplelink.h>
#include <rtems.h>

#define DEFAULT_SSID "DefaultAP"
#define DEFAULT_PASSWORD "123456789"
#define DEFAULT_SECURITY SL_SEC_TYPE_WPA_WPA2
#define DEFAULT_CHANNEL 8

#define SL_STOP_TIMEOUT        0xFFFF

/* Status bits - These are used to set/reset the corresponding bits in a 'status_variable' */
typedef enum{
    STATUS_BIT_CONNECTION =  0, /* If this bit is:
                                 *      1 in a 'status_variable', the device is connected to the AP
                                 *      0 in a 'status_variable', the device is not connected to the AP
                                 */

    STATUS_BIT_STA_CONNECTED,    /* If this bit is:
                                  *      1 in a 'status_variable', client is connected to device
                                  *      0 in a 'status_variable', client is not connected to device
                                  */

    STATUS_BIT_IP_ACQUIRED,       /* If this bit is:
                                   *      1 in a 'status_variable', the device has acquired an IP
                                   *      0 in a 'status_variable', the device has not acquired an IP
                                   */

    STATUS_BIT_IP_LEASED,           /* If this bit is:
                                      *      1 in a 'status_variable', the device has leased an IP
                                      *      0 in a 'status_variable', the device has not leased an IP
                                      */

    STATUS_BIT_CONNECTION_FAILED,   /* If this bit is:
                                     *      1 in a 'status_variable', failed to connect to device
                                     *      0 in a 'status_variable'
                                     */

    STATUS_BIT_P2P_NEG_REQ_RECEIVED,/* If this bit is:
                                     *      1 in a 'status_variable', connection requested by remote wifi-direct device
                                     *      0 in a 'status_variable',
                                     */
    STATUS_BIT_SMARTCONFIG_DONE,    /* If this bit is:
                                     *      1 in a 'status_variable', smartconfig completed
                                     *      0 in a 'status_variable', smartconfig event couldn't complete
                                     */

    STATUS_BIT_SMARTCONFIG_STOPPED  /* If this bit is:
                                     *      1 in a 'status_variable', smartconfig process stopped
                                     *      0 in a 'status_variable', smartconfig process running
                                     */
}e_StatusBits;


#define SET_STATUS_BIT(status_variable, bit)    status_variable |= ((unsigned long)1<<(bit))
#define CLR_STATUS_BIT(status_variable, bit)    status_variable &= ~((unsigned long)1<<(bit))
#define GET_STATUS_BIT(status_variable, bit)    (0 != (status_variable & ((unsigned long)1<<(bit))))

#define IS_PING_DONE(status_variable)             GET_STATUS_BIT(status_variable, STATUS_BIT_PING_DONE)
#define IS_CONNECTED(status_variable)             GET_STATUS_BIT(status_variable, STATUS_BIT_CONNECTION)
#define IS_STA_CONNECTED(status_variable)         GET_STATUS_BIT(status_variable, STATUS_BIT_STA_CONNECTED)
#define IS_IP_ACQUIRED(status_variable)           GET_STATUS_BIT(status_variable, STATUS_BIT_IP_ACQUIRED)
#define IS_IP_LEASED(status_variable)             GET_STATUS_BIT(status_variable, STATUS_BIT_IP_LEASED)
#define IS_CONNECTION_FAILED(status_variable)     GET_STATUS_BIT(status_variable, STATUS_BIT_CONNECTION_FAILED)
#define IS_P2P_NEG_REQ_RECEIVED(status_variable)  GET_STATUS_BIT(status_variable, STATUS_BIT_P2P_NEG_REQ_RECEIVED)
#define IS_SMARTCONFIG_DONE(status_variable)      GET_STATUS_BIT(status_variable, STATUS_BIT_SMARTCONFIG_DONE)
#define IS_SMARTCONFIG_STOPPED(status_variable)   GET_STATUS_BIT(status_variable, STATUS_BIT_SMARTCONFIG_STOPPED)

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
int generateAPSaveProfile(char* ssid_name, char* password, _u8 security, int channel);
int generateAPFromProfile(int index);
int generateAPFromDefaultProfile();
int generateAPFromProfileOnErrorDefault(int index);

_i32 connectToAP(char* ssid_name, char* password, _u8 security, int timeout);
_i32 wlanSetMode(int new_mode);

_i32 setWlanPower(_u8 power);
_i32 setPowerPolicy(_u8 policy);
_i32 sleepWlanDevice(int time);

_i32 configureSimpleLinkToDefaultState();

_i32 pingToConnectedDevice(int interval, int size, int request_timeout, int ping_attemp);
_i32 ping(int interval, int size, int request_timeout, int ping_attemp, _u32 ip);

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
_i16 removeProfiles();

#endif