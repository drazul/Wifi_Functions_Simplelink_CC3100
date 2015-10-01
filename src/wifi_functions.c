/*!
    \file
 
    \brief     Library for common wifi functions. File
*/
#include "wifi_functions.h"

_u32  _status = 0;
_u32  _pingPacketsRecv = 0;
_u32  _gatewayIP = 0;
_u32  _stationIP = 0;
_i16  _device_mode = 0;
int   _already_initialized = 0;

WifiConnectionState _connection_state = { .ssid_name = "", .password = "", 
                    .security = 0, .channel = -1, .mode = NOT_CONNECTED}; ;

static void SimpleLinkPingReport(SlPingReport_t *pPingReport);
_i32 establishConnectionWithAP(char* ssid_name, char* password, _u8 security);
_i32 initializeAppVariables();

/*!
    \brief This function handles WLAN events

    \param[in]      pWlanEvent is the event passed to the handler
*/
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent) {
    if(pWlanEvent == NULL) {

        CLI_Write((_u8 *)"[WLAN EVENT] NULL Pointer Error \n");
        return;
    }
    
    switch(pWlanEvent->Event) {
        case SL_WLAN_CONNECT_EVENT:
        {
            SET_STATUS_BIT(_status, STATUS_BIT_CONNECTION);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT:
        {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(_status, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(_status, STATUS_BIT_IP_ACQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code)
                CLI_Write((_u8 *)"Device disconnected from the AP on application's request \n");

            else
                CLI_Write((_u8 *)"Device disconnected from the AP on an ERROR..!! \n");
            
        }
        break;

        case SL_WLAN_STA_CONNECTED_EVENT:
        {
            SET_STATUS_BIT(_status, STATUS_BIT_STA_CONNECTED);
        }
        break;

        case SL_WLAN_STA_DISCONNECTED_EVENT:
        {
            CLR_STATUS_BIT(_status, STATUS_BIT_STA_CONNECTED);
            CLR_STATUS_BIT(_status, STATUS_BIT_IP_LEASED);
        }
        break;

        default:
        {
            CLI_Write((_u8 *)"[WLAN EVENT] Unexpected event \n");
        }
        break;
    }
}


/*!
    \brief This function handles events for IP address acquisition via DHCP
           indication

    \param[in]      pNetAppEvent is the event passed to the handler
*/
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent) {
    if(pNetAppEvent == NULL) {

        CLI_Write((_u8 *)"[NETAPP EVENT] NULL Pointer Error \n");
        return;
    }
 
    switch(pNetAppEvent->Event) {

        case SL_NETAPP_IPV4_IPACQUIRED_EVENT:
        {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(_status, STATUS_BIT_IP_ACQUIRED);

            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;
            _gatewayIP = pEventData->gateway;
        }
        break;

        case SL_NETAPP_IP_LEASED_EVENT:
        {
            _stationIP = pNetAppEvent->EventData.ipLeased.ip_address;
            SET_STATUS_BIT(_status, STATUS_BIT_IP_LEASED);
        }
        break;

        default:
        {
            CLI_Write((_u8 *)"[NETAPP EVENT] Unexpected event \n");
        }
        break;
    }
}

/*!
    \brief This function handles callback for the HTTP server events

    \param[in]      pHttpEvent - Contains the relevant event information
    \param[in]      pHttpResponse - Should be filled by the user with the
                    relevant response information
*/
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent, SlHttpServerResponse_t *pHttpResponse) {
    CLI_Write((_u8 *)"[HTTP EVENT] Unexpected event \n");
}

/*!
    \brief This function handles general error events indication

    \param[in]      pDevEvent is the event passed to the handler
*/
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent) {
    CLI_Write((_u8 *)"[GENERAL EVENT] \n");
}

/*!
    \brief This function handles socket events indication

    \param[in]      pSock is the event passed to the handler
*/
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock) {

    if(pSock == NULL) {

        CLI_Write("[SOCK EVENT] NULL Pointer Error \n");
        return;
    }

    switch(pSock->Event) {
        case SL_SOCKET_TX_FAILED_EVENT:
        {
            switch( pSock->socketAsyncEvent.SockTxFailData.status ) {
                case SL_ECLOSE:
                    CLI_Write((_u8 *)"[SOCK EVENT] Close socket operation failed to transmit all queued packets\n");
                break;


                default:
                    CLI_Write((_u8 *)"[SOCK EVENT] Unexpected event \n");
                break;
            }
        }
        break;

        default:
            CLI_Write((_u8 *)"[SOCK EVENT] Unexpected event \n");
        break;
    }
}

void printWifiParams() {
    CLI_Write((_u8 *)"SSID name: %s\n", _connection_state.ssid_name);
    CLI_Write((_u8 *)"password: %s\n", _connection_state.password);

    switch(_connection_state.security) {
        case 0:
            CLI_Write((_u8 *)"security: OPEN\n");
        break;
        case 1:
            CLI_Write((_u8 *)"security: WEP\n");

        break;
        case 2:
            CLI_Write((_u8 *)"security: WPA/WPA2\n");
    }   
}

void setWifiConnectionState(char *ssid_name, char* password, _u8 security,
                                 int channel, ConnectionMode mode) {
    _connection_state.ssid_name = ssid_name;
    _connection_state.password = password;
    _connection_state.security = security;
    _connection_state.channel = channel; 
    _connection_state.mode = mode;
}

void init_device() {

    _i32 retVal = -1;
    _i32 mode;

    retVal = configureSimpleLinkToDefaultState();

    if(retVal < 0) {
        if (retVal == DEVICE_NOT_IN_STATION_MODE)
            CLI_Write((_u8 *)"Failed to configure the device in its default state \n");
    }

    CLI_Write((_u8 *)"Device is configured in default state \n");

    mode = sl_Start(0, 0, 0);
    _device_mode = mode;
    _already_initialized = 1;
}

/*!
    \brief This function is used for connect to an Access Point

    \param[in]      ssid_name is the name of the Access point

    \param[in]      password is the password of the Access Point

    \param[in]      security is the security of the WiFi network. Can be:
                        - 0 or SL_SEC_TYPE_OPEN
                        - 1 or SL_SEC_TYPE_WEP
                        - 2 or SL_SEC_TYPE_WPA_WPA2



    \return         On success, zero is returned. On error, negative is returned
*/
_i32 connectToAP(char* ssid_name, char* password, _u8 security) {
    setWifiConnectionState(ssid_name, password, security, -1, MODE_STATION);

    CLI_Write((_u8 *)"Connect to AP\n");
    printWifiParams();

    _i32 retVal = -1;
    if(_already_initialized == 0)
        init_device();

    retVal = establishConnectionWithAP(_connection_state.ssid_name, 
        _connection_state.password, _connection_state.security);

    if(retVal < 0) {
        CLI_Write((_u8 *)"Failed to establish connection w/ an AP \n");
    }

    CLI_Write("Connection established w/ AP and IP is acquired \n");

    return retVal;
}

/*!
    \brief This function is used for generate an Access Point

    \param[in]      ssid_name is the name of the Access point

    \param[in]      password is the password of the Access Point

    \param[in]      security is the security of the WiFi network. Can be:
                        - 0 or SL_SEC_TYPE_OPEN
                        - 1 or SL_SEC_TYPE_WEP
                        - 2 or SL_SEC_TYPE_WPA_WPA2

    \param[in]      channel is the channel where the network is generated


    \return         0 - if mode was set correctly
*/
int generateAP(char* ssid_name, char* password, _u8 security, int channel) {

    setWifiConnectionState(ssid_name, password, security, channel, MODE_AP);

    CLI_Write((_u8 *)"create AP on channel %d\n", _connection_state.channel);
    printWifiParams();

    _i32 mode = ROLE_STA;
    _i32 retVal = -1;

    if(_already_initialized == 0)
        init_device();

    retVal = sl_WlanSetMode(ROLE_AP);

    if(retVal < 0) CLI_Write((_u8 *)"Error\n");

    retVal = sl_WlanSet(SL_WLAN_CFG_AP_ID, WLAN_AP_OPT_SSID,
                pal_Strlen(_connection_state.ssid_name), 
                    (_u8 *) _connection_state.ssid_name);

    if(retVal < 0) CLI_Write((_u8 *)"Error\n");

    retVal = sl_WlanSet(SL_WLAN_CFG_AP_ID, WLAN_AP_OPT_SECURITY_TYPE, 1,
                (_u8 *) &_connection_state.security);

    if(retVal < 0) CLI_Write((_u8 *)"Error\n");


    retVal = sl_WlanSet(SL_WLAN_CFG_AP_ID, WLAN_AP_OPT_PASSWORD, 
                pal_Strlen(_connection_state.password),
                    (_u8 *) _connection_state.password);

    if(retVal < 0) CLI_Write((_u8 *)"Error\n");

        
    retVal=sl_WlanSet(SL_WLAN_CFG_AP_ID, WLAN_AP_OPT_CHANNEL, 1, 
                (unsigned char*) &_connection_state.channel);

    if(retVal < 0) CLI_Write((_u8 *)"Error\n");

    retVal = sl_Stop(SL_STOP_TIMEOUT);

    if(retVal < 0) CLI_Write((_u8 *)"Error\n");

    CLR_STATUS_BIT(_status, STATUS_BIT_IP_ACQUIRED);

    mode = sl_Start(0, 0, 0);
    _device_mode = mode;
    if (mode == ROLE_AP)
        while(!IS_IP_ACQUIRED(_status))  
            rtems_task_wake_after(100); 
    
    else
        CLI_Write((_u8 *)"Device couldn't be configured in AP mode \n");

    CLI_Write((_u8 *)"Device started as Access Point\n");

    return SUCCESS;
}

/*!
    \brief This function is used for change the operation mode of the device

    \param[in]      new_mode is the name of the Access point. Can be:
                        - ROLE_STA    
                        - ROLE_AP     
                        - ROLE_P2P 
   
    \return         new_mode value if it was successfully completed
*/
_i32 wlanSetMode(int new_mode) {

    _i32          retVal = -1;
    _i32          mode = -1;

    mode = sl_Start(0, 0, 0);
    _device_mode = mode;
    ASSERT_ON_ERROR(mode);

    if(mode == new_mode) return 0;

    if (mode == ROLE_AP) 
        while(!IS_IP_ACQUIRED(_status)) { rtems_task_wake_after(100);}
    
    retVal = sl_WlanSetMode(new_mode);
    ASSERT_ON_ERROR(retVal);


    retVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(retVal);

    retVal = sl_Start(0, 0, 0);
    _device_mode = retVal;
    ASSERT_ON_ERROR(retVal);

    if (retVal != new_mode) {
        CLI_Write((_u8 *)"Device couldn't be configured in new mode \n");
    }
 
    return retVal;
}

/*!
    \brief This function is used for change operation power of the device

    \param[in]      power is a number between 0-15, as dB offset from max power. 0 will set maximum power
   
    \return          On success, zero is returned. On error, negative is returned
*/
_i32 setWlanPower(_u8 power) {

    if(_device_mode == ROLE_STA)
        return sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (_u8 *) &power);

    else
        return sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, WLAN_GENERAL_PARAM_OPT_AP_TX_POWER, 1, (_u8 *) &power);
}

/*!
    \brief This function is used for set power policy of the device

    \param[in]      policy is the power policy to set. Can be:
                      - SL_ALWAYS_ON_POLICY
                      - SL_NORMAL_POLICY
                      - SL_LOW_POWER_POLICY
                      - SL_LONG_SLEEP_INTERVAL_POLICY
     
    \return         On success, zero is returned. On error, negative is returned
*/
_i32 setPowerPolicy(_u8 policy) {

    CLI_Write((_u8 *)"Set power policy to ");
    switch(policy){
        case SL_ALWAYS_ON_POLICY:
            CLI_Write((_u8 *)"SL_ALWAYS_ON_POLICY\n");
        break;

        case SL_NORMAL_POLICY:
            CLI_Write((_u8 *)"SL_NORMAL_POLICY\n");

        break;

        case SL_LOW_POWER_POLICY:
            CLI_Write((_u8 *)"SL_LOW_POWER_POLICY\n");
    }


    return sl_WlanPolicySet(SL_POLICY_PM, policy, NULL,0);
}

/*!
    \brief This function is used for sleep the device

    \param[in]      time is a value between 100-2000 ms
     
    \return         On success, zero is returned. On error, negative is returned
*/
_i32 sleepWlanDevice(int time) {

    CLI_Write((_u8 *)"Sleeping Wlan Device %d ms\n", time);

    _u8 pBuff[4] = {0, 0, time, 0};
    return sl_WlanPolicySet(SL_POLICY_PM, SL_LONG_SLEEP_INTERVAL_POLICY, pBuff, sizeof(pBuff));
}

/*!
    \brief This function configure the SimpleLink device in its default state. It:
           - Sets the mode to STATION
           - Configures connection policy to Auto and AutoSmartConfig
           - Deletes all the stored profiles
           - Enables DHCP
           - Disables Scan policy
           - Sets Tx power to maximum
           - Sets power policy to normal
           - Unregisters mDNS services
           - Remove all filters

    \param[in]      none

    \return         On success, zero is returned. On error, negative is returned
*/
_i32 configureSimpleLinkToDefaultState() {

    SlVersionFull ver = {.ChipFwAndPhyVersion = {.ChipId = 0, .FwVersion = 0, .PhyVersion = 0}, 
                .NwpVersion = 0, .Padding = 0, .RomVersion = 0};

    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {.FilterIdMask = 0, .Padding = 0};

    _u8           val = 1;
    _u8           configOpt = 0;
    _u8           configLen = 0;
    _u8           power = 0;

    _i32          retVal = -1;
        
    retVal = initializeAppVariables();
    ASSERT_ON_ERROR(retVal);

    stopWDT();
    initClk();

    CLI_Configure();

    retVal = wlanSetMode(ROLE_STA);

    configOpt = SL_DEVICE_GENERAL_VERSION;
    configLen = sizeof(ver);

    retVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &configOpt, &configLen, (_u8 *) (&ver));
    ASSERT_ON_ERROR(retVal);

    retVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(retVal);

    retVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(retVal);

    retVal = sl_WlanDisconnect();

    if(retVal == 0)
        while(IS_CONNECTED(_status)) 
            rtems_task_wake_after(100);


    retVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE, 1, 1, &val);
    ASSERT_ON_ERROR(retVal);

    configOpt = SL_SCAN_POLICY(0);
    retVal = sl_WlanPolicySet(SL_POLICY_SCAN , configOpt, NULL, 0);
    ASSERT_ON_ERROR(retVal);

    retVal = setWlanPower(0);
    ASSERT_ON_ERROR(retVal);

    //setPowerPolicy(SL_NORMAL_POLICY);
    setPowerPolicy(SL_ALWAYS_ON_POLICY);

    retVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(retVal);

    pal_Memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    retVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(retVal);

    retVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(retVal);

    retVal = initializeAppVariables();
    ASSERT_ON_ERROR(retVal);

    return retVal;
}

/*!
    \brief Connecting to a WLAN Access point

    This function connects to the required AP (SSID_NAME).
    The function will return once we are connected and have acquired IP address

    \param[in]  None

    \return     0 on success, negative error-code on error

    \warning    If the WLAN connection fails or we don't acquire an IP address,
                We will be stuck in this function forever.
*/
_i32 establishConnectionWithAP(char* ssid_name, char* password, _u8 security) {

    SlSecParams_t secParams;

    _i32 retVal = 0;

    secParams.Key = password;
    secParams.KeyLen = pal_Strlen(secParams.Key);
    secParams.Type = security;

    retVal = sl_WlanConnect(ssid_name, pal_Strlen(ssid_name), NULL, &secParams, NULL);

    ASSERT_ON_ERROR(retVal);

    while((!IS_CONNECTED(_status)) || (!IS_IP_ACQUIRED(_status))) {
        CLI_Write((_u8 *)"Connecting...\n");
        rtems_task_wake_after(100); 
    }

    return SUCCESS;
}

/*!
    \brief Disconnecting from a WLAN Access point

    This function disconnects from the connected AP

    \warning        If the WLAN disconnection fails, we will be stuck in this function forever.
*/
int disconnectFromAP() {

     CLI_Write((_u8 *)"Disconnecting from AP\n");

    _i32 retVal = -1;

    retVal = sl_WlanDisconnect();

    if(retVal == 0)
        while(IS_CONNECTED(_status)) 
            rtems_task_wake_after(100);


    return SUCCESS;
}

/*!
    \brief This function initializes the application variables

    \return     0 on success, negative error-code on error
*/
_i32 initializeAppVariables() {

    _status = 0;
    _pingPacketsRecv = 0;
    _stationIP = 0;
    _gatewayIP = 0;
    
    return SUCCESS;
}

/*!
    \brief Wait thread until the first client connects
*/
void waitClients() {
    CLI_Write((_u8 *)"Waiting for clients\n");
    while((!IS_IP_LEASED(_status)) || (!IS_STA_CONNECTED(_status))) 
        rtems_task_wake_after(100);
}

_u32 getStationIP() {
    return _stationIP;
}

/*!
    \brief Get IPv4 value into an array

    \param[in]  val IP value code into a _u32 data type

    \param[out] returnIP IP value code into an array of four numbers
*/
void prettyIPv4(_u32 val, _u8* returnIP) {

    returnIP[0] = SL_IPV4_BYTE(val, 3);
    returnIP[1] = SL_IPV4_BYTE(val, 2);
    returnIP[2] = SL_IPV4_BYTE(val, 1);
    returnIP[3] = SL_IPV4_BYTE(val, 0);
}

/*!
    \brief Ping to a last connected device

    \param[in]  interval interval between ping commands

    \param[in]  size size of the ping package

    \param[in]  request_timeout timeout of the response

    \param[in]  ping_attemp times to retying
*/
void pingToConnectedDevice(int interval, int size, int request_timeout, int ping_attemp) {
    ping(interval, size, request_timeout, ping_attemp, _stationIP);
}

/*!
    \brief Ping to an IP

    \param[in]  interval interval between ping commands

    \param[in]  size size of the ping package

    \param[in]  request_timeout timeout of the response

    \param[in]  ping_attemp times to retying

    \param[in] ip Address to ping
*/
void ping(int interval, int size, int request_timeout, int ping_attemp, _u32 ip) {

    CLI_Write((_u8 *)"pinging to ");
    printPrettyIPv4_u32(ip);

    SlPingStartCommand_t PingParams = {0};

    PingParams.PingIntervalTime = interval;
    PingParams.PingSize = size;
    PingParams.PingRequestTimeout = request_timeout;
    PingParams.TotalNumberOfAttempts = ping_attemp;
    PingParams.Flags = 0;
    PingParams.Ip = ip;

    
    SlPingReport_t Report = {0};

    _u8 SecType = 0;
    _i32 mode = ROLE_STA;
    _i32 retVal = -1;

    retVal = initializeAppVariables();
    ASSERT_ON_ERROR(retVal);

    retVal = sl_NetAppPingStart((SlPingStartCommand_t*) &PingParams, SL_AF_INET,
                           (SlPingReport_t*) &Report, SimpleLinkPingReport);

    while(!IS_PING_DONE(_status)) { 
        ASSERT_ON_ERROR("Error on ping\n");
        rtems_task_wake_after(100); 
    }

    if (_pingPacketsRecv == 0) {
        CLI_Write((_u8 *)"A STATION couldn't connect to the device \n");
        ASSERT_ON_ERROR(LAN_CONNECTION_FAILED);
    }

    CLI_Write((_u8 *)"Device and the station are successfully connected \n");
}

static void SimpleLinkPingReport(SlPingReport_t *pPingReport) {

    SET_STATUS_BIT(_status, STATUS_BIT_PING_DONE);

    if(pPingReport == NULL) {

        CLI_Write((_u8 *)"[PING REPORT] NULL Pointer Error\n");
        return;
    }

    _pingPacketsRecv = pPingReport->PacketsReceived;
}

_u32 getOwnIP() {

    _u8 len = sizeof(SlNetCfgIpV4Args_t);
    _u8 dhcpIsOn = 0;
    SlNetCfgIpV4Args_t ipV4 = {0};
    if(_device_mode == ROLE_STA)
        sl_NetCfgGet(SL_IPV4_STA_P2P_CL_GET_INFO, &dhcpIsOn, &len, (_u8 *) &ipV4);
    else
        sl_NetCfgGet(SL_IPV4_AP_P2P_GO_GET_INFO, &dhcpIsOn, &len, (_u8 *) &ipV4);

    return ipV4.ipV4;
}

_u32 getHostIP() {
    return _gatewayIP;
}

void getOwnMAC(_u8 *macAddressVal) {
    CLI_Write((_u8 *)"get own MAC Address\n");

    _u8 macAddressLen = SL_MAC_ADDR_LEN;
    sl_NetCfgGet(SL_MAC_ADDRESS_GET, NULL, &macAddressLen, macAddressVal);
}

/*!
    \brief Change MAC Address

    \param[in]  macAddressVal new MAC address

    \warning Before that the device can have a malfunction
*/
void setOwnMAC(_u8 *macAddressVal) {

    CLI_Write((_u8 *)"Set own MAC Address to ", 
            macAddressVal[0], macAddressVal[1], macAddressVal[2], 
            macAddressVal[3], macAddressVal[4], macAddressVal[5]);

    sl_NetCfgSet(SL_MAC_ADDRESS_SET, 1, SL_MAC_ADDR_LEN, (_u8 *) macAddressVal);
    sl_Stop(0);
    _device_mode = sl_Start(NULL,NULL,NULL);
}

void printPrettyIPv4_u32(_u32 ip) {
    _u8 pretty_ip[4];

    prettyIPv4(ip, pretty_ip);

    printPrettyIPv4_char(pretty_ip);
}

void printPrettyIPv4_char(_u8* ip) {
    CLI_Write((_u8 *)"IP Address %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void printPrettyMAC(_u8 *macAddressVal) {
    CLI_Write((_u8 *)"MAC Address %02X:%02X:%02X:%02X:%02X:%02X\n", 
        macAddressVal[0], macAddressVal[1], macAddressVal[2], 
        macAddressVal[3], macAddressVal[4], macAddressVal[5]);
}

/*!
    \brief Get all available WiFi networks and restore previous state

    \param[in]  scan_table_size the maximum wifi networks to return

    \param[in] channel channel where scan. Have values between 1-11. Other value means all channels

    \param[in] timeout timeout in second for wifi network scan

    \param[out] netEntries array of found WiFi networks
*/
int scanWifiRestoreState(int scan_table_size, int channel, int timeout, 
                        Sl_WlanNetworkEntry_t *netEntries) {
    int idx = 0;
    WifiConnectionState wifi_state = getWifiState();

    idx = scanWifi(scan_table_size, channel, timeout, netEntries);

    setWifiState(wifi_state);

    return idx;
}

/*!
    \brief Get all available WiFi networks

    \param[in] scan_table_size the maximum wifi networks to return

    \param[in] channel channel where scan. Have values between 1-11. Other value means all channels

    \param[in] timeout timeout in second for wifi network scan

    \param[out] netEntries array of found WiFi networks

    \note this function ends turning off the device, if you want to keep using it set on again
*/
int scanWifi(int scan_table_size, int channel, int timeout, Sl_WlanNetworkEntry_t *netEntries) {

    CLI_Write((_u8 *)"scan wifi\n");

    Sl_WlanNetworkEntry_t netentry = {.bssid = '0', .reserved = 0, . rssi = 0,
                .sec_type = 0, .ssid = '0', .ssid_len = 1};
    _u8   policyOpt = 0;
    _u16  idx = 0;
    _u16  runningIdx = 0;
    _u32  numOfEntries = 0;
    _i32  retVal = -1;
    _u32  policyVal = 0;

    if (_already_initialized == 1)
        sl_Stop(0);
    
    init_device();

    retVal = initializeAppVariables();
    ASSERT_ON_ERROR(retVal);

    slWlanScanParamCommand_t ScanParamConfig = {0};

    if(channel >= 1 && channel <= 11) {
        CLI_Write((_u8 *)"Scan on channel %d\n", channel);

        ScanParamConfig.G_Channels_mask = channel;
        ScanParamConfig.rssiThershold = - 80;
    }
    else {
        CLI_Write((_u8 *)"Scan on all channels\n");

        ScanParamConfig.G_Channels_mask = 12;
        ScanParamConfig.rssiThershold = - 80;
    }
    sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, WLAN_GENERAL_PARAM_OPT_SCAN_PARAMS, 
                sizeof(slWlanScanParamCommand_t), (_u8 *) &ScanParamConfig);

    policyOpt = SL_CONNECTION_POLICY(0, 0, 0, 0, 0);
    retVal = sl_WlanPolicySet(SL_POLICY_CONNECTION , policyOpt, NULL, 0);
    if (retVal < 0)
    {
        CLI_Write("Failed to set the connection policy \n");
        CLI_Write((_u8 *)"Error\n");
    }

    policyOpt = SL_SCAN_POLICY(1);

    policyVal = 15;

    CLI_Write("Enabling and configuring the scan policy \n");

    retVal = sl_WlanPolicySet(SL_POLICY_SCAN , policyOpt,
                            (_u8 *)&policyVal, sizeof(policyVal));
    if (retVal < 0)
    {
        CLI_Write("Failed to Enable the scan policy \n");
        CLI_Write((_u8 *)"Error\n");
    }

    rtems_task_wake_after(timeout * 1000);

    runningIdx = 0;
    numOfEntries = scan_table_size;

    retVal = sl_WlanGetNetworkList(runningIdx, numOfEntries,
                                   &netEntries[runningIdx]);

    /* From Texas instrument CC3100 driver
     *
     * Because of a bug user should either read the maximum entries or read
     * entries one by one from the end and check for duplicates. Once a duplicate
     * is found process should be stopped.
     */

    runningIdx = 20;
    numOfEntries = 1;
    pal_Memset(netEntries, 0, sizeof(netEntries));

    do {
        runningIdx--;
        retVal = sl_WlanGetNetworkList(runningIdx, numOfEntries,
                                   &netentry);
        if(retVal < (int) numOfEntries) {
            CLI_Write((_u8 *)"No wifi found\n");
            return 0;
        }

        if(idx > 0) {
            if(0 == pal_Memcmp(netentry.bssid,
                      netEntries[idx - 1].bssid, SL_BSSID_LENGTH))
                break;
        }

        pal_Memcpy(&netEntries[idx], &netentry, sizeof(Sl_WlanNetworkEntry_t));
        idx++;

    } while (runningIdx > 0);

    CLI_Write("Scan Process completed \n");

    policyOpt = SL_SCAN_POLICY(0);
    retVal = sl_WlanPolicySet(SL_POLICY_SCAN , policyOpt, NULL, 0);

    if (retVal < 0)
    {
        CLI_Write("Failed to to disable the scan policy \n");
        CLI_Write((_u8 *)"Error\n");
    }

    CLI_Write("Disabled the scan policy \n");
    
    retVal = sl_Stop(SL_STOP_TIMEOUT);
    _already_initialized = 0;

    if(retVal < 0)
       CLI_Write((_u8 *)"error\n");

    setWifiConnectionState("", "", 0, -1, NOT_CONNECTED);

    return idx;
}

/*!
    \brief Get the number of less saturated channel

    \return the number of less saturated channel
*/
int getLessSaturatedChannel() {
    int scan_table_size = 10, less_channel = 10000, less_num_entries = 10000;
    int i, num_entries, j;

    Sl_WlanNetworkEntry_t netEntries[scan_table_size];
    
    for(i = 1; i <= 11; i++) {
        
        num_entries = scanWifi(scan_table_size, i, 3, netEntries);
        
        for(j = 0; j < num_entries; j++)
            CLI_Write((_u8 *)"SSID: %s\n", netEntries[j].ssid);

        if(num_entries < less_num_entries) {
            less_channel = i;
            less_num_entries = num_entries;
        }
    }

    return less_channel;
}

/*!
    \brief Get the wifi connection state

    \return the wifi connection state
*/
WifiConnectionState getWifiState() {
    return _connection_state;
}

/*!
    \brief Set the wifi connection state
*/
void setWifiState(WifiConnectionState state) {

    switch(state.mode) {
        case MODE_AP:
            generateAP(state.ssid_name, state.password, 
                state.security, state.channel);
        break;
        case MODE_STATION:
            connectToAP(state.ssid_name, state.password, 
                state.security);
    }
}

