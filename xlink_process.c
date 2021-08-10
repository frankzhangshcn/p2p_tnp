#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <string.h>
#include <sched.h>
#include <stdarg.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <mqueue.h>
#include <libgen.h>
#include <sys/mman.h>
#include <stdint.h>
#include <limits.h>

#include <curl/curl.h>
#include "common.h"
#include "xlink_type.h"
#include "Xlink_Head_Adaptation.h"

#include "xlink_process.h"
//#define FZ_DEBUG(info,y...)	do{ printf("\r\n%s:fun(%s)line:%04d:="info,__FILE__,__FUNCTION__,__LINE__,##y);}while(0)
#define GE_SUCCESS      (0)
#define GE_FAIL         (-1)
#define READ_PID                    (0)
#define READ_PKEY                   (1)

//#define XLINK_SERVER_ADDR           "cm-ge.xlink.cn"
//#define XLINK_SERVER_PORT           "23779"

#define XLINK_OTA_ADDR                  "api-ge.xlink.cn"
#define XLINK_OTA_PORT                  (443)

#define WIFI_FIRMWARE_VERSION       (100)
#define WIFI_FIRMWARE_SUB_VERSION   (0)
#define MCU_FIRMWARE_VERSION        (28)

#define XLINK_HARDWARE_VERSION          (1)
//#define XLINK_CURRENT_VERSION           (10000)
//#define XLINK_CURRENT_VERSION           (10001)
#define XLINK_CURRENT_VERSION           (10002)
#define AUTH_CODE_LEN                   (16+16)
#define ACCESS_TOKEN_LEN                (128)
#define DOWNLOAD_URL_LEN                (256)
#define XLINK_AUTHORIZE_CODE_ERROR      (4001097)
typedef struct
{
    uint16_t src_ver;
    uint16_t tar_ver;
    uint16_t current_version; // last_version
    uint8_t mac[6];
    int device_id;
    char auth_code[AUTH_CODE_LEN];
    char access_token[ACCESS_TOKEN_LEN];
    time_t ntokenendtick;
    char download_url[DOWNLOAD_URL_LEN];
    char download_md5[64];
}ota_info_t;


/* resizable buffer */
typedef struct {
  char *buf;
  size_t size;
} memory;

static pthread_mutex_t xlink_lock = PTHREAD_MUTEX_INITIALIZER;
static const char product_ID[]="1607d4c1275000011607d4c12750d806";
static const char product_KEY[]="abc9bd4baaf4a3a9b17c7194f87cf5c8";
static XLINK_USER_CONFIG user_config_call = {0};
static ota_info_t otainfo = {0};

static const char* read_PID_and_PKEY(uint8_t flag)
{
    if(flag == READ_PID)
    {
        return product_ID;
    }
    else
    {
        return product_KEY;
    }
}

static void app_status(XLINK_APP_STATUS status)
{
	switch(status)
	{
    	case XLINK_WIFI_STA_APP_CONNECT:
    		//printf("APP connected\n");
    		break;
    	case XLINK_WIFI_STA_APP_DISCONNECT:
    		//printf("APP disconnect\n");
    		break;
    	case XLINK_WIFI_STA_APP_TIMEOUT:
    		//printf("APP connect timeout\n");
    		break;
    	case XLINK_WIFI_STA_CONNECT_SERVER:
            //FZ_DEBUG("Socket connected to server\n");
    		break;
    	case XLINK_WIFI_STA_DISCONNCT_SERVER:
            //printf("Socket disconnect to server\n");
    		break;
    	case XLINK_WIFI_STA_LOGIN_SUCCESS:
    		//FZ_DEBUG("Socket login server success\n");
    		break;
    	default:
    		break;
	}
}

static uint8_t xsdk_config[__XLINK_CONFIG_BUFFER_SIZE__+1] = {0};

static int32_t xlink_write_config(char *data, uint32_t len)
{
    memcpy(xsdk_config, (uint8_t*)data, len);
	return len;
}

static int32_t xlink_read_config(char *data, uint32_t len)
{
    memcpy((uint8_t*)data, xsdk_config, len);
	return len;
}

static void xlink_SDK_init(void)
{
	//user_config_call.tcp_pipe2 = pipe2_call;
	//user_config_call.tcp_pipe = pipe1_call;
	//user_config_call.udp_pipe = udp_pipe_call;
	user_config_call.writeConfig = xlink_write_config;
	user_config_call.readConfig = xlink_read_config;
	user_config_call.status = app_status;
    //user_config_call.upgrade = upgrade_task;
    //user_config_call.server_time = time_callback;
#ifdef XLINK_SDK_DEBUG
	user_config_call.DebugPrintf = printf;
#else
	user_config_call.DebugPrintf = NULL;
#endif
	user_config_call.wifi_type = 1;
	user_config_call.wifisoftVersion = WIFI_FIRMWARE_VERSION+WIFI_FIRMWARE_SUB_VERSION;//ota_info.cur_wifi_ver + ota_info.cur_ble_ver;
	user_config_call.mcuHardwareVersion = 1;
	user_config_call.mcuHardwareSoftVersion = MCU_FIRMWARE_VERSION;
	user_config_call.in_internet = 1;
	//user_config_call.maclen = get_device_mac(user_config_call.mac);

	user_config_call.mac[0] = otainfo.mac[0];
	user_config_call.mac[1] = otainfo.mac[1];
	user_config_call.mac[2] = otainfo.mac[2];
	user_config_call.mac[3] = otainfo.mac[3];
	user_config_call.mac[4] = otainfo.mac[4];
	user_config_call.mac[5] = otainfo.mac[5];
	user_config_call.maclen = 6;
    /* 缺省两条 */
#if __ALL_DEVICE__
	user_config_call.tcpRecvBuffer = sdk_inner_buf;
	user_config_call.tcpRecvBuuferLength = SDK_INNER_BUF_SIZE; //must 2^n
	user_config_call.send_tcp = send_tcp_to_remote;
	user_config_call.send_udp = send_udp_to_remote;
#endif
	//user_config_call.Xlink_SetDataPoint = SetDataPiont;
	//user_config_call.Xlink_GetAllDataPoint = GetAllDataPiont;

    char *p_PID = (char*)read_PID_and_PKEY(READ_PID);
    char *p_PKEY = (char*)read_PID_and_PKEY(READ_PKEY);

	if (XlinkSystemInit(p_PID, p_PKEY, &user_config_call) == GE_SUCCESS)
	{
        //FZ_DEBUG("Xlink system init failed\n");
	}
    else
    {
        //FZ_DEBUG("Xlink system init success, %s\n", XlinkSystemVersion());
        //FZ_DEBUG("Device MAC: %x:%x:%x:%x:%x:%x", user_config_call.mac[0],
        //    user_config_call.mac[1],  user_config_call.mac[2], user_config_call.mac[3], user_config_call.mac[4], user_config_call.mac[5]);
    }
#if 0
    union {
        xlink_uint8 All;
        struct
        {
            xlink_uint8 isActivation : 1;
            xlink_uint8 isUpgrade : 1;
            xlink_uint8 isSaveDevicekey : 1;
            xlink_uint8 isAppSetName : 1;
            xlink_uint8 isChangedPassword : 1;
            xlink_uint8 isSetPassword : 1;
            xlink_uint8 isAppSetPasswork : 1;
            xlink_uint8 res : 1;
        } Bit;
    } flag;
    xlink_int8 saveBuffer[180];
    xlink_read_config(saveBuffer, 180);
    flag.All = saveBuffer[0] ^ 0x23;
    extern XLINK_FUNC void XlinkSdkAppSetDeviceName(xlink_int8* name, xlink_uint16 nameLength);
    if(flag.Bit.isAppSetName != 1)
    {
        XlinkSdkAppSetDeviceName("xlink_dev", strlen("xlink_dev"));
    }
#endif
	XlinkPorcess_UDP_Disable();
}
#if 0
static void xlink_SDK_uninit(void)
{
    Xlink_Close_Net();

}
#endif
static time_t get_system_time_second(void)
{
    time_t timep;
    time(&timep);
    return timep;
}
int get_sdk_info(ota_info_t *pinfo)
{
    int nret = -1;
    if(strlen(pinfo->auth_code) > 0)
    {
        nret = 0;
        return nret;
    }
    xlink_SDK_init();
    int ncount = 0;
    do
    {
        uint32_t current_time = 0;
        current_time = get_system_time_second();
        XlinkSystemTcpLoop();
        //xlink sdk loop
        XlinkSystemLoop(current_time, 10);
        //pinfo->device_id = XlinkSystemGetDeviceID();
        XlinkGetAuthCode(pinfo->auth_code);
        ncount++;
        if(strlen(pinfo->auth_code) > 0)
        {
            //printf("[H31BG_OTA] p2p_tnp.c %s(%d),authcode[%s],deviceif=%d\r\n",_FU_, _L_,pinfo->auth_code,pinfo->device_id);
            nret = 0;
            break;
        }
        ms_sleep(10);
    }while(ncount < 300);
    Xlink_Close_Net();
    //printf("c:%p:%s\n",pinfo,pinfo->auth_code);
    //printf("ncount:%d\n",ncount);
    return nret;
}

static size_t grow_buffer(void *contents, size_t sz, size_t nmemb, void *ctx)
{
  size_t realsize = sz * nmemb;
  memory *mem = (memory*) ctx;
  char *ptr = realloc(mem->buf, mem->size + realsize);
  if(!ptr) {
    /* out of memory */
    //printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
  mem->buf = ptr;
  memcpy(&(mem->buf[mem->size]), contents, realsize);
  mem->size += realsize;
  return realsize;
}
static int get_json_int(char *json, char *string, int *value)
{
	int ret = -1;
	char *temp_str1 = NULL;

    if(!json || !string)
	{
        printf("get_json_string param error");
		return ret;
	}

	temp_str1 = strstr(json, string);
	if(temp_str1 != NULL)
	{
		temp_str1 += 1;
		temp_str1 = strstr(temp_str1, ":");
		if(temp_str1 != NULL)
		{
            temp_str1 += 1;
			*value = atoi(temp_str1);
			ret = 0;
		}
	}

	return ret;
}

static int get_json_string(char *json, char *string, char *data, int len)
{
	int ret = -1, temp_len = 0;
	char *temp_str1 = NULL, *temp_str2 = NULL;
    if(!json || !string || len <= 0)
	{
        printf("get_json_string param error");
		return ret;
	}

	temp_str1 = strstr(json, string);
	if(temp_str1 != NULL)
	{
		temp_str1 += 1;
		temp_str1 = strstr(temp_str1, ":");
		if(temp_str1 != NULL)
		{
            temp_str1 += 1;
			temp_str1 = strstr(temp_str1, "\"");
			if(temp_str1 != NULL)
			{
                temp_str1 += 1;
				temp_str2 = strstr(temp_str1, "\"");
			}
		}
	}
	if((temp_str1 != NULL) && (temp_str2 != NULL))
	{
        temp_len = temp_str2 - temp_str1;
		if(temp_len <= len)
		{
			memcpy(data, temp_str1, temp_len);
            data[temp_len] = 0;
			ret = 0;
		}
        else
        {
            printf("%s is too long", string);
        }
	}

	return ret;
}
// 返回自系统开机以来的秒数（tick）
static time_t GetTickCount()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec);
}
static int get_access_token(ota_info_t *pinfo)
{
    int ret = -1;
	uint8_t post_data[512] = {0};
	char url[128];
	CURL *curl = NULL;
	int nval = 0;
	int nauthcodErrorCount = 0;
    struct curl_slist *headers = NULL;
	memory *pmem = NULL;
	if(!pinfo)
	{
	    return ret;
	}
    do
    {	
        if(get_sdk_info(pinfo) < 0)
	    {
	        return ret;
	    }

        if(strlen(pinfo->access_token) > 0)
        {
            if(GetTickCount() < pinfo->ntokenendtick)
            {
                ret = 0;
                return ret;
            }
            pinfo->ntokenendtick = 0;
            pinfo->device_id = 0;
            memset(&pinfo->access_token,0,sizeof(pinfo->access_token));
        }

        pmem = malloc(sizeof(memory));
        if(!pmem) {
            /* out of memory */
            //printf("not enough memory (realloc returned NULL)\n");
            return ret;
        }
        pmem->size = 0;
        pmem->buf = malloc(1);
        if(!pmem->buf) {
            /* out of memory */
            free(pmem);
            //printf("not enough memory (realloc returned NULL)\n");
            return ret;
        }
        memset(&url,0,sizeof(url));
        snprintf(url,sizeof(url),"https://%s/v2/device_login",XLINK_OTA_ADDR);
        //printf("url:%s\n",url);
        char *p_PID = read_PID_and_PKEY(READ_PID);
        uint8_t mac[13] = {0};

        snprintf((char*)mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X", pinfo->mac[0], pinfo->mac[1], pinfo->mac[2], pinfo->mac[3], pinfo->mac[4], pinfo->mac[5]);

        sprintf((char*)post_data, "{\"product_id\":\"%s\",\"mac\":\"%s\",\"authorize_code\":\"%s\"}", p_PID, mac, pinfo->auth_code);
        nauthcodErrorCount++;
        curl_global_init(CURL_GLOBAL_ALL);
        curl = curl_easy_init();
        if(curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_PORT, XLINK_OTA_PORT);

            // no authentication
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

            /* no progress meter please */
            curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

            curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, grow_buffer);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, pmem);
            headers = curl_slist_append(headers, "Content-Type:application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            curl_easy_perform(curl);

            curl_slist_free_all(headers); /* free the list again */
            headers = NULL;
            nauthcodErrorCount++;
            long response_code = 0;
            if(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK)
            {
                printf("response_code:%d\n",response_code);
            }
            //printf("data:%d:%s\n",pmem->size,pmem->buf);
            if(response_code == 200)
            {
                nauthcodErrorCount = 0;
                if((ret = get_json_string((char*)pmem->buf, "\"access_token\"", pinfo->access_token, ACCESS_TOKEN_LEN)) == GE_SUCCESS)
                {
                    //printf("xlink token:%s\n",pinfo->access_token);
                    dump_string(_F_, _FU_, _L_, "xlink token:%s\n",pinfo->access_token);
                }

                if((ret = get_json_int((char*)pmem->buf, "\"device_id\"", &nval)) == GE_SUCCESS)
                {
                    //printf("xlink device_id:%d\n", nval);
                    dump_string(_F_, _FU_, _L_, "xlink device_id:%d\n", nval);
                    pinfo->device_id = nval;
                }
    #if 0
                nval = 0;
                if((ret = get_json_int((char*)pmem->buf, "\"expire_in\"", &nval)) == GE_SUCCESS)
                {
                    printf("expire_in:%d\n", nval);
                    pinfo->ntokenendtick = GetTickCount() + nval/2;
                    printf("tick:%d\n", pinfo->ntokenendtick);
                }
    #endif
            }else{
                if(get_json_int((char*)pmem->buf, "\"code\"", &nval) == 0)
                {
                    printf("nval:%d\n",nval);
                    if(XLINK_AUTHORIZE_CODE_ERROR == nval)
                    {
                        dump_string(_F_, _FU_, _L_,"auth code error\n");
                        memset(&pinfo->auth_code,0,sizeof(pinfo->auth_code));
                        nauthcodErrorCount++;
                    }
                }
            }

            curl_easy_cleanup(curl);
            curl = NULL;
        }
        curl_global_cleanup();
        if(pmem)
        {
            if(pmem->buf)
            {
                free(pmem->buf);
            }
            free(pmem);
            pmem = NULL;
        }
    }while(nauthcodErrorCount == 3);
    return ret;
}
int get_version_and_get_download_url(ota_info_t *pinfo)
{
    int ret = -1;
    int nval = 0;
	uint8_t post_data[512] = {0};
	char url[128];
	CURL *curl = NULL;
	char token_header[ACCESS_TOKEN_LEN + 128] = {0};
    struct curl_slist *headers = NULL;
	memory *pmem = NULL;

	if(!pinfo)
	{
	    return ret;
	}
    if(get_access_token(pinfo) < 0)
	{
	    return ret;
	}
	pinfo->tar_ver = 0;
	memset(&pinfo->download_url,0,sizeof(pinfo->download_url));
	memset(&pinfo->download_md5,0,sizeof(pinfo->download_md5));

	snprintf(token_header,sizeof(token_header),"Access-Token:%s",pinfo->access_token);

    pmem = malloc(sizeof(memory));
    if(!pmem) {
        /* out of memory */
        printf("not enough memory (realloc returned NULL)\n");
        return ret;
    }
    pmem->size = 0;
    pmem->buf = malloc(1);
    if(!pmem->buf) {
        /* out of memory */
        free(pmem);
        printf("not enough memory (realloc returned NULL)\n");
        return ret;
    }
    memset(&url,0,sizeof(url));
    snprintf(url,sizeof(url),"https://%s/v2/upgrade/firmware/check/%d",XLINK_OTA_ADDR,pinfo->device_id);
    //printf("url:%s\n",url);
    char *p_PID = read_PID_and_PKEY(READ_PID);
    sprintf((char*)post_data, "{\"product_id\":\"%s\",\"type\":\"1\",\"current_version\":\"%02d\",\"identify\":\"0\"}", p_PID, pinfo->src_ver);
    //printf("post_data:%s\n",post_data);
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_PORT, XLINK_OTA_PORT);

        // no authentication
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        /* no progress meter please */
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, grow_buffer);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, pmem);
        headers = curl_slist_append(headers, "Content-Type:application/json");
        headers = curl_slist_append(headers, token_header);
        headers = curl_slist_append(headers, "Connection:close");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        curl_easy_perform(curl);
        curl_slist_free_all(headers); /* free the list again */
        //printf("data:%d:%s\n",pmem->size,pmem->buf);
        if(pmem->size > 0)
        {
            pinfo->tar_ver = 0;
            if((ret = get_json_int((char*)pmem->buf, "\"target_version\"", &nval)) == GE_SUCCESS)
            {
                //printf("xlink target_version:%d\n", nval);
                dump_string(_F_, _FU_, _L_, "xlink target_version:%d\n", nval);
                pinfo->tar_ver = (uint16_t)nval;
            }
            //printf("xlink version:%d %d\n",pinfo->tar_ver, pinfo->current_version);
            dump_string(_F_, _FU_, _L_, "xlink version:%d %d\n",pinfo->tar_ver, pinfo->current_version);
            if(pinfo->tar_ver > pinfo->current_version)
            {
                if((ret = get_json_string((char*)pmem->buf, "\"target_version_url\"", pinfo->download_url, sizeof(pinfo->download_url))) == GE_SUCCESS)
                {
                    //printf("xlink download_url:%s\n", pinfo->download_url);
                    dump_string(_F_, _FU_, _L_, "xlink download_url:%s\n", pinfo->download_url);
                }
                if((ret = get_json_string((char*)pmem->buf, "\"from_version_md5\"", pinfo->download_md5, sizeof(pinfo->download_md5))) == GE_SUCCESS)
                {
                    //printf("xlink download_md5:%s\n", pinfo->download_md5);
                    dump_string(_F_, _FU_, _L_, "xlink download_md5:%s\n", pinfo->download_md5);
                }
            }

    	}
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    if(pmem)
    {
        if(pmem->buf)
        {
            free(pmem->buf);
        }
        free(pmem);
    }
    return ret;
}

static int report_version(ota_info_t *pinfo)
{
    int ret = -1;
	uint8_t post_data[512] = {0};
	char url[128];
	CURL *curl = NULL;
	char token_header[ACCESS_TOKEN_LEN + 128] = {0};
    struct curl_slist *headers = NULL;
	memory *pmem = NULL;
	if(!pinfo)
	{
	    return ret;
	}
    if(get_access_token(pinfo) < 0)
	{
	    return ret;
	}

	snprintf(token_header,sizeof(token_header),"Access-Token:%s",pinfo->access_token);

    pmem = malloc(sizeof(memory));
    if(!pmem) {
        /* out of memory */
        printf("not enough memory (realloc returned NULL)\n");
        return ret;
    }
    pmem->size = 0;
    pmem->buf = malloc(1);
    if(!pmem->buf) {
        /* out of memory */
        free(pmem);
        printf("not enough memory (realloc returned NULL)\n");
        return ret;
    }

    memset(&url,0,sizeof(url));
    snprintf(url,sizeof(url),"https://%s/v2/upgrade/firmware/report/%d",XLINK_OTA_ADDR,pinfo->device_id);
    sprintf(post_data, "{\"type\":\"1\",\"mod\":\"%d\",\"identify\":\"0\",\"last_version\":\"%d\",\"current_version\":\"%d\",\"result\":\"0\"}", 1, pinfo->current_version, pinfo->current_version);
    //printf("post_data:%s\n",post_data);
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_PORT, XLINK_OTA_PORT);

        // no authentication
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        /* no progress meter please */
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, grow_buffer);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, pmem);
        headers = curl_slist_append(headers, "Content-Type:application/json");
        headers = curl_slist_append(headers, token_header);
        headers = curl_slist_append(headers, "Connection:close");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        curl_easy_perform(curl);
        curl_slist_free_all(headers); /* free the list again */
        long response_code = 0;
        if(curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK)
        {
            //printf("xlink response_code:%d\n",response_code);
            dump_string(_F_, _FU_, _L_, "xlink response_code:%d\n",response_code);
            if(200 == response_code)
            {
                ret = 0;
                //printf("xlink report ok\n");
                dump_string(_F_, _FU_, _L_, "xlink report ok\n");
            }else{
                ret = 1;
            }
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    if(pmem)
    {
        if(pmem->buf)
        {
            free(pmem->buf);
        }
        free(pmem);
    }
    return ret;
}
static int binit = 0;
static void xlink_init(void)
{
    if(binit) return;
    otainfo.src_ver = XLINK_HARDWARE_VERSION;
    otainfo.current_version = XLINK_CURRENT_VERSION;
    dump_string(_F_, _FU_, _L_, "xlink current version:%d\n",otainfo.current_version);
    binit = 1;
}

static int set_mac(char *pmac)
{
    int ret = -1;
    if(!pmac)
    {
        return ret;
    }
    if(sscanf(pmac, "%02x:%02x:%02x:%02x:%02x:%02x", &otainfo.mac[0], &otainfo.mac[1], &otainfo.mac[2], &otainfo.mac[3], &otainfo.mac[4], &otainfo.mac[5]) == 6)
    {
        if((otainfo.mac[0] > 0) || (otainfo.mac[1] > 0) || (otainfo.mac[2] > 0)
            || (otainfo.mac[3] > 0) || (otainfo.mac[4] > 0) || (otainfo.mac[5] > 0))
        {
            ret = 0;
        }
    }
    return ret;
}

char *xlink_get_authcode()
{
    xlink_init();
    return otainfo.auth_code;
}

void xlink_set_authcode(char *pauthcode)
{
    xlink_init();
    if(!pauthcode)
    {
        return;
    }
    if(strlen(pauthcode) == 0 )
    {
        return;
    }
    snprintf(otainfo.auth_code, sizeof(otainfo.auth_code), "%s", pauthcode);
    //printf("xlink otainfo.auth_code:%s\n",otainfo.auth_code);
    dump_string(_F_, _FU_, _L_, "xlink otainfo.auth_code:%s\n",otainfo.auth_code);
    return;
}
int xlink_get_download_url(char *pmac, char *url, char *md5)
{
    int ret = -1;
    pthread_mutex_lock(&xlink_lock); 
    xlink_init();
    if(set_mac(pmac) < 0)
    {
        pthread_mutex_unlock(&xlink_lock);
        return ret;
    }
    if(!url || !md5)
    {
        pthread_mutex_unlock(&xlink_lock);
        return ret;
    }
    if((ret = get_version_and_get_download_url(&otainfo)) == GE_SUCCESS)
    {
        sprintf(url,"%s", otainfo.download_url);
        sprintf(md5,"%s", otainfo.download_md5);
    }
    pthread_mutex_unlock(&xlink_lock);
    return ret;
}

int xlink_report_version(char *pmac)
{

    int ret = -1;
    pthread_mutex_lock(&xlink_lock);
    xlink_init();
    if(set_mac(pmac) < 0)
    {
        pthread_mutex_unlock(&xlink_lock);
        return ret;
    }
    ret = report_version(&otainfo);
    pthread_mutex_unlock(&xlink_lock);
    return ret;
}

