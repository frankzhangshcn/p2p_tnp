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

#include "cyassl/options.h"
#include "cyassl/ctaocrypt/aes.h"
#include "cyassl/ctaocrypt/sha.h"

#include "common.h"
#include "libcommon.h"
///#include "mediaDataShare.h"
#include "frameshare.h"
#include "mp4read.h"
#include "ptz_ctl.h"

#include "PPPP_API.h"
#include "AVSTREAM_IO_Proto.h"

#include "conftool.h"
//#include "../../lib/aec/include/AudioAecProcess.h"

#include "uart_com.h"

#define __PRINT_MACRO(x) #x
#define DEVICE_NAME(name, suffix) #name"-"__PRINT_MACRO(suffix)
#define IMAGE_SUFFIX(name, suffix) #name"_"__PRINT_MACRO(suffix)"m"
#define IMAGE_NAME IMAGE_SUFFIX(home, DEVICE_SUFFIX)
#pragma message(DEVICE_NAME(familymonitor, DEVICE_SUFFIX))
#define MAX_SESSION_NUM						8
#define MAX_VIEWING_NUM						6
#define MAX_P2P_AUTH_NONCE					100
#define P2P_AUTH_SESSION_NONCE_LEN          7
#define P2P_AUTH_CMD_NONCE_LEN              8
#define MAX_I_FRAME_CACHE_SIZE 				MAX_VIDEO_FRAME
#define MAX_REALTIME_P_FRAME_CACHE_SIZE 	100*1024
#define MAX_RECORD_P_FRAME_CACHE_SIZE 		100*1024
#define MAX_AUDIO_FRAME_CACHE_SIZE 		20*1024
#define AUDIO_DATA_FIX_LEN					80

#define TRUE    1
#define FALSE   0

#define IPAD 0x36
#define OPAD 0x5c

#define LOAD_URL_FIXED_PART_NUM         5
#define LOAD_URL_VERSION_PART_LEN       21

#define TNP_IPCAM_CMD_VER_1			1

#define RECORD_EVENT_MMAP   "/tmp/record_event"


#define offsetof(type, member) ((long) &((type *) 0)->member)

typedef enum
{
	CHANNEL_IOCTRL = 0,
	CHANNEL_AUDIO,
	CHANNEL_VIDEO_REALTIME_IFRAME,
	CHANNEL_VIDEO_REALTIME_PFRAME,
	CHANNEL_VIDEO_RECORD_IFRAME,
	CHANNEL_VIDEO_RECORD_PFRAME,
}CHANNEL_TYPE;

typedef enum
{
	AUTH_OK = 0,
	AUTH_FAIL,
	AUTH_BAD_NONCE,
	AUTH_UNSUPPORTED_VERSION,
	AUTH_BAD_SESSION_NONCE,
}AUTH_RESULT_TYPE;

typedef enum
{
    CH_DOT = 0,
    CH_UNLINE,
    CH_DIGIT,
    CH_UPLETT,
    CH_UNKNOWN,
}CH_TYPE;

typedef enum
{
	USER_STATE_UNUSED,
	USER_STATE_CLOSED,
	USER_STATE_USED,
}USER_STATE;

typedef struct
{
	char p2p_auth_session_nonce[P2P_AUTH_SESSION_NONCE_LEN+1];
	char p2p_auth_cmd_nonce[MAX_P2P_AUTH_NONCE][32];
	int cur_nonce;
}p2p_nonce_t;

typedef struct
{
	STimeDay starttime;
	unsigned int duration;
}tnp_event_msg_s;

typedef struct
{
	unsigned short event_cnt;
	unsigned char  rsv[10];

}tnp_event_msg_head_s;

typedef struct
{
	st_AVStreamIOHead io_head;
	st_AVIOCtrlHead ctrl_head;
	tnp_event_msg_head_s head;
	tnp_event_msg_s event[MAX_RECORD_EVENT];	/*flexiable area, cnt=event_cnt*/
	time_t newest_end_time;
}tnp_eventlist_msg_s;

typedef struct
{
	unsigned char usecount;
	unsigned char resolution;
	unsigned char cmd_vesion;
	unsigned char rsv[1];
}tnp_ipcamstart_msg_s;

typedef struct
{
	unsigned char usecount;
	unsigned char resolution;
	unsigned char cmd_vesion;
	unsigned char rsv[1];
	STimeDay replay_time;	/*use utc time*/
}tnp_ipcamreplay_msg_s;

typedef struct{
	char bUsed;
	char bVideoRequested;
	char bAudioRequested;
	char bRecordPlay;

	char bSpeakerStart;
	char encrypt;
	char record_crtl_refreshed;
	char file_switch;

	char force_i_frame;
	char use_test_auth;
	char calc_bitrate;
	char resolution_switch_counter;
	char first_i_frame_sended;
	char view_state;
	char tnp_ver;
	char reserved[1];

	short width;
	short height;

	unsigned short video_seq;
	unsigned short audio_seq;

	int SessionHandle;
	int usecount;
	int resolution;
	int pre_resolution;
	int auto_resolution;
	int record_speed;
	int pre_record_speed;
	int video_index;
	int audio_index;
	int i_frame_left_size;
	unsigned int cur_ts;
	unsigned int max_buff_size;
    unsigned int videoStartTime;
	time_t replay_time;
    unsigned int playDuration;
	struct timeval g_tv;

	mp4trackinfo mp4info;
	SMsgAVIoctrlPlayRecord record_ctrl;
	p2p_nonce_t p2p_nonce;

	char password[20];
	unsigned char *buff;
    unsigned short fshare_read_mask;
    unsigned char vps[40];
    int vps_len;
#if defined(PRODUCT_H60GA)|| defined(PRODUCT_H31BG) ||defined(NOT_PLT_API)
    unsigned char sps[80];
#else
    unsigned char sps[60];
#endif
    int sps_len;
    unsigned char pps[20];
    int pps_len;
} st_User;

struct sha1_ctx
{
  unsigned int A;
  unsigned int B;
  unsigned int C;
  unsigned int D;
  unsigned int E;

  unsigned int total[2];
  unsigned int buflen;
  unsigned int buffer[32];
};

typedef struct
{

	mqd_t mqfd_dispatch;
	mqd_t mq_p2ptnp;

	mmap_info_s* mmap_info;

	int cur_usr;
	st_User gUser[MAX_SESSION_NUM];
	int viewer_table[MAX_VIEWING_NUM];
	int user_num;
	int max_user_num;
}g_p2ptnp_info_s;

#define PPPP_DRW_MODE_ALL_RELIABLE 0x0
#define PPPP_DRW_MODE_CH0_CH2_CH4_RELIABLE 0x002A
#define PPPP_DRW_MODE_CH0_CH2_CH4_CH5_RELIABLE 0x000A

extern UINT16 gStephenIndex;

g_p2ptnp_info_s g_p2ptnp_info;

pthread_mutex_t event_list_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t viewer_table_lock = PTHREAD_MUTEX_INITIALIZER;

static short tnp_version = TNP_VERSION_2;
record_event_info_t *gEventLog = NULL;
int g_is_internet = 0;
int g_updatestat = 0;
int factory_mode = 0;
tnp_eventlist_msg_s tnp_eventlist_msg;
Aes aes;
Aes aes_dec;
unsigned int check_login_success = 0;
unsigned int check_login_fail = 0;

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *load_url_fixed_part_table[LOAD_URL_FIXED_PART_NUM] = {"http://yi-version.qiniudn.com/@/familymonitor/",
                                                                    "http://115.28.170.6:8084/vfile/download/familymonitor/",
                                                                    "http://download.xiaoyi.com.tw/smarthomecam/",
                                                                    "http://download.xiaoyi.com/smarthomecam/",
                                                                    "http://ds51qrrlkjd6a.cloudfront.net/smarthomecam/"};

static char vesion_char_map[LOAD_URL_VERSION_PART_LEN] = {
                                                    CH_DIGIT, CH_DOT, CH_DIGIT, CH_DOT, CH_DIGIT, CH_DOT, CH_DIGIT, CH_UPLETT,
                                                    CH_UNLINE, CH_DIGIT, CH_DIGIT, CH_DIGIT, CH_DIGIT, CH_DIGIT, CH_DIGIT, CH_DIGIT,
                                                    CH_DIGIT, CH_DIGIT, CH_DIGIT, CH_DIGIT, CH_DIGIT};

int p2p_send_ctrl_data(int index, ENUM_AVIOCTRL_MSGTYPE msg_type, UINT16 nIOCtrlCmdNum, char *payload, int payload_len);
int p2p_send_ctrl_data_ext(int index, ENUM_AVIOCTRL_MSGTYPE msg_type, UINT16 nIOCtrlCmdNum, char *payload, int payload_len);


#ifdef WORDS_BIGENDIAN
# define SWAP(n) (n)
#else
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#endif

#define BLOCKSIZE 4096
#if BLOCKSIZE % 64 != 0
# error "invalid BLOCKSIZE"
#endif
void append_str(char *pmainstr, *pstr)
{
	sprintf(pmainstr, "%s%s",pmainstr,pstr);
}
int test_add(int a, int b)
{
	return a+b;
}

#if defined(PRODUCT_H31BG)
////////////////////////////////////////////////////////////////
//#include <signal.h>
static int g_auto_ota_count = 0;
static struct itimerval g_auto_ota_oldtv;
struct itimerval g_auto_ota_itv;

static int g_auto_ota_timer_delay=10; // second
static int g_auto_ota_timer_cyc=30; // 3600 second
static int g_auto_ota_start_time_hour=0; // 0~4
static int g_auto_ota_end_time_hour=4; // 0~4

static void get_timer_to_localtime()
{
  	time_t timep_utc;
	time_t timep_region;
  	struct tm* pTime_region = NULL;

	int  m_region = (g_p2ptnp_info.mmap_info->ts/3600);

	(void)time(&timep_utc);// timep_utc = time(NULL)
	timep_region =  timep_utc +  g_p2ptnp_info.mmap_info->ts; 
	pTime_region = localtime(&timep_region);

	if((NULL!=pTime_region))
	{
    	printf("%s(%d),region GMT+(%d),ts=%d,now utc2localtm is %04d-%02d-%02d %02d:%02d:%02d\r\n"
           ,_FU_, _L_,m_region,g_p2ptnp_info.mmap_info->ts
	       ,pTime_region->tm_year+1900, pTime_region->tm_mon+1, pTime_region->tm_mday, pTime_region->tm_hour, pTime_region->tm_min, pTime_region->tm_sec);
	}	

	return;
}


static void auto_ota_set_timer(int sec,int usec,int dsec,int dusec)
{
    printf("[H31BG_OTA] p2p_tnp.c %s(%d) sec=%d,usec=%d,dsec=%d,dusec=%d!\r\n",_FU_, _L_,sec,usec,dsec,dusec);	

    //Timeout to run first time
    g_auto_ota_itv.it_value.tv_sec = sec;
    g_auto_ota_itv.it_value.tv_usec = usec;   

    //After first, the Interval time for clock	
    g_auto_ota_itv.it_interval.tv_sec = dsec;
    g_auto_ota_itv.it_interval.tv_usec = dusec;

	// ITIMER_ Real indicates that the sigalrm signal will be triggered every time the timer wakes up
    setitimer(ITIMER_REAL, &g_auto_ota_itv, &g_auto_ota_oldtv); 

}

static void auto_ota_shut_timer()
{
	// disable and close this timer,set tv to zero 
    g_auto_ota_itv.it_value.tv_sec = 0;        
    g_auto_ota_itv.it_value.tv_usec = 0;
    g_auto_ota_itv.it_interval.tv_sec = 0;
    g_auto_ota_itv.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &g_auto_ota_itv, &g_auto_ota_oldtv);
}


int auto_ota_do_update()//int do_update(int index, UINT16 nIOCtrlCmdNum)
{
    char cmd[1024] = {0};
	char url[256] = {0};
	char md5[64] = {0};
    int success = 0;
	int ret = 0;
	g_download_t g_download_info;

	memset(&g_download_info, 0, sizeof(g_download_t));

	if(g_updatestat == 1)
	{
		return -1;
	}

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_do_update_begin");
#ifdef NOT_PLT_API
	success = get_update_url_md5(url, md5);
#else
	success = get_update_url_md5_QGopen(url, md5);
#endif
	if(success == 1)
	{
	    memset(cmd, 0, sizeof(cmd));
		snprintf(g_download_info.url, sizeof(g_download_info.url), "%s", url);
		snprintf(g_download_info.md5, sizeof(g_download_info.md5), "%s", md5);
		if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_DOWNLOAD_INFO, (char *)&g_download_info, sizeof(g_download_t)) < 0)
		{
			dump_string(_F_, _FU_, _L_, "p2p_set_download_info send_msg fail!\n");
		}
		printf("g_download_info.url =%s %s\n",g_download_info.url,g_download_info.md5);
		snprintf(cmd, sizeof(cmd), "killall upgrade_firmware;rm -f /home/%s;rm -f /tmp/sd/%s;rm -f /tmp/update/%s;/backup/tools/upgrade_firmware \"%s\" \"%s\" &",
                IMAGE_NAME, IMAGE_NAME, IMAGE_NAME,
                 url, md5);

		printf("[H31BG_OTA] p2p_tnp.c %s(%d) cmd%s\r\n",_FU_, _L_,cmd);	

		system(cmd);
		g_updatestat = 1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "cloudAPI get_update_url_md5 failed url = %s, md5 = %s\n", url, md5);
		g_updatestat = 4;
		return -2;
	}

	//ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_UPDATE_RSP, nIOCtrlCmdNum, g_p2ptnp_info.mmap_info->version, strlen(g_p2ptnp_info.mmap_info->version));
	//dump_string(_F_, _FU_, _L_,"IOTYPE_USER_IPCAM_UPDATE_RSP, ret = %d\n", ret);

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_do_update_end");

	return 0;
}


void auto_ota_signal_handler(int m)
{
	int ret = 0;
	unsigned char devMac[6]={0};
	int m_time = 0;	
	int m_hour = 0;
	int m_min = 0;
	int m_sec = 0;

  	time_t timep_utc;
	time_t timep_region;
  	struct tm* pTime_region = NULL;
	int  m_region = (g_p2ptnp_info.mmap_info->ts/3600);

    g_auto_ota_count ++;

	printf("[H31BG_OTA] p2p_tnp.c %s(%d) Cnt=%d,api_server[%s],version=%s\r\n",_FU_, _L_,g_auto_ota_count,g_p2ptnp_info.mmap_info->api_server,g_p2ptnp_info.mmap_info->version);	

	// 44:01:BB:EF:48:B6;
	sscanf(g_p2ptnp_info.mmap_info->mac, "%02x:%02x:%02x:%02x:%02x:%02x", &devMac[0], &devMac[1], &devMac[2], &devMac[3], &devMac[4], &devMac[5]); 
	m_time = (devMac[4] * devMac[5]);
	m_hour = (m_time/3600)%4;
	m_min = (m_time%3600)/60;	
	printf("[H31BG_OTA] p2p_tnp.c %s(%d) this dev mac[%s]=%02x:%02x:%02x:%02x:%02x:%02x\r\n",_FU_, _L_,g_p2ptnp_info.mmap_info->mac, devMac[0], devMac[1], devMac[2], devMac[3], devMac[4], devMac[5]);	
	printf("[H31BG_OTA] p2p_tnp.c %s(%d) this dev start do_update m_time=%d is %02d:%02d\r\n",_FU_, _L_,m_time,m_hour, m_min);	

	(void)time(&timep_utc);// timep_utc = time(NULL)
	timep_region =  timep_utc +  g_p2ptnp_info.mmap_info->ts; 
	pTime_region = localtime(&timep_region);

	if((NULL!=pTime_region))
	{
    	printf("[H31BG_OTA] p2p_tnp.c %s(%d),region GMT+(%d),ts=%d,now utc2localtm is %04d-%02d-%02d %02d:%02d:%02d\r\n"
           ,_FU_, _L_,m_region,g_p2ptnp_info.mmap_info->ts
	       ,pTime_region->tm_year+1900, pTime_region->tm_mon+1, pTime_region->tm_mday, pTime_region->tm_hour, pTime_region->tm_min, pTime_region->tm_sec);
	}
	if((g_auto_ota_start_time_hour <= pTime_region->tm_hour) && (pTime_region->tm_hour <= g_auto_ota_end_time_hour))
	{
		ret = auto_ota_do_update();
	}

	if(ret!=0)
	{
    	//auto_ota_shut_timer();
	}
}

int auto_ota_init_alarm_handler()
{
	printf("[H31BG_OTA] p2p_tnp.c %s(%d) ENTER!\r\n",_FU_, _L_);

    signal(SIGALRM, auto_ota_signal_handler);  //将SIGALRM信号与signal_handler函数建立关系,当信号触发时便会调用该函数.

	if(g_p2ptnp_info.mmap_info->auto_ota_enable == 1)
	{
		//auto_ota_set_timer(2,0,30,0);
		auto_ota_set_timer(g_auto_ota_timer_delay,0,g_auto_ota_timer_cyc,0);
	}
	else{
		auto_ota_shut_timer();	
	}

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////
///	p2p_ptz_set_motion_track(){}
///	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_SET_MOTION_TRACK, (char *)&motion_track_switch, sizeof(motion_track_switch)) < 0)
static int set_mic_audio(int index, SMsgAVIoctrlMicAudioReq *p_mic_audio_cfg, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlMicAudioReq rsp;
	int ret = 0;

	if(p_mic_audio_cfg == NULL){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_RECORD_MIC_REQ SMsgAVIoctrlMicAudioReq is NULL!\n");
		return -1;
	}

	rsp.enable  = ntohl(p_mic_audio_cfg->enable);// ntohl(p_mic_audio_cfg->enable); 
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_RECORD_MIC_REQ enable = 0x%08x = %d\n",p_mic_audio_cfg->enable,rsp.enable);

	//g_p2ptnp_info.mmap_info->mic_audio_enable  = rsp.enable;// mmap_info only read not write;p2p_tnp crashed
	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_MIC_AUDIO_ENABLE, (char *)&rsp.enable, sizeof(rsp.enable)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "DISPATCH_MIC_AUDIO_ENABLE send_msg fail!\n");
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_RECORD_MIC_RESP, nIOCtrlCmdNum, (char *)p_mic_audio_cfg, sizeof(SMsgAVIoctrlMicAudioReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_RECORD_MIC_RESP, ret = %d\n", ret);

	return ret;
}

static int get_mic_audio(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlMicAudioReq rsp;
	int ret = 0;

	rsp.enable = htonl(g_p2ptnp_info.mmap_info->mic_audio_enable);//htonl(g_p2ptnp_info.mmap_info->mic_audio_enable);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_RECORD_MIC_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlMicAudioReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_RECORD_MIC_RESP ret = %d,mic_audio_enable = 0x%08x = %d\n", ret,rsp.enable,g_p2ptnp_info.mmap_info->mic_audio_enable);

	return ret;
}

static int set_auto_ota(int index, SMsgAVIoctrlAutoOTAReq *p_auto_ota_cfg, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlAutoOTAReq rsp;
	int ret = 0;

	if(p_auto_ota_cfg == NULL){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AUTO_OTA_REQ SMsgAVIoctrlAutoOTAReq is NULL!\n");
		return -1;
	}

	rsp.enable  = ntohl(p_auto_ota_cfg->enable);//ntohl(p_auto_ota_cfg->enable);
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AUTO_OTA_REQ enable = 0x%08x = %d\n",p_auto_ota_cfg->enable,rsp.enable);

	//g_p2ptnp_info.mmap_info->auto_ota_enable  = rsp.enable; // mmap_info only read not write;p2p_tnp crashed
	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_AUTO_OTA_ENABLE, (char *)&rsp.enable, sizeof(rsp.enable)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "DISPATCH_AUTO_OTA_ENABLE send_msg fail!\n");
	}

	if(rsp.enable == 1)
	{
		//auto_ota_set_timer(2,0,30,0);
		auto_ota_set_timer(g_auto_ota_timer_delay,0,g_auto_ota_timer_cyc,0);
	}
	else
	{
		auto_ota_shut_timer();	
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_AUTO_OTA_RESP, nIOCtrlCmdNum, (char *)p_auto_ota_cfg, sizeof(SMsgAVIoctrlAutoOTAReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AUTO_OTA_RESP, ret = %d\n", ret);

	return ret;
}

static int get_auto_ota(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlAutoOTAReq rsp;
	int ret = 0;

	rsp.enable = htonl(g_p2ptnp_info.mmap_info->auto_ota_enable);//htonl(g_p2ptnp_info.mmap_info->auto_ota_enable);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_AUTO_OTA_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlAutoOTAReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_AUTO_OTA_RESP ret = %d,enable = 0x%08x = %d\n", ret,rsp.enable,g_p2ptnp_info.mmap_info->auto_ota_enable);
	return ret;
}

static int set_motion_detection(int index, SMsgAVIoctrlMotionDetectionReq *p_motion_detection_cfg, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlMotionDetectionReq rsp;
	int ret = 0;

	if(p_motion_detection_cfg == NULL){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_MOTION_DETECTION_REQ SMsgAVIoctrlAutoOTAReq is NULL!\n");
		return -1;
	}

	rsp.enable  = ntohl(p_motion_detection_cfg->enable);
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_MOTION_DETECTION_REQ enable = 0x%08x = %d\n",p_motion_detection_cfg->enable,rsp.enable);

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_MOTION_DETECTION_ENABLE, (char *)&rsp.enable, sizeof(rsp.enable)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "DISPATCH_MOTION_DETECTION_ENABLE send_msg fail!\n");
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_MOTION_DETECTION_RESP, nIOCtrlCmdNum, (char *)p_motion_detection_cfg, sizeof(SMsgAVIoctrlMotionDetectionReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_MOTION_DETECTION_RESP, ret = %d\n", ret);

	return ret;
}

static int get_motion_detection(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlMotionDetectionReq rsp;
	int ret = 0;

	rsp.enable = htonl(g_p2ptnp_info.mmap_info->motion_detection_enable);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_MOTION_DETECTION_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlMotionDetectionReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_MOTION_DETECTION_RESP ret = %d,enable = 0x%08x = %d\n", ret,rsp.enable,g_p2ptnp_info.mmap_info->motion_detection_enable);
	return ret;
}

static int p2p_set_new_wifi(int index,SMsgAVIoctrlNewWifiReq *p_new_wifi_info, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlNewWifiReq rsp;
	int ret = 0;

	if(p_new_wifi_info == NULL){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_NEW_WIFI_REQ SMsgAVIoctrlNewWifiReq is NULL!\n");
		return -1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_NEW_WIFI_REQ p_new_wifi_info->ssid is %s, p_new_wifi_info->password is %s!\n",p_new_wifi_info->ssid,p_new_wifi_info->password);
	}
	
	memset(&rsp, 0, sizeof(rsp));
	snprintf(rsp.ssid, sizeof(rsp.ssid), "%s", p_new_wifi_info->ssid);
	snprintf(rsp.password, sizeof(rsp.password), "%s", p_new_wifi_info->password);
	dump_string(_F_, _FU_, _L_, " rsp.ssid is %s, rsp.password is %s!\n",rsp.ssid,rsp.password);
	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_NEW_WIFI_CONF, (char *)&rsp, sizeof(rsp)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "DISPATCH_SET_NEW_WIFI_CONF send_msg fail!\n");
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_NEW_WIFI_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlNewWifiReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_NEW_WIFI_RESP, ret = %d\n", ret);

	return ret;
}

static int set_water_mark(int index, SMsgAVIoctrlWatermarkReq *p_water_mark_cfg, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlWatermarkReq rsp;
	int ret = 0;

	if(p_water_mark_cfg == NULL){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AUTO_OTA_REQ SMsgAVIoctrlWatermarkReq is NULL!\n");
		return -1;
	}

	rsp.enable  = ntohl(p_water_mark_cfg->enable);// ntohl(p_mic_audio_cfg->enable); 
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AUTO_OTA_REQ enable = 0x%08x = %d\n",p_water_mark_cfg->enable,rsp.enable);

	//g_p2ptnp_info.mmap_info->mic_audio_enable  = rsp.enable;// mmap_info only read not write;p2p_tnp crashed
	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_WATER_MARK_CONF, (char *)&rsp.enable, sizeof(rsp.enable)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "DISPATCH_SET_WATER_MARK_CONF send_msg fail!\n");
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_AUTO_OTA_RESP, nIOCtrlCmdNum, (char *)p_water_mark_cfg, sizeof(SMsgAVIoctrlWatermarkReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AUTO_OTA_RESP, ret = %d\n", ret);

	return ret;
}

static int get_water_mark(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlWatermarkReq rsp;
	int ret = 0;

	rsp.enable = htonl(g_p2ptnp_info.mmap_info->water_mark_enable);//htonl(g_p2ptnp_info.mmap_info->mic_audio_enable);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_WATER_MARK_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlWatermarkReq));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_WATER_MARK_RESP ret = %d,water_mark_enable = 0x%08x = %d\n", ret,rsp.enable,g_p2ptnp_info.mmap_info->water_mark_enable);

	return ret;
}




static int set_del_timestamp(int index, unsigned int *tmdata, UINT16 tmlen, int nIOCtrlCmdNum)
{
	int  i = 0;
	unsigned int *pTimestamp =NULL;
	int ret = 0;

	if(tmdata == NULL){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_TIMESTAMP_REQ tmdata is NULL!\n");
		return -1;
	}

	if((tmlen%4) != 0){
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_TIMESTAMP_REQ tmlen is ERROR!\n");
		return -1;
	}

	pTimestamp = (unsigned int *)malloc(tmlen);

	for(i=0;i<(tmlen/4);i++)
	{
		*(pTimestamp+i)  = ntohl(*(tmdata+i));// ntohl(p_mic_audio_cfg->enable); 
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_TIMESTAMP_REQ pTimestamp[%d] = 0x%08x = %d\n",i,*(pTimestamp+i),*(pTimestamp+i));
	}

	//g_p2ptnp_info.mmap_info->mic_audio_enable  = rsp.enable;// mmap_info only read not write;p2p_tnp crashed
	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_DEL_TIMESTAMP, (char *)pTimestamp, tmlen) < 0)
	{
		dump_string(_F_, _FU_, _L_, "DISPATCH_SET_DEL_TIMESTAMP send_msg fail!\n");
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_TIMESTAMP_RESP, nIOCtrlCmdNum, (char *)tmdata, tmlen);
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_TIMESTAMP_RESP, ret = %d\n", ret);

	free(pTimestamp);
	return ret;
}

#endif //#if defined(PRODUCT_H31BG)



/* Initialize structure containing state of computation. */
void sha1_init_ctx (struct sha1_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
void sha1_process_block (const void *buffer, size_t len,
				struct sha1_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
void sha1_process_bytes (const void *buffer, size_t len,
				struct sha1_ctx *ctx);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 20 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF be correctly
   aligned for a 32 bits value.  */
void *sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf);


/* Put result from CTX in first 20 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha1_read_ctx (const struct sha1_ctx *ctx, void *resbuf);


/* Compute SHA1 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 20 bytes
   beginning at RESBLOCK.  */
int sha1_stream (FILE *stream, void *resblock);

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *sha1_buffer (const char *buffer, size_t len, void *resblock);


/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (RFC 1321, 3.1: Step 1)  */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };


/* Take a pointer to a 160 bit block of data (five 32 bit ints) and
   initialize it to the start constants of the SHA1 algorithm.  This
   must be called before using hash in the call to sha1_hash.  */
void
sha1_init_ctx (struct sha1_ctx *ctx)
{
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;
  ctx->E = 0xc3d2e1f0;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

/* Put result from CTX in first 20 bytes following RESBUF.  The result
   must be in little endian byte order.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32-bit value.  */
void *
sha1_read_ctx (const struct sha1_ctx *ctx, void *resbuf)
{
  ((uint32_t *) resbuf)[0] = SWAP (ctx->A);
  ((uint32_t *) resbuf)[1] = SWAP (ctx->B);
  ((uint32_t *) resbuf)[2] = SWAP (ctx->C);
  ((uint32_t *) resbuf)[3] = SWAP (ctx->D);
  ((uint32_t *) resbuf)[4] = SWAP (ctx->E);

  return resbuf;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32-bit value.  */
void *
sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf)
{
  /* Take yet unprocessed bytes into account.  */
  uint32_t bytes = ctx->buflen;
  size_t size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;

  /* Now count remaining bytes.  */
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  ctx->buffer[size - 2] = SWAP ((ctx->total[1] << 3) | (ctx->total[0] >> 29));
  ctx->buffer[size - 1] = SWAP (ctx->total[0] << 3);

  memcpy (&((char *) ctx->buffer)[bytes], fillbuf, (size - 2) * 4 - bytes);

  /* Process last bytes.  */
  sha1_process_block (ctx->buffer, size * 4, ctx);

  return sha1_read_ctx (ctx, resbuf);
}

/* Compute SHA1 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 16 bytes
   beginning at RESBLOCK.  */
int
sha1_stream (FILE *stream, void *resblock)
{
  struct sha1_ctx ctx;
  char buffer[BLOCKSIZE + 72];
  size_t sum;

  /* Initialize the computation context.  */
  sha1_init_ctx (&ctx);

  /* Iterate over full file contents.  */
  while (1)
    {
      /* We read the file in blocks of BLOCKSIZE bytes.  One call of the
	 computation function processes the whole buffer so that with the
	 next round of the loop another block can be read.  */
      size_t n;
      sum = 0;

      /* Read block.  Take care for partial reads.  */
      while (1)
	{
	  n = fread (buffer + sum, 1, BLOCKSIZE - sum, stream);

	  sum += n;

	  if (sum == BLOCKSIZE)
	    break;

	  if (n == 0)
	    {
	      /* Check for the error flag IFF N == 0, so that we don't
		 exit the loop after a partial read due to e.g., EAGAIN
		 or EWOULDBLOCK.  */
	      if (ferror (stream))
		return 1;
	      goto process_partial_block;
	    }

	  /* We've read at least one byte, so ignore errors.  But always
	     check for EOF, since feof may be true even though N > 0.
	     Otherwise, we could end up calling fread after EOF.  */
	  if (feof (stream))
	    goto process_partial_block;
	}

      /* Process buffer with BLOCKSIZE bytes.  Note that
			BLOCKSIZE % 64 == 0
       */
      sha1_process_block (buffer, BLOCKSIZE, &ctx);
    }

 process_partial_block:;

  /* Process any remaining bytes.  */
  if (sum > 0)
    sha1_process_bytes (buffer, sum, &ctx);

  /* Construct result in desired memory.  */
  sha1_finish_ctx (&ctx, resblock);
  return 0;
}

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void *
sha1_buffer (const char *buffer, size_t len, void *resblock)
{
  struct sha1_ctx ctx;

  /* Initialize the computation context.  */
  sha1_init_ctx (&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  sha1_process_bytes (buffer, len, &ctx);

  /* Put result in desired memory area.  */
  return sha1_finish_ctx (&ctx, resblock);
}

void
sha1_process_bytes (const void *buffer, size_t len, struct sha1_ctx *ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      memcpy (&((char *) ctx->buffer)[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 64)
	{
	  sha1_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

	  ctx->buflen &= 63;
	  /* The regions in the following copy operation cannot overlap.  */
	  memcpy (ctx->buffer,
		  &((char *) ctx->buffer)[(left_over + add) & ~63],
		  ctx->buflen);
	}

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 64)
    {
#if !_STRING_ARCH_unaligned
# define alignof(type) offsetof (struct { char c; type x; }, x)
# define UNALIGNED_P(p) (((size_t) p) % alignof (uint32_t) != 0)
      if (UNALIGNED_P (buffer))
	while (len > 64)
	  {
	    sha1_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
	    buffer = (const char *) buffer + 64;
	    len -= 64;
	  }
      else
#endif
	{
	  sha1_process_block (buffer, len & ~63, ctx);
	  buffer = (const char *) buffer + (len & ~63);
	  len &= 63;
	}
    }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0)
    {
      size_t left_over = ctx->buflen;

      memcpy (&((char *) ctx->buffer)[left_over], buffer, len);
      left_over += len;
      if (left_over >= 64)
	{
	  sha1_process_block (ctx->buffer, 64, ctx);
	  left_over -= 64;
	  memcpy (ctx->buffer, &ctx->buffer[16], left_over);
	}
      ctx->buflen = left_over;
    }
}

/* --- Code below is the primary difference between md5.c and sha1.c --- */

/* SHA1 round constants */
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

/* Round functions.  Note that F2 is the same as F4.  */
#define F1(B,C,D) ( D ^ ( B & ( C ^ D ) ) )
#define F2(B,C,D) (B ^ C ^ D)
#define F3(B,C,D) ( ( B & C ) | ( D & ( B | C ) ) )
#define F4(B,C,D) (B ^ C ^ D)

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.
   Most of this code comes from GnuPG's cipher/sha1.c.  */
#define rol(x, n) (((x) << (n)) | ((uint32_t) (x) >> (32 - (n))))

#define M(I) ( tm =   x[I&0x0f] ^ x[(I-14)&0x0f] \
                ^ x[(I-8)&0x0f] ^ x[(I-3)&0x0f] \
               , (x[I&0x0f] = rol(tm, 1)) )

#define R(A,B,C,D,E,F,K,M)  do { E += rol( A, 5 )     \
                          + F( B, C, D )  \
                          + K         \
                          + M;        \
                     B = rol( B, 30 );    \
                       } while(0)

void
sha1_process_block (const void *buffer, size_t len, struct sha1_ctx *ctx)
{
  const uint32_t *words = buffer;
  size_t nwords = len / sizeof (uint32_t);
  const uint32_t *endp = words + nwords;
  uint32_t x[16];
  uint32_t a = ctx->A;
  uint32_t b = ctx->B;
  uint32_t c = ctx->C;
  uint32_t d = ctx->D;
  uint32_t e = ctx->E;

  /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];


  while (words < endp)
    {
      uint32_t tm;
      int t;
      for (t = 0; t < 16; t++)
	{
	  x[t] = SWAP (*words);
	  words++;
	}

      R( a, b, c, d, e, F1, K1, x[ 0] );
      R( e, a, b, c, d, F1, K1, x[ 1] );
      R( d, e, a, b, c, F1, K1, x[ 2] );
      R( c, d, e, a, b, F1, K1, x[ 3] );
      R( b, c, d, e, a, F1, K1, x[ 4] );
      R( a, b, c, d, e, F1, K1, x[ 5] );
      R( e, a, b, c, d, F1, K1, x[ 6] );
      R( d, e, a, b, c, F1, K1, x[ 7] );
      R( c, d, e, a, b, F1, K1, x[ 8] );
      R( b, c, d, e, a, F1, K1, x[ 9] );
      R( a, b, c, d, e, F1, K1, x[10] );
      R( e, a, b, c, d, F1, K1, x[11] );
      R( d, e, a, b, c, F1, K1, x[12] );
      R( c, d, e, a, b, F1, K1, x[13] );
      R( b, c, d, e, a, F1, K1, x[14] );
      R( a, b, c, d, e, F1, K1, x[15] );
      R( e, a, b, c, d, F1, K1, M(16) );
      R( d, e, a, b, c, F1, K1, M(17) );
      R( c, d, e, a, b, F1, K1, M(18) );
      R( b, c, d, e, a, F1, K1, M(19) );
      R( a, b, c, d, e, F2, K2, M(20) );
      R( e, a, b, c, d, F2, K2, M(21) );
      R( d, e, a, b, c, F2, K2, M(22) );
      R( c, d, e, a, b, F2, K2, M(23) );
      R( b, c, d, e, a, F2, K2, M(24) );
      R( a, b, c, d, e, F2, K2, M(25) );
      R( e, a, b, c, d, F2, K2, M(26) );
      R( d, e, a, b, c, F2, K2, M(27) );
      R( c, d, e, a, b, F2, K2, M(28) );
      R( b, c, d, e, a, F2, K2, M(29) );
      R( a, b, c, d, e, F2, K2, M(30) );
      R( e, a, b, c, d, F2, K2, M(31) );
      R( d, e, a, b, c, F2, K2, M(32) );
      R( c, d, e, a, b, F2, K2, M(33) );
      R( b, c, d, e, a, F2, K2, M(34) );
      R( a, b, c, d, e, F2, K2, M(35) );
      R( e, a, b, c, d, F2, K2, M(36) );
      R( d, e, a, b, c, F2, K2, M(37) );
      R( c, d, e, a, b, F2, K2, M(38) );
      R( b, c, d, e, a, F2, K2, M(39) );
      R( a, b, c, d, e, F3, K3, M(40) );
      R( e, a, b, c, d, F3, K3, M(41) );
      R( d, e, a, b, c, F3, K3, M(42) );
      R( c, d, e, a, b, F3, K3, M(43) );
      R( b, c, d, e, a, F3, K3, M(44) );
      R( a, b, c, d, e, F3, K3, M(45) );
      R( e, a, b, c, d, F3, K3, M(46) );
      R( d, e, a, b, c, F3, K3, M(47) );
      R( c, d, e, a, b, F3, K3, M(48) );
      R( b, c, d, e, a, F3, K3, M(49) );
      R( a, b, c, d, e, F3, K3, M(50) );
      R( e, a, b, c, d, F3, K3, M(51) );
      R( d, e, a, b, c, F3, K3, M(52) );
      R( c, d, e, a, b, F3, K3, M(53) );
      R( b, c, d, e, a, F3, K3, M(54) );
      R( a, b, c, d, e, F3, K3, M(55) );
      R( e, a, b, c, d, F3, K3, M(56) );
      R( d, e, a, b, c, F3, K3, M(57) );
      R( c, d, e, a, b, F3, K3, M(58) );
      R( b, c, d, e, a, F3, K3, M(59) );
      R( a, b, c, d, e, F4, K4, M(60) );
      R( e, a, b, c, d, F4, K4, M(61) );
      R( d, e, a, b, c, F4, K4, M(62) );
      R( c, d, e, a, b, F4, K4, M(63) );
      R( b, c, d, e, a, F4, K4, M(64) );
      R( a, b, c, d, e, F4, K4, M(65) );
      R( e, a, b, c, d, F4, K4, M(66) );
      R( d, e, a, b, c, F4, K4, M(67) );
      R( c, d, e, a, b, F4, K4, M(68) );
      R( b, c, d, e, a, F4, K4, M(69) );
      R( a, b, c, d, e, F4, K4, M(70) );
      R( e, a, b, c, d, F4, K4, M(71) );
      R( d, e, a, b, c, F4, K4, M(72) );
      R( c, d, e, a, b, F4, K4, M(73) );
      R( b, c, d, e, a, F4, K4, M(74) );
      R( a, b, c, d, e, F4, K4, M(75) );
      R( e, a, b, c, d, F4, K4, M(76) );
      R( d, e, a, b, c, F4, K4, M(77) );
      R( c, d, e, a, b, F4, K4, M(78) );
      R( b, c, d, e, a, F4, K4, M(79) );

      a = ctx->A += a;
      b = ctx->B += b;
      c = ctx->C += c;
      d = ctx->D += d;
      e = ctx->E += e;
    }
}

/* memxor.c -- perform binary exclusive OR operation of two memory blocks.
   Copyright (C) 2005, 2006 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by Simon Josefsson.  The interface was inspired by memxor
   in Niels M�ller's Nettle. */

void *
memxor (void * dest, const void * src, size_t n)
{
  char const *s = src;
  char *d = dest;

  for (; n > 0; n--)
    *d++ ^= *s++;

  return dest;
}

int
hmac_sha1 (const void *key, size_t keylen,
	   const void *in, size_t inlen, void *resbuf)
{
  struct sha1_ctx inner;
  struct sha1_ctx outer;
  char optkeybuf[20];
  char block[64];
  char innerhash[20];

  /* Reduce the key's size, so that it becomes <= 64 bytes large.  */

  if (keylen > 64)
    {
      struct sha1_ctx keyhash;

      sha1_init_ctx (&keyhash);
      sha1_process_bytes (key, keylen, &keyhash);
      sha1_finish_ctx (&keyhash, optkeybuf);

      key = optkeybuf;
      keylen = 20;
    }

  /* Compute INNERHASH from KEY and IN.  */

  sha1_init_ctx (&inner);

  memset (block, IPAD, sizeof (block));
  memxor (block, key, keylen);

  sha1_process_block (block, 64, &inner);
  sha1_process_bytes (in, inlen, &inner);

  sha1_finish_ctx (&inner, innerhash);

  /* Compute result from KEY and INNERHASH.  */

  sha1_init_ctx (&outer);

  memset (block, OPAD, sizeof (block));
  memxor (block, key, keylen);

  sha1_process_block (block, 64, &outer);
  sha1_process_bytes (innerhash, 20, &outer);

  sha1_finish_ctx (&outer, resbuf);

  return 0;
}

char * base64_encode( const unsigned char * bindata, char * base64, int binlength )
{
    int i, j;
    unsigned char current;

    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return base64;
}

CH_TYPE char_type(char ch)
{
    if(ch == '.')
        return CH_DOT;
    else if(ch == '_')
        return CH_UNLINE;
    else if(ch >= '0' && ch <= '9')
        return CH_DIGIT;
    else if(ch >= 'A' && ch <= 'Z')
        return CH_UPLETT;
    else
        return CH_UNKNOWN;
}

int p2p_checkbuf(unsigned session, unsigned char channel, unsigned int* WriteSize, unsigned int* ReadSize)
{
	int ret_val = 0;

	ret_val = PPPP_Check_Buffer(session, channel, WriteSize, ReadSize);

	if(ret_val >= 0)
	{
		//if((NULL!=WriteSize)&&(*WriteSize > 100*1024))
		{
			//printf("session(%d) channel(%d) WriteSize(%d)\n", session, channel, *WriteSize);
		}
	}
	else
	{
		if(NULL!=WriteSize)
		{
			*WriteSize = 0xfffffff;
		}
		if(NULL!=ReadSize)
		{
			*ReadSize = 0xfffffff;
		}
		//printf("check fail(%d) session(%d) channel(%d) WriteSize(%d)\n", ret_val, session, channel, *WriteSize);
	}

	return ret_val;
}
int check_url(char *url)
{
    int i = 0, j = 0;
    char *ptr = NULL;

    for(i = 0; i < LOAD_URL_FIXED_PART_NUM; i++)
    {
        if(memcmp(url, load_url_fixed_part_table[i], strlen(load_url_fixed_part_table[i])) == 0)
        {
            ptr = url + strlen(load_url_fixed_part_table[i]);

            if(strlen(ptr) != LOAD_URL_VERSION_PART_LEN)
                continue;

            for(j = 0; j < LOAD_URL_VERSION_PART_LEN; j++)
            {
                if(char_type(ptr[j]) != vesion_char_map[j])
                    break;
            }

            if(j == LOAD_URL_VERSION_PART_LEN)
                return 0;
        }
    }

    return -1;
}

void tnp_calc_timecost_init(struct timeval *g_tv)
{
	(void)gettimeofday(g_tv, NULL);
    return;
}

int tnp_calc_timecost_result(struct timeval *g_tv)
{
	struct timeval tv_now;
	(void)gettimeofday(&tv_now, NULL);
    return ((int)(tv_now.tv_sec-g_tv->tv_sec)*1000+(int)(tv_now.tv_usec-g_tv->tv_usec)/1000);
}

void printf_withtime(const char* string, int level, ...)
{
    //if(level>=PRINTLEVEL)
    {
        va_list arg_ptr;
        time_t timep;
        struct tm* p=NULL;
        struct timeval tv;
        char   loginfo[MQ_MAX_MSG_SIZE-sizeof(COM_MSGHD_t)];
        //char* s_ptr = NULL;

        if(NULL==string)
            return;

        time(&timep);
        p = localtime(&timep);
        gettimeofday(&tv, NULL);

        fprintf(stdout, "PPPP MOD [%d:%d:%d.%06d]", p->tm_hour, p->tm_min, p->tm_sec, (int)tv.tv_usec);

        va_start(arg_ptr, level);
        //s_ptr = va_arg(arg_ptr, char*);
        vfprintf(stdout, string, arg_ptr);
        vsnprintf(loginfo, sizeof(loginfo), string, arg_ptr);
        va_end(arg_ptr);
        fflush(stdout);
        //send_log_msg(g_dispatch_mqfd, level, loginfo);
    }
    return;
}

int CreatEventlogShareMem(void)
{
    int fd = -1;

    /* �¼���Ϣ�Ĺ����ڴ� */
    fd = open(RECORD_EVENT_MMAP, O_RDONLY);
    if(fd == -1)
    {
        return -1;
    }

    gEventLog = (record_event_info_t *) mmap( NULL, sizeof(record_event_info_t), PROT_READ, MAP_SHARED, fd, 0);

    close(fd);

    if (MAP_FAILED == gEventLog)
    {
        return -1;
    }

    return 0;
}


unsigned int get_cur_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec*1000 + tv.tv_usec/1000;
}

/* ��������������n�� */
int event_log_get(unsigned long startIndex, unsigned long num, record_event_t * pstRetBuf)
{
    int i;
    int realStart;
    memset(pstRetBuf,  0, (sizeof(record_event_t) * num));

    realStart = (MAX_RECORD_EVENT+gEventLog->head-startIndex)%MAX_RECORD_EVENT;
    if((0==gEventLog->num)||((realStart>gEventLog->head)&&(realStart<gEventLog->tail)))
    {
        dump_string(_F_, _FU_, _L_, "event_log_get: param is error, findNumber %d, head(%d) tail(%d) num(%d)!!! \n",
			realStart, gEventLog->head, gEventLog->tail, gEventLog->num);
        return 0;
    }

    //UIPrint("event_log_get: findNumber %d, startIndex %d, num %d, buf 0x%x, realStart %d ! \n",  PRINTLEVEL, findNumber, startIndex, num, pstRetBuf, realStart);

	#if 0
	dump_string(_F_, _FU_, _L_, "event_log_get: param is ok, findNumber %d, head(%d) tail(%d) num(%d)!!! \n",
		realStart, gEventLog->head, gEventLog->tail, gEventLog->num);
	#endif
    i = 0;

    for (i=0; i<num ; i++)
    {
        pstRetBuf[i].start_time = gEventLog->event[realStart].start_time;
		pstRetBuf[i].end_time = gEventLog->event[realStart].end_time;
		realStart -= 1;
		realStart = (realStart+MAX_RECORD_EVENT)%MAX_RECORD_EVENT;
		//dump_string(_F_, _FU_, _L_, "i(%d) realStart(%d) pstRetBuf[i].start_time(%d) pstRetBuf[i].end_time(%d)\n", i, realStart, pstRetBuf[i].start_time, pstRetBuf[i].end_time);
    }

    return i;
}

int event_log_seach(unsigned long startTime, unsigned long endTime, unsigned long type, unsigned long* pnumber)
{
    *pnumber = 0;

    if (NULL == gEventLog)
    {
        CreatEventlogShareMem();
        if(NULL == gEventLog)
        {
            dump_string(_F_, _FU_, _L_, "event_log_seach: mem alloc fail \n");
            return -1;
        }
    }

	*pnumber = gEventLog->num;

    //UIPrint("event_log_seach: findNumber %d !\n", PRINTLEVEL, findNumber);
    return 0;
}

int init_replay_frame(unsigned char *buf, unsigned char **all_buf, char* filename, unsigned int* replaytime, unsigned int filetime, int fileDuration, int resolution, int replay_speed, mp4trackinfo* info, unsigned int max_buff_size, unsigned int *all_buff_size)
{
    mp4read_t mp4read = NULL;
	int max_sample_size = 0;
	int is_sync = 0;
	unsigned char *ptr = NULL;
	unsigned int temp_size = 0;
	unsigned int local_size = max_buff_size;
	int ret = 0;
	unsigned int tmp_duration = MIN(60*1000, fileDuration*1000);

	mp4read = mp4read_create();
    if (!mp4read || mp4read_open_file(mp4read, filename) < 0)
    {
    	dump_string(_F_, _FU_, _L_, "mp4read = %p\n", mp4read);
        dump_string(_F_, _FU_, _L_, "mp4read_open_file(filename = %s) failed!\n", filename);
        goto error;
    }

	info->handle = (void *)mp4read;
	info->videotrack = resolution+1;
	info->audiotrack = 1;
    if(replay_speed != 1)
    {
        #ifdef DISABLE_VIDEO_CH_FAST
        info->videotrack = 2;
		#else
		info->videotrack = 3;
		#endif
        info->audiotrack = 0;
    }
	//info->audio_timescale = 64;
	info->video_totalsample = mp4read_get_video_num_of_samples(mp4read, info->videotrack);
	info->audio_totalsample = mp4read_get_audio_num_of_samples(mp4read, info->audiotrack);
	//tmp_duration = mp4read_get_duration(mp4read);
	info->file_duration = tmp_duration;
	info->video_timescale = info->file_duration/MAX(1,info->video_totalsample);
	info->audio_timescale = info->file_duration/MAX(1,info->audio_totalsample);
	if(*replaytime > filetime)
	{
		info->video_sampleid = MAX(((*replaytime-filetime)%60)*1000/info->video_timescale, 1);
		info->audio_sampleid = MAX(((*replaytime-filetime)%60)*1000/info->audio_timescale, 1);
	}
	else
	{
		info->video_sampleid = 1;
		info->audio_sampleid = 1;
	}

	dump_string(_F_, _FU_, _L_, "tmp_duration(%d) video_totalsample(%d) audio_totalsample(%d) video_timescale(%d) audio_timescale(%d) "
		" video_sampleid(%d) audio_sampleid(%d) replaytime(%lu) filetime(%lu)\n",
			tmp_duration, info->video_totalsample, info->audio_totalsample, info->video_timescale, info->audio_timescale,
			info->video_sampleid, info->audio_sampleid, *replaytime, filetime);

    max_sample_size = mp4read_get_video_max_sample_size(mp4read, info->videotrack);
	if(max_sample_size > max_buff_size)
	{
		temp_size = *all_buff_size;
		*all_buff_size = (max_sample_size + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t))/4*4+1024;
		ptr = malloc(*all_buff_size);
		if(!ptr)
		{
			dump_string(_F_, _FU_, _L_, "malloc(all_buff_size = %d) failed!\n", *all_buff_size);
			*all_buff_size = temp_size;
			goto error;
		}
		else
		{
			dump_string(_F_, _FU_, _L_, "realloc ok, all_buff_size = %d\n", *all_buff_size);
			memcpy(ptr, *all_buf, temp_size);
			free(*all_buf);
			*all_buf = ptr;
			buf = *all_buf + (temp_size - max_buff_size);
			local_size = *all_buff_size - (temp_size - max_buff_size);
		}
	}

	while(1)
	{
		ret = mp4read_read_video_sample(info->handle, info->videotrack, info->video_sampleid, buf, local_size, &is_sync);

		if(ret <= 0)
		{
			dump_string(_F_, _FU_, _L_, "MP4ReadSample fail video_sampleid(%d) ret(%d) bufsize(%d)\n", info->video_sampleid,
				ret, local_size);
			break;
		}

		if(is_sync == 1)
		{
			dump_string(_F_, _FU_, _L_, "got i frame\n");
			break;
		}

		info->video_sampleid++;
		if(info->video_sampleid > info->video_totalsample)
		{
			break;
		}
	}

	info->start_ms = get_cur_ms();
	info->video_init_sampleid = info->video_sampleid;
	info->audio_init_sampleid = info->audio_sampleid;

	*replaytime = filetime;

	return ret;

	error:

	if (mp4read)
	{
		mp4read_close_file(mp4read);
		mp4read_destroy(mp4read);
	}

	return -1;
}

int close_replay_frame(mp4trackinfo* info)
{
    if(info->handle != NULL)
    {
        mp4read_close_file((mp4read_t)info->handle);
        mp4read_destroy((mp4read_t)info->handle);
		info->handle = NULL;
        dump_string(_F_, _FU_, _L_, "close mp4file and destroy mp4read\n");
    }
    return 1;
}

static void revert_start_code(unsigned char *buf, int len)
{
    int size = buf[0] << 24;
    size |= buf[1] << 16;
    size |= buf[2] << 8;
    size |= buf[3];

    buf[0] = 0x00;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x01;

    if (4 + size + 4 <= len)
    {
        buf += 4 + size;
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x01;
    }
}

int get_video_replay_frame(unsigned char* buf, mp4trackinfo* info, unsigned int max_buff_size, int *is_sync, int replay_speed)
{
    int ret = 0;
    if(info->video_sampleid > info->video_totalsample)
    {
        dump_string(_F_, _FU_, _L_, "change file video_sampleid(%d) video_totalsample(%d)\n", info->video_sampleid, info->video_totalsample);
		close_replay_frame(info);
        return -1;
    }

    if(replay_speed < 1)
    {
        replay_speed = 1;
    }

    if(info->handle != NULL)
    {
        unsigned int ms_gap = get_cur_ms()-info->start_ms;

        if(ms_gap > ((info->video_sampleid-info->video_init_sampleid)*(info->video_timescale/replay_speed)))
        {
			//dump_string(_F_, _FU_, _L_, "handle(%d) videotrack(%d) video_sampleid(%d) \n", info->handle, info->videotrack, info->video_sampleid);
			ret = mp4read_read_video_sample(info->handle, info->videotrack, info->video_sampleid, buf, max_buff_size, is_sync);
            if(ret > 0)
            {
                info->video_sampleid++;
                ///buf[0]=0;buf[1]=0;buf[2]=0;buf[3]=1;
                revert_start_code(buf, ret);
                //dump_mem("mp4 video frame", ret, buf, 16);
                ret += 4;
            }
            else
            {
                ret = 0;
            }
        }
    }

    return ret;
}

int get_audio_replay_frame(unsigned char* buf, mp4trackinfo* info, unsigned int max_buff_size)
{
	int ret=0;

    if(info->handle != NULL)
    {
        unsigned int ms_gap = get_cur_ms()-info->start_ms;
		unsigned char* audiobuf = buf+7;

        if(ms_gap >= ((info->audio_sampleid-info->audio_init_sampleid)*info->audio_timescale))
        {
            //dump_string(_F_, _FU_, _L_, "handle(%d) audiotrack(%d) audio_sampleid(%d)\n", info->handle, info->audiotrack, info->audio_sampleid);
			ret = mp4read_read_audio_sample(info->handle, info->audiotrack, info->audio_sampleid, audiobuf, max_buff_size - 7);
			if(ret > 0)
			{
				ret += 7;	/*add adts head*/
                info->audio_sampleid++;
				buf[0]=0xff;
				buf[1]=0xf1;
				buf[2]=0x60;
				//buf[2]=0x6c;
				buf[3]=0x40;
				//buf[3]=0x80;
				buf[4]=(ret&0x7FF) >> 3;
				buf[5]=((ret&7)<<5) + 0x1F;
				buf[6]=0xfc;
                //dump_mem("mp4 audio frame", bufsize, (char*)buf, 16);
            }
			else
			{
				ret = 0;
			}
        }
    }
    return ret;
}
#if 0
int must_get_next_video_frame(NAL_TYPE type, int chn, unsigned char *buffer, unsigned char **all_buffer, unsigned int size, unsigned int *all_size, int* index, _t_frame_attr* info)
{
    int ret = -1;
	unsigned int need_len = 0;
	unsigned char *ptr = NULL;
	unsigned int temp_size = 0;
    unsigned int local_size = size;

    while(1)
    {
        switch(type)
        {
            case NAL_SPS:
                ret = MediaDataVideoGetNewSPSFrame(chn, buffer, local_size, index, info);
                break;
            case NAL_PPS:
                ret = MediaDataVideoGetOldPPSFrame(chn, buffer, local_size, index, info);
                break;
            case NAL_IDR_SLICE:
                ret = MediaDataVideoGetOldIFrame(chn, buffer, local_size, index, info);
                break;
            default:
                //ret = MediaDataGetNextFrame(chn, buffer, *size, index, info);
				ret = MediaDataGetNextFrame_withlen(chn, buffer, local_size, &need_len, index, info);
				if(ret == -2)
				{
					temp_size = *all_size;
					*all_size = (need_len - local_size + temp_size)/4*4 + 1024;
					ptr = malloc(*all_size);
					if (!ptr)
					{
						dump_string(_F_, _FU_, _L_, "realloc(all_size = %d) failed!\n", *all_size);
						*all_size = temp_size;
						return -1;
					}
					else
					{
						dump_string(_F_, _FU_, _L_, "realloc ok, all_size = %d\n", *all_size);
						memcpy(ptr, *all_buffer, temp_size);
						free(*all_buffer);
						*all_buffer = ptr;
						buffer = *all_buffer + (temp_size - size);
						local_size = *all_size - (temp_size - size);
						continue;
					}
				}
                break;
        }
        if(0==ret)
        {
            break;
        }
        usleep(30*1000);
    }
    return 0;
}

int get_next_video_frame(NAL_TYPE type, int chn, unsigned char *buffer, unsigned char **all_buffer, unsigned int size, unsigned int *all_size, int* index, _t_frame_attr* info, int maydelay)
{
    int ret=-1;
	unsigned int need_len = 0;
    unsigned int ts = 0;
	unsigned char *ptr = NULL;
	unsigned int temp_size = 0;
    unsigned int local_size = size;

    while(1)
    {
        switch(type)
        {
            case NAL_SPS:
                ret = MediaDataVideoGetNewSPSFrame(chn, buffer, local_size, index, info);
                break;
            case NAL_PPS:
                ret = MediaDataVideoGetNewPPSFrame(chn, buffer, local_size, index, info);
                break;
            case NAL_IDR_SLICE:
                ret = MediaDataVideoGetNewIFrame(chn, buffer, local_size, index, info);
                break;
            default:
                //ret = MediaDataGetNextFrame(chn, buffer, size, index, info);
				ret = MediaDataGetNextFrame_withlen(chn, buffer, local_size, &need_len, index, info);
				if (ret >= 0)
                {
                    ret = MediaDataVideoGetNewestIFrameTs(chn, &ts);
                    if (ret >= 0)
                    {
                        if((0==maydelay)&&(ts > info->timestamp + 5000))
                        //if(0)
                        {
                            dump_string(_F_, _FU_, _L_, "chn %d: next frame timestamp 0x%lx < newest I 0x%x, delta %ld ms \n",
                                        chn, info->timestamp, ts, ts-info->timestamp);
                            ret = MediaDataVideoGetNewSPSFrame(chn, buffer, local_size, index, info);
                        }
                    }
                }
				else if(ret == -2)
				{
					temp_size = *all_size;
					*all_size = (need_len - local_size + temp_size)/4*4 + 1024;
					ptr = malloc(*all_size);
					if (!ptr)
					{
						dump_string(_F_, _FU_, _L_, "realloc(all_size = %d) failed!\n", *all_size);
						*all_size = temp_size;
						return -1;
					}
					else
					{
						dump_string(_F_, _FU_, _L_, "realloc ok, all_size = %d\n", *all_size);
						memcpy(ptr, *all_buffer, temp_size);
						free(*all_buffer);
						*all_buffer = ptr;
						buffer = *all_buffer + (temp_size - size);
						local_size = *all_size - (temp_size - size);
						continue;
					}
				}
                //return ret;
        }
        if(0==ret)
        {
            break;
        }
        usleep(30*1000);
    }
    return 0;
}

int get_next_audio_frame(NAL_TYPE type, unsigned char* buffer, int size, int* index, _t_frame_attr* info, unsigned int ts)
{
    int ret=-1;
    while(1)
    {
        switch(type)
        {
            case NAL_AUD:
                //ret = MediaDataAudioGetByTs(MMAP_CHN_AUD, buffer, size, ts, index, info);
                ret = MediaDataAudioGetNewFrame(MMAP_CHN_AUD,buffer, size,index, info);
                break;
            default:
                ret = MediaDataGetNextFrame(MMAP_CHN_AUD, buffer, size, index, info);
                return ret;
        }
        if(0==ret)
        {
            break;
        }
        usleep(30*1000);
    }
    return 0;
}
#endif
int check_p2p_viewer()
{
	int user_index = 0;
	int got_usr = 0;

	for(user_index = 0; user_index < MAX_SESSION_NUM; user_index++)
	{
		if((USER_STATE_USED == g_p2ptnp_info.gUser[user_index].bUsed)&&
			(g_p2ptnp_info.gUser[user_index].bRecordPlay>0 || g_p2ptnp_info.gUser[user_index].bVideoRequested>0))
		{
			got_usr += 1;
			printf("p2p cur user %d SessionHandle(%d)\n", user_index, g_p2ptnp_info.gUser[user_index].SessionHandle);
		}
	}

	printf("p2p cur viewer(%d) max_user_num(%d) in_packet_loss(%d) out_packet_loss(%d)\n",
		got_usr, g_p2ptnp_info.max_user_num, g_p2ptnp_info.mmap_info->in_packet_loss,
		g_p2ptnp_info.mmap_info->out_packet_loss);
	return got_usr;
}

int p2p_send_msg(mqd_t mqfd, MSG_TYPE msg_type, char *payload, int payload_len)
{
    COM_MSGHD_t MsgHead;
    char send_buf[1024] = {0};
    int send_len = 0;
    int fsMsgRet = 0;

    memset(&MsgHead, 0, sizeof(MsgHead));
    MsgHead.srcMid = MID_P2P;
    MsgHead.mainOperation = msg_type;
    MsgHead.subOperation = 1;
    MsgHead.msgLength = payload_len;

    switch(msg_type)
    {
        case DISPATCH_SET_LIGHT_ON:
        case DISPATCH_SET_LIGHT_OFF:
        case DISPATCH_SET_POWER_ON:
        case DISPATCH_SET_POWER_OFF:
        case DISPATCH_SET_MOTION_RCD:
        case DISPATCH_SET_ALWAYS_RCD:
        case DISPATCH_SET_MIRROR_ON:
        case DISPATCH_SET_MIRROR_OFF:
		case RMM_SET_DAY_NIGHT_MODE:
		case RMM_APP_MODE_EARPHONE: //fengwu add 0425
        case RMM_APP_MODE_SPKER: //fengwu add 0425
		case RMM_SET_MOTION_DETECT:
        case RMM_SET_LDC:
        case RMM_SET_BABY_CRY:
		case RMM_SET_MIC_VOLUME:
		case RMM_SET_ENCODE_MODE:
		case RMM_SET_HIGH_RESOLUTION:
		case RMM_APP_AUDIO_MODE_SIMPLEX:
		case RMM_APP_AUDIO_MODE_DUPLEX:
        case RMM_SET_ABNORMAL_SOUND:
        case RMM_SET_ABNORMAL_SOUND_SENSITIVITY:
            MsgHead.dstBitmap = MID_RMM;
            break;

		case CLOUD_START_PANORAMA_CAPTURE:
		case CLOUD_ABORT_PANORAMA_CAPTURE:
        case CLOUD_DEBUG_P2P:
        case P2P_CHECK_CLOUD_NET:
            MsgHead.dstBitmap = MID_CLOUD;
            break;
        #ifdef YI_RTMP_CLIENT
        case DISPATCH_RTMP_CHANGE:
            MsgHead.dstBitmap = MID_RTMP;
            break;
        #endif
		#if defined(PRODUCT_H31BG)
        case DISPATCH_SET_DEL_TIMESTAMP:		
            MsgHead.dstBitmap = MID_RCD;
            break;	
		#endif//#if defined(PRODUCT_H31BG)				
        default:
            MsgHead.dstBitmap = MID_DISPATCH;
            break;
    }


    memcpy(send_buf, &MsgHead, sizeof(MsgHead));

	if((NULL!=payload)&&(payload_len>0))
	{
		memcpy(send_buf + sizeof(MsgHead), payload, payload_len);
	}

    send_len = sizeof(MsgHead) + payload_len;

    fsMsgRet = mqueue_send(mqfd, send_buf, send_len);

    return fsMsgRet;
}

int p2p_set_debug_info()
{
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, CLOUD_DEBUG_P2P, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_,  "p2p_set_debug_info send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_,  "p2p_set_debug_info send_msg ok!\n");
        return 0;
    }
}

void p2p_debug_log(int error, char *message)
{
    time_t cur_time = time(NULL);
    static time_t pre_debug_time = 0;
    static time_t error_message_time = 0;
    if(0 == pre_debug_time)
    {
        pre_debug_time = cur_time;
    }

    debug_string(DEBUG_INFO_TYPE_P2P_E, "mark=p2ptrack,time=%ld,%s", cur_time, message);

    if(0 == error)
    {
        if((error_message_time > 0) && (cur_time > (error_message_time + 1800)))
        {
            if(0 == p2p_set_debug_info())
            {
                error_message_time = 0;
            }
        }
    }
    else
    {
        if(cur_time > (pre_debug_time + 1800))
        {
            if(0 == p2p_set_debug_info())
            {
                error_message_time = 0;
                pre_debug_time = cur_time;
            }
        }
        else
        {
            if(0 == error_message_time)
            {
                error_message_time = cur_time;
            }
        }
    }
}

int p2p_set_power(MSG_TYPE msg_type)
{
	int count_down = 0;
	char value = -1;

	if(msg_type != DISPATCH_SET_POWER_ON && msg_type != DISPATCH_SET_POWER_OFF)
	{
		return -1;
	}

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, msg_type, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_power send_msg fail!\n");
        return -1;
    }
    else
    {
		dump_string(_F_, _FU_, _L_, "p2p_set_power send_msg ok!\n");

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->power_mode == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

int p2p_set_light(MSG_TYPE msg_type)
{
	int count_down = 0;
	char value = -1;

	if(msg_type != DISPATCH_SET_LIGHT_ON && msg_type != DISPATCH_SET_LIGHT_OFF)
	{
		return -1;
	}

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, msg_type, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_light send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_light send_msg ok!\n");

		count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->light_mode == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

        return 0;
    }
}

int p2p_set_motion_record(MSG_TYPE msg_type)
{
	int count_down = 0;
	char value = -1;

	if(msg_type != DISPATCH_SET_MOTION_RCD && msg_type != DISPATCH_SET_ALWAYS_RCD)
	{
		return -1;
	}

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, msg_type, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_motion_record send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_motion_record send_msg ok!\n");

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->record_mode == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

int p2p_set_mirror_flip(MSG_TYPE msg_type)
{
	int count_down = 0;
	char value = -1;

	if(msg_type != DISPATCH_SET_MIRROR_ON && msg_type != DISPATCH_SET_MIRROR_OFF)
	{
		return -1;
	}

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, msg_type, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_mirror_flip send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_mirror_flip send_msg ok!\n");

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->mirror == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

int p2p_set_motion_detect(int index, SMsAVIoctrlMotionDetectCfg *p_motion_cfg, int nIOCtrlCmdNum)
{
	int cnt_down = 0;
	motion_rect_t motion_rect = {0};
	SMsAVIoctrlMotionDetectCfg Rsp;
	int ret = 0;

	motion_rect.mode = ntohl(p_motion_cfg->mode);
	motion_rect.resolution = ntohl(p_motion_cfg->resolution);

	motion_rect.left = ntohl(p_motion_cfg->rect.top_left_x);
	motion_rect.top = 0 - ntohl(p_motion_cfg->rect.top_left_y);
	motion_rect.right = ntohl(p_motion_cfg->rect.bottom_right_x);
	motion_rect.bottom = 0 - ntohl(p_motion_cfg->rect.bottom_right_y);

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_MOTION_DETECT, (char *)&motion_rect, sizeof(motion_rect_t)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_motion_detect send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_motion_detect send_msg ok!\n");

    	cnt_down = 10;
		while(cnt_down)
		{
			if(g_p2ptnp_info.mmap_info->motion_rect.mode == motion_rect.mode &&
				g_p2ptnp_info.mmap_info->motion_rect.resolution == motion_rect.resolution &&
				g_p2ptnp_info.mmap_info->motion_rect.left == motion_rect.left &&
				g_p2ptnp_info.mmap_info->motion_rect.top == motion_rect.top &&
				g_p2ptnp_info.mmap_info->motion_rect.right == motion_rect.right &&
				g_p2ptnp_info.mmap_info->motion_rect.bottom == motion_rect.bottom)
			{
				break;
			}

			cnt_down--;
			usleep(100*1000);
		}
    }

	memset(&Rsp, 0, sizeof(SMsAVIoctrlMotionDetectCfg));
	Rsp.mode = htonl(g_p2ptnp_info.mmap_info->motion_rect.mode);
	Rsp.resolution = htonl(g_p2ptnp_info.mmap_info->motion_rect.resolution);
	Rsp.rect.top_left_x = htonl(g_p2ptnp_info.mmap_info->motion_rect.left);
	Rsp.rect.top_left_y = htonl(0 - g_p2ptnp_info.mmap_info->motion_rect.top);
	Rsp.rect.bottom_right_x = htonl(g_p2ptnp_info.mmap_info->motion_rect.right);
	Rsp.rect.bottom_right_y = htonl(0 - g_p2ptnp_info.mmap_info->motion_rect.bottom);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_MOTION_DETECT_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsAVIoctrlMotionDetectCfg));

	return ret;
}

int p2p_get_motion_detect(int index, int nIOCtrlCmdNum)
{
	SMsAVIoctrlMotionDetectCfg Rsp;
	int ret = 0;

	memset(&Rsp, 0, sizeof(SMsAVIoctrlMotionDetectCfg));
	Rsp.mode = htonl(g_p2ptnp_info.mmap_info->motion_rect.mode);
	Rsp.resolution = htonl(g_p2ptnp_info.mmap_info->motion_rect.resolution);
	Rsp.rect.top_left_x = htonl(g_p2ptnp_info.mmap_info->motion_rect.left);
	Rsp.rect.top_left_y = htonl(0 - g_p2ptnp_info.mmap_info->motion_rect.top);
	Rsp.rect.bottom_right_x = htonl(g_p2ptnp_info.mmap_info->motion_rect.right);
	Rsp.rect.bottom_right_y = htonl(0 - g_p2ptnp_info.mmap_info->motion_rect.bottom);

	p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_MOTION_DETECT_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsAVIoctrlMotionDetectCfg));

	return ret;
}

int p2p_set_alarm_mode(int alarm_mode)
{
	int count_down = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_HUMAN_MOTION, (char *)&alarm_mode, sizeof(alarm_mode)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_alarm_mode %d send_msg fail!\n", alarm_mode);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_alarm_mode %d send_msg ok!\n", alarm_mode);

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->human_motion_enable == alarm_mode)
			{
        		break;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

#ifdef HAVE_FEATURE_FACE
int p2p_set_human_face(int face_enable)
{
    int count_down = 0;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_HUMAN_FACE, (char *)&face_enable, sizeof(face_enable)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_human_face %d send_msg fail!\n", face_enable);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_human_face %d send_msg ok!\n", face_enable);
    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->human_face_enable == face_enable)
			{
                break;
			}
			usleep(100*1000);
		}
		return 0;
    }
}
#endif

int p2p_set_day_night_mode(MSG_TYPE msg_type, int value)
{
	int count_down = 0;

	if(msg_type != RMM_SET_DAY_NIGHT_MODE)
	{
		return -1;
	}

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, msg_type, (char *)&value, sizeof(value)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_day_night_mode %d send_msg fail!\n", value);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_day_night_mode %d send_msg ok!\n", value);

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->irlight_mode == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

int p2p_set_alarm_sensitivity(int sensitivity)
{
	int count_down = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_MOTION_SENSITIVITY, (char *)&sensitivity, sizeof(sensitivity)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_alarm_sensitivity %d send_msg fail!\n", sensitivity);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_alarm_sensitivity %d send_msg ok!\n", sensitivity);

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->motion_sensitivity == sensitivity)
			{
        		break;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

void p2p_set_audio_mode(int mode)
{
	if(mode == 1)
	{
		printf("\n\n[Peter] p2p RMM_APP_AUDIO_MODE_SIMPLEX mode\n\n");
		if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_APP_AUDIO_MODE_SIMPLEX, (char *)&mode, sizeof(mode)) < 0)
		{
			dump_string(_F_, _FU_, _L_, "RMM_APP_MODE_EARPHONE send_msg fail!\n");
		}
	}
	else if (mode == 2)
	{
		printf("\n\n[Peter] p2p RMM_APP_AUDIO_MODE_DUPLEX mode\n\n");
		if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_APP_AUDIO_MODE_DUPLEX, (char *)&mode, sizeof(mode)) < 0)
		{
			dump_string(_F_, _FU_, _L_, "RMM_APP_MODE_SPKER send_msg fail!\n");
		}

	}
	else
	{
		printf("\n\n[Peter] p2p other mode\n\n");
		dump_string(_F_, _FU_, _L_, "RMM_APP_MODE_SPKER mode error!\n");
	}
}


int p2p_set_video_backup_state(int index, video_backup_state_set *backup_state, int nIOCtrlCmdNum)
{
	video_backup_state_set_resp Rsp;
	int count_down = 0;

	memset(&Rsp, 0, sizeof(Rsp));

	if(backup_state->enable < 0 || backup_state->enable > 1 ||
		backup_state->backup_period < 0 || backup_state->backup_period > 3 ||
		backup_state->user_path < 0|| backup_state->user_path > 1)
	{
		Rsp.result = 1;
	}
	else
	{
		if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_VIDEO_BACKUP_STATE, (char *)backup_state, sizeof(video_backup_state_set_resp)) < 0)
		{
			dump_string(_F_, _FU_, _L_, "p2p_set_video_backup_state fail!\n");
			return -1;
		}

		count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->video_backup_info.enable == backup_state->enable &&
			g_p2ptnp_info.mmap_info->video_backup_info.resolution == backup_state->resolution &&
			g_p2ptnp_info.mmap_info->video_backup_info.backup_period == backup_state->backup_period &&
			g_p2ptnp_info.mmap_info->video_backup_info.user_path == backup_state->user_path)
			{
				break ;
			}
			usleep(100*1000);
		}

		Rsp.result = 0;
	}

	p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_VIDEO_BACKUP_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(Rsp));

	return 0;
}

int p2p_set_encode_mode(int value)
{
	int count_down = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_ENCODE_MODE, (char *)&value, sizeof(value)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_encode_mode %d send_msg fail!\n", value);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_encode_mode %d send_msg ok!\n", value);

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->encode_mode == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

int p2p_set_high_resolution(int value)
{
	int count_down = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_HIGH_RESOLUTION, (char *)&value, sizeof(value)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_high_resolution %d send_msg fail!\n", value);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_high_resolution %d send_msg ok!\n", value);

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->high_resolution == value)
			{
        		return 0;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

int p2p_get_video_backup_state(int index, int nIOCtrlCmdNum)
{
	video_backup_state_get_resp Rsp;

	memset(&Rsp, 0, sizeof(Rsp));

	if(g_p2ptnp_info.mmap_info->is_xiaomirouter == 0)
	{
		Rsp.is_mi_router = 0;
	}
	else
	{
		Rsp.is_mi_router = 1;
	}

	if(g_p2ptnp_info.mmap_info->tf_status.stat == TF_CHECK_OK)
	{
		Rsp.has_sd = 1;
	}
	else
	{
		Rsp.has_sd = 0;
	}

	Rsp.enable = g_p2ptnp_info.mmap_info->video_backup_info.enable;
	Rsp.resolution = g_p2ptnp_info.mmap_info->video_backup_info.resolution;
	Rsp.backup_period = g_p2ptnp_info.mmap_info->video_backup_info.backup_period;
	Rsp.user_path = g_p2ptnp_info.mmap_info->video_backup_info.user_path;
	Rsp.router_sd_total_size = htonl(g_p2ptnp_info.mmap_info->video_backup_info.router_sd_total_size);
	Rsp.router_sd_free_size = htonl(g_p2ptnp_info.mmap_info->video_backup_info.router_sd_free_size);
	Rsp.router_sd_cam_used_size = htonl(g_p2ptnp_info.mmap_info->video_backup_info.router_sd_cam_used_size);
	Rsp.extra_sd_total_size = htonl(g_p2ptnp_info.mmap_info->video_backup_info.extra_sd_total_size);
	Rsp.extra_sd_free_size = htonl(g_p2ptnp_info.mmap_info->video_backup_info.extra_sd_free_size);
	Rsp.extra_sd_cam_used_size = htonl(g_p2ptnp_info.mmap_info->video_backup_info.extra_sd_cam_used_size);

	p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_VIDEO_BACKUP_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(Rsp));

	return 0;
}

int p2p_send_connected()
{
	int ret = 0;

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_CONNECTTED, NULL, 0) < 0)
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_connected send_msg fail!\n");
		ret = -1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_connected send_msg ok!\n");
	}

	return ret;
}

int p2p_send_disconnected()
{
	int ret = 0;

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_DISCONNECTTED, NULL, 0) < 0)
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_disconnected send_msg fail!\n");
		ret = -1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_disconnected send_msg ok!\n");
	}

	return ret;
}

int p2p_send_viewing()
{
	int ret = 0;
	int viewer = check_p2p_viewer();

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_VIEWING, (char *)&viewer, sizeof(viewer)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_viewing send_msg fail!\n");
		ret = -1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_viewing send_msg ok!\n");
	}

	return ret;
}

int p2p_send_stop_viewing()
{
	int ret = 0;
	int viewer = check_p2p_viewer();

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_STOP_VIEWING, (char *)&viewer, sizeof(viewer)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_stop_viewing send_msg fail!\n");
		ret = -1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_stop_viewing send_msg ok!\n");
	}

	return ret;
}

int p2p_send_clr_viewing()
{
	int ret = 0;

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_CLR_VIEWING, NULL, 0) < 0)
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_clr_viewing send_msg fail!\n");
		ret = -1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "p2p_send_clr_viewing send_msg ok!\n");
	}

	return ret;
}

int p2p_set_tnp_init_status(TNP_INIT_STATUS_T stauts)
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_TNP_INIT_STATUS, (char *)&stauts, sizeof(stauts)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_tnp_init_status %d send_msg fail!\n", stauts);
		ret = -1;
    }
    else
    {
		dump_string(_F_, _FU_, _L_, "p2p_set_tnp_init_status %d send_msg ok!\n", stauts);
    }

	return ret;
}

int p2p_set_tnp_work_mode(TNP_WORK_MODE_T mode)
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_TNP_WORK_MODE, (char *)&mode, sizeof(mode)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_tnp_work_mode %d send_msg fail!\n", mode);
		ret = -1;
    }
    else
    {
		dump_string(_F_, _FU_, _L_, "p2p_set_tnp_work_mode %d send_msg ok!\n", mode);
    }

	return ret;
}


int p2p_set_tnp_check_login_success()
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_TNP_CHECK_LOGIN_SUCCESS, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_tnp_check_login_success send_msg fail!\n");
		ret = -1;
    }
    else
    {
		//dump_string(_F_, _FU_, _L_, "p2p_set_tnp_check_login_success send_msg ok!\n");
    }

	return ret;
}

int p2p_set_tnp_check_login_fail()
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_TNP_CHECK_LOGIN_FAIL, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_tnp_check_login_fail send_msg fail!\n");
		ret = -1;
    }
    else
    {
		//dump_string(_F_, _FU_, _L_, "p2p_set_tnp_check_login_fail send_msg ok!\n");
    }

	return ret;
}

int p2p_set_tnp_connect_success()
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_TNP_CONNECT_SUCCES, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_tnp_connect_success send_msg fail!\n");
		ret = -1;
    }
    else
    {
		//dump_string(_F_, _FU_, _L_, "p2p_set_tnp_connect_success send_msg ok!\n");
    }

	return ret;
}

int p2p_set_immediate_bitrate(int rate)
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_TNP_IMMEDIATE_BITRATE, (char *)&rate, sizeof(rate)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_immediate_bitrate %d send_msg fail!\n", rate);
		ret = -1;
    }
    else
    {
		//dump_string(_F_, _FU_, _L_, "p2p_set_immediate_bitrate send_msg ok!\n");
    }

	return ret;
}

int p2p_set_pwd_used_cnt()
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_PWD_USED_CNT, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_pwd_used_cnt send_msg fail!\n");
		ret = -1;
    }

	return ret;
}

int p2p_get_sd_state()
{
	int ret = 0;

	if(TF_CHECK_OK==g_p2ptnp_info.mmap_info->tf_status.stat)
	{
		ret = 0;
	}
	else if(TF_SPACE_TOO_LITTLE==g_p2ptnp_info.mmap_info->tf_status.stat)
	{
		ret = 4;
	}
	else if(TF_NOT_EXIST==g_p2ptnp_info.mmap_info->tf_status.stat)
	{
		ret = 5;
	}
	else if(TF_CARD_BADD==g_p2ptnp_info.mmap_info->tf_status.stat)
	{
		ret = 3;
	}
	else if(TF_SYSTEM_FORMAT_ERROR==g_p2ptnp_info.mmap_info->tf_status.stat)
	{
		ret = 2;
	}
	else if(TF_WRITE_SPEED_SLOW==g_p2ptnp_info.mmap_info->tf_status.stat)
	{
		ret = 1;
	}

    printf("hue, p2p_get_sd_state() return (%d) \n", ret);
	return ret;
}

int p2p_ptz_preset_add(int index, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlPTZPresetResp Rsp;
	char prev_preset_value[MAX_PTZ_PRESET] = {0};
	char prev_preset_count = 0, cur_preset_count = 0;
	int cnt_down = 50;
	unsigned int i = 0;
	short success = 0;
	int ret = 0;

	for(i = 0; i < MAX_PTZ_PRESET; i++)
	{
		if(g_p2ptnp_info.mmap_info->ptz_info[i].preset_enable == 1)
		{
			prev_preset_value[i] = 1;
			prev_preset_count++;
		}
	}

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_PRESET_ADD, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_preset_add send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		cur_preset_count = 0;
		for(i = 0; i < MAX_PTZ_PRESET; i++)
		{
			if(g_p2ptnp_info.mmap_info->ptz_info[i].preset_enable == 1)
			{
				cur_preset_count++;
			}
		}

		if(cur_preset_count == prev_preset_count + 1)
		{
			success = 1;
			break;
		}

		cnt_down--;
		usleep(20*1000);
	}

	memset(&Rsp, 0, sizeof(Rsp));
	cur_preset_count = 0;
	for(i = 0; i < MAX_PTZ_PRESET; i++)
	{
		if(g_p2ptnp_info.mmap_info->ptz_info[i].preset_enable == 1)
		{
			Rsp.preset.preset_value[i] = i + 1;
			cur_preset_count++;
			if(prev_preset_value[i] == 0)
			{
				Rsp.index  = htons(i + 1);
			}
		}
	}

	Rsp.result = htons(success);
	Rsp.preset.preset_count = cur_preset_count;

	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_PRESET_ADD_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsgAVIoctrlPTZPresetResp));

	return ret;
}

int p2p_ptz_preset_del(int index, int preset_id, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlPTZPresetResp Rsp;
	int preset_count = 0;
	int real_preset_id = 0;
	int cnt_down = 50;
	unsigned int i = 0;
	short success = 0;
	int ret = 0;

	real_preset_id = preset_id - 1;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_PRESET_DEL, (char *)&real_preset_id, sizeof(real_preset_id)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_preset_del send_msg fail!\n");
		ret = -1;
    }

	#if 1
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ptz_info[preset_id - 1].preset_enable == 0)
		{
			success = 1;
			break;
		}

		cnt_down--;
		usleep(20*1000);
	}
	#endif

	memset(&Rsp, 0, sizeof(Rsp));
	preset_count = 0;
	for(i = 0; i < MAX_PTZ_PRESET; i++)
	{
		if(g_p2ptnp_info.mmap_info->ptz_info[i].preset_enable == 1)
		{
			Rsp.preset.preset_value[i] = i + 1;
			preset_count++;

		}
	}

	Rsp.result = htons(success);
	Rsp.index  = htons(preset_id);
	Rsp.preset.preset_count = preset_count;

	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_PRESET_DEL_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsgAVIoctrlPTZPresetResp));

	return ret;
}

int p2p_ptz_preset_call(int index, int preset_id, int nIOCtrlCmdNum)
{
	SMsgAVIoctrlPTZPresetResp Rsp;
	int preset_count = 0;
	int real_preset_id = 0;
	unsigned int i = 0;
	short success = 0;
	int ret = 0;

	real_preset_id = preset_id - 1;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_PRESET_CALL, (char *)&real_preset_id, sizeof(real_preset_id)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_preset_call send_msg fail!\n");
		ret = -1;
    }

	memset(&Rsp, 0, sizeof(Rsp));
	preset_count = 0;
	for(i = 0; i < MAX_PTZ_PRESET; i++)
	{
		if(g_p2ptnp_info.mmap_info->ptz_info[i].preset_enable == 1)
		{
			Rsp.preset.preset_value[i] = i + 1;
			preset_count++;
		}
	}

	success = 1;
	Rsp.result = htons(success);
	Rsp.index  = htons(preset_id);
	Rsp.preset.preset_count = preset_count;

	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_PRESET_CALL_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsgAVIoctrlPTZPresetResp));

	return ret;
}

int p2p_ptz_set_cruise_stay_time(int index, unsigned int cruise_mode, unsigned int stay_time, int nIOCtrlCmdNum)
{
	ptz_cruise_time cruise_time;
	//int cnt_down = 50;
	int ret = 0;

	memset(&cruise_time, 0, sizeof(cruise_time));
	cruise_time.mode = cruise_mode;
	cruise_time.sleep = stay_time;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_SET_CURISE_STAY_TIME, (char *)&cruise_time, sizeof(cruise_time)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_set_cruise_stay_time send_msg fail!\n");
		ret = -1;
    }

	#if 0
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ptz_cruise_mode == cruise_mode && g_p2ptnp_info.mmap_info->ptz_sleep == stay_time)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}
	#endif

	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_SET_CURISE_STAY_TIME_RESP, nIOCtrlCmdNum, NULL, 0);

	return ret;
}

int p2p_ptz_set_cruise_period(int index, unsigned int start_time, unsigned int end_time, int nIOCtrlCmdNum)
{
	ptz_cruise_peroid cruise_period;
	//int cnt_down = 50;
	int ret = 0;

	memset(&cruise_period, 0, sizeof(cruise_period));
	cruise_period.start_time = start_time;
	cruise_period.end_time = end_time;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_SET_CURISE_PERIOD, (char *)&cruise_period, sizeof(cruise_period)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_set_cruise_period send_msg fail!\n");
		ret = -1;
    }

	#if 0
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ptz_cruise_start_time == start_time && g_p2ptnp_info.mmap_info->ptz_cruise_end_time == end_time)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}
	#endif

	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_SET_CRUISE_PERIOD_RESP, nIOCtrlCmdNum, NULL, 0);

	return ret;
}

int p2p_ptz_set_motion_track(int index, unsigned int motion_track_switch, int nIOCtrlCmdNum)
{
	//int cnt_down = 50;
	int ret = 0;

	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_SET_MOTION_TRACK, (char *)&motion_track_switch, sizeof(motion_track_switch)) < 0)
	{
		dump_string(_F_, _FU_, _L_, "p2p_ptz_set_motion_track send_msg fail!\n");
		ret = -1;
	}

	#if 0
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ptz_motion_track_switch == motion_track_switch)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}
	#endif
    #if !defined(HUMAN_MOTION_TRACK)
	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_SET_MOTION_TRACK_RESP, nIOCtrlCmdNum, NULL, 0);
    #else
    int cnt_down = 50;
    while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ptz_motion_track_switch == motion_track_switch)
		{
			break;
		}
		cnt_down--;
		usleep(20*1000);
	}
	int reply_dev_info(int index, ENUM_AVIOCTRL_MSGTYPE msg_type, UINT16 nIOCtrlCmdNum);
    reply_dev_info(index, IOTYPE_USER_PTZ_SET_MOTION_TRACK_RESP, nIOCtrlCmdNum);
    #endif

	return ret;

}

int p2p_ptz_set_cruise(int index, unsigned int cruise_switch, int nIOCtrlCmdNum)
{
	int ret = 0;

	if(cruise_switch == 1)
	{
	    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_CRUISE_START, NULL, 0) < 0)
	    {
	        dump_string(_F_, _FU_, _L_, "p2p_ptz_cruise_start send_msg fail!\n");
			ret = -1;
	    }
	}
	else if(cruise_switch == 0)
	{
	    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_CRUISE_STOP, NULL, 0) < 0)
	    {
	        dump_string(_F_, _FU_, _L_, "p2p_ptz_cruise_stop send_msg fail!\n");
			ret = -1;
	    }
	}

	p2p_send_ctrl_data(index, IOTYPE_USER_PTZ_SET_CRUISE_RESP, nIOCtrlCmdNum, NULL, 0);

	return ret;
}

int p2p_ptz_direction_ctrl(PTZ_DIRECTION direction, int speed)
{
	ptz_dir_ctrl dir_ctrl;
	int ret = 0;

	memset(&dir_ctrl, 0, sizeof(dir_ctrl));
	dir_ctrl.head.dstBitmap= MID_DISPATCH;
	dir_ctrl.head.mainOperation = DISPATCH_P2P_PTZ_DIRECTION_CTRL;
	dir_ctrl.head.msgLength = sizeof(dir_ctrl);
	dir_ctrl.head.srcMid = MID_P2P;
	dir_ctrl.head.subOperation = DISPATCH_P2P_PTZ_DIRECTION_CTRL;
	dir_ctrl.direction = direction;
	dir_ctrl.speed = speed;

    printf("hor:%d,ver:%d\r\n",g_p2ptnp_info.mmap_info->hw_ver.hor,g_p2ptnp_info.mmap_info->hw_ver.ver);
    printf("direction:%d\r\n",dir_ctrl.direction);
    //// normal is revert  ,,,, revert is normal...... fuck!!!!
	if(g_p2ptnp_info.mmap_info->hw_ver.hor == PTZ_DIR_REVERT)//hw config
	{
		if(dir_ctrl.direction == PTZ_DIRECTION_LEFT)
		{
			dir_ctrl.direction = PTZ_DIRECTION_LEFT;
		}
		else if(dir_ctrl.direction ==  PTZ_DIRECTION_RIGHT)
		{
			dir_ctrl.direction = PTZ_DIRECTION_RIGHT;
		}
	}
    else if(g_p2ptnp_info.mmap_info->hw_ver.hor == PTZ_DIR_NORMAL)
    {
        if(dir_ctrl.direction == PTZ_DIRECTION_LEFT)
		{
			dir_ctrl.direction = PTZ_DIRECTION_RIGHT;
		}
		else if(dir_ctrl.direction ==  PTZ_DIRECTION_RIGHT)
		{
			dir_ctrl.direction = PTZ_DIRECTION_LEFT;
		}
    }
    else
    {
    #if defined(SENSOR_MOUNT_SWAP) || defined(P2P_PTZ_H_MIRROR)
        if (direction == PTZ_DIRECTION_LEFT)
            dir_ctrl.direction = PTZ_DIRECTION_RIGHT;
        else if (direction ==  PTZ_DIRECTION_RIGHT)
            dir_ctrl.direction = PTZ_DIRECTION_LEFT;
    #endif
    }
    //// normal is revert  ,,,, revert is normal...... fuck(dispatch adjust again)!!!!
	if(g_p2ptnp_info.mmap_info->hw_ver.ver == PTZ_DIR_REVERT)//hw config
	{
		if(dir_ctrl.direction == PTZ_DIRECTION_UP)
		{
			dir_ctrl.direction = PTZ_DIRECTION_UP;
		}
		else if(dir_ctrl.direction ==  PTZ_DIRECTION_DOWN)
		{
			dir_ctrl.direction = PTZ_DIRECTION_DOWN;
		}
	}
    else if(g_p2ptnp_info.mmap_info->hw_ver.ver == PTZ_DIR_NORMAL)
    {
	    if(dir_ctrl.direction == PTZ_DIRECTION_UP)
		{
			dir_ctrl.direction = PTZ_DIRECTION_DOWN;
		}
		else if(dir_ctrl.direction ==  PTZ_DIRECTION_DOWN)
		{
			dir_ctrl.direction = PTZ_DIRECTION_UP;
		}
    }
    else
    {
    #ifdef P2P_PTZ_V_FLIP
        if (direction == PTZ_DIRECTION_UP)
            dir_ctrl.direction = PTZ_DIRECTION_DOWN;
        else if (direction ==  PTZ_DIRECTION_DOWN)
            dir_ctrl.direction = PTZ_DIRECTION_UP;
    #endif
    }

    if(g_p2ptnp_info.mmap_info->hw_ver.ptz_func == '2'){    //***uart_ptz_usd
        printf("hue, ptz_func('%c') \n", g_p2ptnp_info.mmap_info->hw_ver.ptz_func);
        //***������̨,p2p��������ֵ�����Ҫ��ת,�������
        if (direction == PTZ_DIRECTION_UP)
            dir_ctrl.direction = PTZ_DIRECTION_UP;
        else if (direction ==  PTZ_DIRECTION_DOWN)
            dir_ctrl.direction = PTZ_DIRECTION_DOWN;

        //if (direction == PTZ_DIRECTION_LEFT)
        //    dir_ctrl.direction = PTZ_DIRECTION_RIGHT;
        //else if (direction ==  PTZ_DIRECTION_RIGHT)
        //    dir_ctrl.direction = PTZ_DIRECTION_LEFT;
    }

    printf("direction:%d\r\n",dir_ctrl.direction);
    if(mqueue_send(g_p2ptnp_info.mqfd_dispatch, (char*)&dir_ctrl, sizeof(dir_ctrl)) < 0)
    {
        dump_string(_F_, _FU_, _L_,  "p2p_ptz_direction_ctrl send_msg fail!\n");
        ret = -1;
    }

	return ret;
}

int p2p_ptz_direction_ctrl_stop()
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_DIRECTION_CTRL_STOP, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_direction_ctrl_stop send_msg fail!\n");
		ret = -1;
    }

	return ret;
}

int p2p_ptz_home()
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_P2P_PTZ_HOME, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_ptz_home send_msg fail!\n");
		ret = -1;
    }

	return ret;
}

int p2p_ptz_jump_to_point(int transverse_proportion, int longitudinal_proportion)
{
	ptz_point_t ptz_point;
	int ret = 0;

	memset(&ptz_point, 0, sizeof(ptz_point));
	ptz_point.head.dstBitmap= MID_DISPATCH;
	ptz_point.head.mainOperation = DISPATCH_P2P_PTZ_JUMP_TO_POINT;
	ptz_point.head.msgLength = sizeof(ptz_point);
	ptz_point.head.srcMid = MID_P2P;
	ptz_point.head.subOperation = DISPATCH_P2P_PTZ_JUMP_TO_POINT;
	ptz_point.transverse_proportion = transverse_proportion;
	ptz_point.longitudinal_proportion = longitudinal_proportion;

    if(mqueue_send(g_p2ptnp_info.mqfd_dispatch, (char*)&ptz_point, sizeof(ptz_point)) < 0)
    {
        dump_string(_F_, _FU_, _L_,  "p2p_ptz_jump_to_point send_msg fail!\n");
        ret = -1;
    }

	return ret;
}

int p2p_set_panorama_capture_state(PANORAMA_CAPTURE_STATE state)
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_PANORAMA_CAPTURE_STATE, (char *)&state, sizeof(state)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_panorama_capture_state send_msg to dispatch fail!\n");
		ret = -1;
    }

	return ret;
}

int p2p_start_panorama_capture(int index, int nIOCtrlCmdNum)
{
	panorama_capture_start_resp resp;
	int cnt_down = 0;
	int ret  = 0;

	if(g_p2ptnp_info.mmap_info->panorama_capture_state == PANORAMA_CAPTURE_STATE_IDLE || g_p2ptnp_info.mmap_info->panorama_capture_state == PANORAMA_CAPTURE_STATE_FAIL)
	{
		if(g_p2ptnp_info.mmap_info->panorama_capture_state == PANORAMA_CAPTURE_STATE_FAIL)
		{
			p2p_set_panorama_capture_state(PANORAMA_CAPTURE_STATE_IDLE);

			while(cnt_down)
			{
				if(g_p2ptnp_info.mmap_info->panorama_capture_state == PANORAMA_CAPTURE_STATE_IDLE)
				{
					break;
				}

				cnt_down--;
				usleep(100*1000);
			}
		}

	    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, CLOUD_START_PANORAMA_CAPTURE, NULL, 0) < 0)
	    {
	        dump_string(_F_, _FU_, _L_, "p2p_start_panorama_capture send_msg to cloud fail!\n");
			ret = -1;
	    }
	}

	memset(&resp, 0, sizeof(resp));
	resp.state = htonl(g_p2ptnp_info.mmap_info->panorama_capture_state);

	p2p_send_ctrl_data(index, IOTYPE_USER_PANORAMA_CAPTURE_START_RSP, nIOCtrlCmdNum, (char *)&resp, sizeof(resp));

	return ret;
}

int p2p_abort_panorama_capture(int index, int nIOCtrlCmdNum)
{
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, CLOUD_ABORT_PANORAMA_CAPTURE, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_abort_panorama_capture send_msg to cloud fail!\n");
		ret = -1;
    }

	p2p_send_ctrl_data(index, IOTYPE_USER_PANORAMA_CAPTURE_ABORT_RSP, nIOCtrlCmdNum, NULL, 0);

	return ret;
}

int p2p_schedule_panorama_capture_report(int index, int nIOCtrlCmdNum)
{
	panorama_capture_schedule_resp resp;
	int percent = 0;
	int ret = 0;

	memset(&resp, 0, sizeof(resp));
	resp.state = htonl(g_p2ptnp_info.mmap_info->panorama_capture_state);
	percent = g_p2ptnp_info.mmap_info->panorama_capture_count*100/6;
	resp.percent = htonl(percent);
    resp.ptz_y_angle = htonl(g_p2ptnp_info.mmap_info->ptz_y_angle);

	p2p_send_ctrl_data(index, IOTYPE_USER_PANORAMA_CAPTURE_SCHEDULE_POLLING_RSP, nIOCtrlCmdNum, (char *)&resp, sizeof(resp));

	return ret;
}

int p2p_sync_info_from_server(int index, int nIOCtrlCmdNum)
{
	int ret = 0;
	char payload[4] = {0};

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SYNC_INFO_FROM_SERVER, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_sync_info_from_server send_msg fail!\n");
		ret = -1;
    }
    else
    {
		dump_string(_F_, _FU_, _L_, "p2p_sync_info_from_server send_msg ok!\n");
    }

	p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_TRIGGER_SYNC_INFO_FROM_SERVER_RESP, nIOCtrlCmdNum, payload, sizeof(payload));

	return ret;
}

int p2p_set_ldc(int percent)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_LDC, (char *)&percent, sizeof(percent)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_ldc send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ldc_percent == percent)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_baby_cry(int enable)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_BABY_CRY, (char *)&enable, sizeof(enable)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_baby_cry send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->baby_cry_enable == enable)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_abnormal_sound(int enable)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_ABNORMAL_SOUND, (char *)&enable, sizeof(enable)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_abnormal_sound send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->abnormal_sound_enable == enable)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_abnormal_sound_sensitivity(int value)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_ABNORMAL_SOUND_SENSITIVITY, (char *)&value, sizeof(value)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_abnormal_sound_sensitivity send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->abnormal_sound_sensitivity == value)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_mic_volume(int percent)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_SET_MIC_VOLUME, (char *)&percent, sizeof(percent)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_mic_volume send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->mic_volume == percent)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_viewpoint_trace(unsigned char mode)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_VIEWPOINT_TRACE, (char *)&mode, sizeof(mode)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_viewpoint_trace send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->viewpoint_trace == mode)
		{
			break;
		}

		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_voice_ctrl(unsigned char mode)
{
	int cnt_down = 50;
	int ret = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_VOICE_CTRL, (char *)&mode, sizeof(mode)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_voice_ctrl send_msg fail!\n");
		ret = -1;
    }

	while(cnt_down-- && (g_p2ptnp_info.mmap_info->voice_ctrl != mode))
	{
		usleep(100*1000);
	}

	return ret;
}

int p2p_set_lapse_video(int enable)
{
	int cnt_down = 50;
	int ret = 0;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_LAPSE_VIDEO, (char *)&enable, sizeof(enable)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_viewpoint_trace send_msg fail!\n");
		ret = -1;
    }
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->lapse_video_enable == enable)
		{
			break;
		}
		cnt_down--;
		usleep(100*1000);
	}
	return ret;
}

int p2p_set_white_led_mode(int mode)
{
	int cnt_down = 50;
	int ret = 0;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_WHITE_LED_MODE, (int *)&mode, sizeof(mode)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_white_led_mode send_msg fail!\n");
		ret = -1;
    }
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->white_led_mode == mode)
		{
			break;
		}
		cnt_down--;
		usleep(100*1000);
	}
	return ret;
}

int p2p_set_white_led_close(int flag)
{
	int cnt_down = 50;
	int ret = 0;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATH_SET_WHITE_LED_CLOSE, (int *)&flag, sizeof(flag)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "DISPATH_SET_WHITE_LED_CLOSE send_msg fail!\n");
		ret = -1;
    }
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->white_led_close == flag)
		{
			break;
		}
		cnt_down--;
		usleep(100*1000);
	}
	return ret;
}

int p2p_set_alarm(int status)
{
	int cnt_down = 50;
	int ret = 0;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_ALARM, (int *)&status, sizeof(status)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_alarm send_msg fail!\n");
		ret = -1;
    }
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->alarm == status)
		{
			break;
		}
		cnt_down--;
		usleep(100*1000);
	}
	return ret;
}

int p2p_set_soft_reset()
{
	int ret = 0;
    dump_string(_F_, _FU_, _L_, "p2p_set_soft_reset!\n");
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SOFT_REST, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_alarm send_msg fail!\n");
		ret = -1;
    }
	return ret;
}
int p2p_send_wifi_conf_msg(mqd_t mqfd, int mode, char* ssid, char* pwd, char* bind_key)
{
    wifi_conf_t msg;
    int fsMsgRet = 0;

    memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    //send msg to rmm
    msg.head.dstBitmap= MID_DISPATCH;
    msg.head.mainOperation = DISPATCH_SET_WIFI_CONF;
    msg.head.msgLength = 0;
    msg.head.srcMid = MID_P2P;
    msg.head.subOperation = DISPATCH_SET_WIFI_CONF;

    msg.conf_mode = mode;
    snprintf(msg.ssid, sizeof(msg.ssid), "%s", ssid);
    snprintf(msg.pwd, sizeof(msg.pwd), "%s", pwd);
    snprintf(msg.bind_key, sizeof(msg.bind_key), "%s", bind_key);

    if((fsMsgRet=mqueue_send(mqfd, (char*)&msg, sizeof(msg)))<0)
    {
        dump_string(_F_, _FU_, _L_, "msg snd err, err no is %d", fsMsgRet);
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "msg snd success");
    }

    return fsMsgRet;

}
int p2p_send_wifi_work_mode(mqd_t mqfd, int wifi_mode, char *ap_tnp_did)
{
    int fsMsgRet = 0;

    wifi_mode_t msg;
    memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    //send msg to rmm
    msg.head.dstBitmap= MID_DISPATCH;
    msg.head.mainOperation = RMM_SET_WIFI_WORK_MODE ;
    msg.head.msgLength = 0;
    msg.head.srcMid = MID_P2P;
    msg.head.subOperation = RMM_SET_WIFI_WORK_MODE;

    msg.wifi_mode = wifi_mode;
    snprintf(msg.ap_tnp_did, sizeof(msg.ap_tnp_did), "%s", ap_tnp_did);

    if((fsMsgRet=mqueue_send(mqfd, (char*)&msg, sizeof(msg)))<0)
    {
        dump_string(_F_, _FU_, _L_, "msg snd err, err no is %d", fsMsgRet);
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "msg snd success");
    }

    while(g_p2ptnp_info.mmap_info->wifi_mode != wifi_mode)
    {
        usleep(200*1000);
    }
    return fsMsgRet;
}

int reply_dev_info(int index, ENUM_AVIOCTRL_MSGTYPE msg_type, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlDeviceInfoResp Rsp;
	char preset_count = 0;
	char checkbuf[128]={0};
    char cmd[128] = {0};
	int i = 0;
	int ret = 0;
    int lapse_left_time = 0;

	memset(&Rsp, 0, sizeof(Rsp));

	Rsp.interface_version = 9;

	Rsp.language = g_p2ptnp_info.mmap_info->language;

	dump_string(_F_, _FU_, _L_, "g_p2ptnp_info.mmap_info->ts:%d\n", g_p2ptnp_info.mmap_info->ts);

	if(REGION_CHINA == g_p2ptnp_info.mmap_info->region_id)
	{
		Rsp.is_utc_time = 0;
	}
	else
	{
		Rsp.is_utc_time = 1;
	}
	dump_string(_F_, _FU_, _L_, "region_id:%d is_utc_time:%d\n", g_p2ptnp_info.mmap_info->region_id, Rsp.is_utc_time);

	Rsp.lossrate = g_p2ptnp_info.mmap_info->in_packet_loss;
	Rsp.update_without_tf = 1;

	#if defined(PRODUCT_R30GB) || defined(PRODUCT_R35GB) || defined(PRODUCT_H50GA) || defined(PRODUCT_H60GA)|| defined(PRODUCT_H31BG) || defined(PRODUCT_Y29GA) || defined(PRODUCT_R31GB)\
    || defined(PRODUCT_Y21GA) || defined(PRODUCT_Y28GA)|| defined(PRODUCT_H51GA) || defined(PRODUCT_H30GA) || defined(PRODUCT_H31GA) || defined(PRODUCT_H32GA)|| defined(PRODUCT_H52GA) || defined(PRODUCT_H53GA)\
    || defined(PRODUCT_LYR30) || defined(PRODUCT_R33GB)  || defined(PRODUCT_Y19GA) || defined(PRODUCT_Y26GA) || defined(PRODUCT_Y621)
		Rsp.hd_version =  HD_VER_R30GB;
	#else
		Rsp.hd_version = HD_VER_Y301GB;
	#endif

	Rsp.tfstat = p2p_get_sd_state();

	if(0==g_p2ptnp_info.mmap_info->day_night_mode)
	{
		Rsp.day_night_mode = 1;
	}
	else
	{
		Rsp.day_night_mode = g_p2ptnp_info.mmap_info->day_night_mode;
	}

	if(0 < (int)g_p2ptnp_info.mmap_info->in_packet_loss)
	{
		Rsp.internet_lossrate = 0;
	}
	else
	{
		Rsp.internet_lossrate = 0xff&(MAX(0,(0-(int)g_p2ptnp_info.mmap_info->in_packet_loss)));
	}

	Rsp.internet_visit = 0xff&g_is_internet;

	Rsp.check_stat = 0;

	Rsp.version = htonl(0);
	Rsp.channel = htonl(0);

	Rsp.total = htonl(g_p2ptnp_info.mmap_info->sd_size);

	Rsp.free = htonl(g_p2ptnp_info.mmap_info->sd_leftsize);

	Rsp.silentmode = g_p2ptnp_info.mmap_info->power_mode;
	Rsp.lightmode = g_p2ptnp_info.mmap_info->light_mode;
    Rsp.mirrorflip = g_p2ptnp_info.mmap_info->mirror;
	Rsp.alarm_sensitivity = g_p2ptnp_info.mmap_info->motion_sensitivity;
	Rsp.version_type = 0;
	Rsp.router_backup = 0;
	Rsp.ldc_percent = g_p2ptnp_info.mmap_info->ldc_percent;
	Rsp.baby_cry_enable = g_p2ptnp_info.mmap_info->baby_cry_enable;
	Rsp.mic_volume = g_p2ptnp_info.mmap_info->mic_volume;
	Rsp.frame_rate = 20;
	Rsp.encode_mode = g_p2ptnp_info.mmap_info->encode_mode;
	Rsp.high_resolution = g_p2ptnp_info.mmap_info->high_resolution;
	Rsp.viewpoint_trace = g_p2ptnp_info.mmap_info->viewpoint_trace;
	Rsp.voice_ctrl = g_p2ptnp_info.mmap_info->voice_ctrl;
    if(LAPSE_VIDEO_ON == g_p2ptnp_info.mmap_info->lapse_video_enable)
    {
        if(g_p2ptnp_info.mmap_info->lapse_video_end_time <= 0)
        {
            lapse_left_time = -1;
        }
        else if(g_p2ptnp_info.mmap_info->lapse_video_end_time > time(NULL))
        {
            lapse_left_time = g_p2ptnp_info.mmap_info->lapse_video_end_time - time(NULL);
        }
        else
        {
            lapse_left_time = 0;
        }
    }
    else
    {
        lapse_left_time = 0;
    }
    Rsp.lapse_left_time = htonl(lapse_left_time);

	if(1==g_updatestat)
	{
        snprintf(cmd, sizeof(cmd), "ls /tmp/update/%s -l|awk '{print $5}'", IMAGE_NAME);
		system_cmd_withret_timeout(cmd, checkbuf, sizeof(checkbuf), 60);
		if(atoi(checkbuf) > 0)
		{
			int getsize = atoi(checkbuf);
			#if defined(PRODUCT_B091QP)
			Rsp.update_percent = MIN(100, getsize*100/(2000*1000));
			#else
			Rsp.update_percent = MIN(100, getsize*100/(1*1000*1000));
			#endif
			if(Rsp.update_percent >= 100)
				g_updatestat = 2;
		}
		else
		{
			Rsp.update_percent = 0;
		}
	}

	dump_string(_F_, _FU_, _L_, "stStreamCtrl.update_percent(%d)\n", Rsp.update_percent);

	Rsp.update_stat = g_updatestat;
	Rsp.recordmode = g_p2ptnp_info.mmap_info->record_mode;
	Rsp.update_mode = 1;

	for(i = 0; i < MAX_PTZ_PRESET; i++)
	{
		if(g_p2ptnp_info.mmap_info->ptz_info[i].preset_enable == 1)
		{
			Rsp.preset.preset_value[i] = i + 1;
			preset_count++;
		}
	}
	Rsp.preset.preset_count = preset_count;

	Rsp.ptzinfo.motion_track_switch = g_p2ptnp_info.mmap_info->ptz_motion_track_switch;
	Rsp.ptzinfo.cruise_switch = g_p2ptnp_info.mmap_info->ptz_cruise_flag;
	Rsp.ptzinfo.cruise_mode = g_p2ptnp_info.mmap_info->ptz_cruise_mode;
	Rsp.ptzinfo.preset_cruise_stay_time = htonl(g_p2ptnp_info.mmap_info->ptz_sleep);
	Rsp.ptzinfo.panoramic_cruise_stay_time = htonl(g_p2ptnp_info.mmap_info->ptz_panoramic_sleep);
	Rsp.ptzinfo.start_time = htonl(g_p2ptnp_info.mmap_info->ptz_cruise_start_time);
	Rsp.ptzinfo.end_time = htonl(g_p2ptnp_info.mmap_info->ptz_cruise_end_time);

	Rsp.speak_mode = g_p2ptnp_info.mmap_info->speak_mode;

    Rsp.abnormal_sound = g_p2ptnp_info.mmap_info->abnormal_sound_enable;
    Rsp.abnormal_sound_sensitivity = g_p2ptnp_info.mmap_info->abnormal_sound_sensitivity;

    Rsp.alarm_mode = g_p2ptnp_info.mmap_info->human_motion_enable;
#ifdef HAVE_FEATURE_FACE
    #if !defined(NOT_PLT_API)
    Rsp.face_enable = htonl(g_p2ptnp_info.mmap_info->human_face_enable);
    #else
	Rsp.face_enable = g_p2ptnp_info.mmap_info->human_face_enable;
	#endif
#endif
    if(g_p2ptnp_info.mmap_info->white_led_mode == WHITE_LED_MODE_NONE)
        Rsp.white_led = WHITE_LED_MODE_OFF_E;
    else
        Rsp.white_led = g_p2ptnp_info.mmap_info->white_led_mode;
    Rsp.alarm_didi = g_p2ptnp_info.mmap_info->alarm;

#if defined(PRODUCT_H30GA) || defined(PRODUCT_H31GA) || defined(PRODUCT_H32GA) || defined(PRODUCT_H31BG)
    Rsp.alarm_ring = g_p2ptnp_info.mmap_info->alarm;
    Rsp.alarm_ring++;
#endif
    printf("white_led_mode =%d,alarm_didi = %d\n",g_p2ptnp_info.mmap_info->white_led_mode,g_p2ptnp_info.mmap_info->alarm);
	ret = p2p_send_ctrl_data(index, msg_type, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsgAVIoctrlDeviceInfoResp));
	dump_string(_F_, _FU_, _L_, "reply_dev_info, ret = %d\n", ret);

	return ret;
}

#if 1
int reply_aec_key_verify(int index, UINT16 nIOCtrlCmdNum)
{
	aec_key_verify_resp resp;
	int ret = 0;

	memset(&resp, 0, sizeof(resp));
	memcpy_s(resp.aec_key, 11, g_p2ptnp_info.mmap_info->aec_key, 11);
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERIFY_RESP, nIOCtrlCmdNum, (char *)&resp, sizeof(resp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERIFY_RESP, ret = %d\n", ret);

	return ret;
}
#else
int reply_aec_key_verify(int index, UINT16 nIOCtrlCmdNum, char *buf)
{
	aec_key_verify_resp resp;
	int ret = 0;

	memset(&resp, 0, sizeof(resp));
	memcpy_s(resp.aec_key, 11, buf, 11);
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERIFY_RESP, nIOCtrlCmdNum, (char *)&resp, sizeof(resp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERIFY_RESP, ret = %d\n", ret);

	return ret;
}
#endif


#ifdef AP_MODE
int p2p_set_ap_conf(unsigned char enable, char *ssid, char *pwd)
{
	int cnt_down = 50;
	int ret = 0;
    char tmp_ssid[32] = {0};
    char tmp_pwd[32] = {0};

    get_ap_conf(HOSTAPDCONF, tmp_ssid, tmp_pwd);
    if((strlen(ssid) == 0 && strcmp(pwd, tmp_pwd) == 0) || (strcmp(ssid, tmp_ssid) == 0 && strcmp(pwd, tmp_pwd)))
    {
        dump_string(_F_, _FU_, _L_, "set ap info same, ignore it.\n");
        return 0;
    }

    if(set_ap_conf(HOSTAPDCONF, ssid, pwd) != 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_ap_conf send_msg fail!\n");
        return -1;
    }
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_AP_ENABLE, &enable, sizeof(enable)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_ap_conf send_msg fail!\n");
		ret = -1;
    }
	while(cnt_down)
	{
		if(g_p2ptnp_info.mmap_info->ap_enable == enable)
		{
			break;
		}
		cnt_down--;
		usleep(100*1000);
	}

	return ret;
}

static unsigned int refresh_ping = 1;
int p2p_alert_days_refresh()
{
	int cnt_down = 500;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_REFRESH_ALRET_DAYS, (char *)&refresh_ping, sizeof(unsigned int)) < 0)
    {
        dump_string(_F_, _FU_, _L_,  "p2p refresh alarm days send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_,  "p2p refresh alarm days send_msg ok!\n");
        //return 0;
    }

    while(cnt_down){
        if(g_p2ptnp_info.mmap_info->refresh_pong == refresh_ping){
            break;
        }
        cnt_down--;
        usleep(10*1000);
    }

    if(++refresh_ping >= UINT_MAX - 1)//avoid overflow
        refresh_ping = 1;


    return 0;
}

int p2p_alert_event_refresh(int start_time, int end_time)
{
	int cnt_down = 500;
    alarm_event_info_t alarm_event_info;
    alarm_event_info.refresh_ping = refresh_ping;
    alarm_event_info.start_time = start_time;
    alarm_event_info.end_time = end_time;
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_REFRESH_ALRET_EVENT, (char *)&alarm_event_info, sizeof(alarm_event_info_t)) < 0)
    {
        dump_string(_F_, _FU_, _L_,  "p2p refresh alarm event send_msg fail!\n");
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_,  "p2p refresh alarm event send_msg ok!\n");
        //return 0;
    }

    while(cnt_down){
        if(g_p2ptnp_info.mmap_info->refresh_pong == refresh_ping){
            break;
        }
        cnt_down--;
        usleep(10*1000);
    }

    if(++refresh_ping >= UINT_MAX - 1)//avoid overflow
        refresh_ping = 1;

    return 0;
}

int reply_set_ap_conf(int index, UINT16 nIOCtrlCmdNum, char is_ok)//is_ok, 0:fail    1:success
{
    int ret = 0;
    char resp = is_ok;
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_AP_MODE_RESP, nIOCtrlCmdNum, &resp, sizeof(resp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_AP_MODE_RESP , is_ok: %d, ret = %d\n", is_ok, ret);
	return ret;
}

int reply_get_ap_conf(int index, UINT16 nIOCtrlCmdNum)
{
    SMsgAVIoctrlApConfResp resp;
	int ret = 0;
	memset(&resp, 0, sizeof(resp));
    resp.ap_enable = g_p2ptnp_info.mmap_info->ap_enable;
    get_ap_conf(HOSTAPDCONF, resp.ssid, resp.pwd);
    //printf("##hxq enable: %d, ssid: %s, pwd: %s\n", resp.ap_enable, resp.ssid, resp.pwd);
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_AP_MODE_RESP, nIOCtrlCmdNum, (char *)&resp, sizeof(resp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_AP_MODE_RESP , ret = %d\n", ret);
	return ret;
}

int reply_day_event_list(int index, UINT16 nIOCtrlCmdNum)
{
    int i = 0;
    int count = 0;
    int ret = 0;
    int resp_len = 0;
    alarm_day_ctx_t alarm_day_ctx;
    memset(&alarm_day_ctx, 0, sizeof(alarm_day_ctx_t));
    count = g_p2ptnp_info.mmap_info->alarm_day_ctx.day_count;
    alarm_day_ctx.day_count = htonl(count);
    for( ; i < count; i++){
        alarm_day_ctx.time[i] = htonl(g_p2ptnp_info.mmap_info->alarm_day_ctx.time[i]);
    }
    resp_len = sizeof(int) + count * sizeof(int);
    printf("##hxq alert days count: %d, resp_len: %d\n", count, resp_len);
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_DAY_EVENT_LIST_RESP, nIOCtrlCmdNum, (char *)&alarm_day_ctx, resp_len);
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_DAY_EVENT_LIST_RESP, ret = %d\n", ret);
	return ret;
}

int reply_alert_event_list(int index, UINT16 nIOCtrlCmdNum)
{
    int i = 0;
    int count = 0;
    int ret = 0;
    int resp_len;
    SMsgAVIoctrlAlertListEventResp resp;
    memset(&resp, 0, sizeof(resp));
    count = g_p2ptnp_info.mmap_info->alarm_event_ctx.num;
    printf("##hxq alert event count: %d\n", count);
    resp.count = htonl(count);
    for( ; i < count; i++){
        resp.alert_event[i].type = htonl(g_p2ptnp_info.mmap_info->alarm_event_ctx.arr[i].type);
        resp.alert_event[i].start_time = htonl((int)g_p2ptnp_info.mmap_info->alarm_event_ctx.arr[i].start_time);
        resp.alert_event[i].duration = htonl(g_p2ptnp_info.mmap_info->alarm_event_ctx.arr[i].duration);
    }
    resp_len = sizeof(int) + count*sizeof(alert_event_t);
    printf("##hxq alert event resp_len: %d\n", resp_len);
	ret = p2p_send_ctrl_data_ext(index, IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_RESP, nIOCtrlCmdNum, (char *)&resp, resp_len);
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_RESP, ret = %d\n", ret);
	return ret;
}
#endif

int reply_factory_test_info(int index, UINT16 nIOCtrlCmdNum)
{
	get_factory_test_info_resp resp;
	int ret = 0;
	memset(&resp, 0, sizeof(resp));
	snprintf(resp.firmware_version, sizeof(resp.firmware_version), "%s", g_p2ptnp_info.mmap_info->version);
	snprintf(resp.mac_str, sizeof(resp.mac_str), "%s", g_p2ptnp_info.mmap_info->mac);
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_FACTORY_TEST_INFO_RESP, nIOCtrlCmdNum, (char *)&resp, sizeof(resp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_FACTORY_TEST_INFO_RESP, ret = %d\n", ret);
	return ret;
}
int reply_event_list(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlListEventResp stListEventResp = {0};
	unsigned long start, end;
	int i = 0, j = 0, leftevent = 0;
	char payload[1024] = {0};
	int payload_len = 0;
	SAvEvent savE[AVIOCTRL_MAX_REC_NUM_IN_RSP];
	record_event_t envent_info[AVIOCTRL_MAX_REC_NUM_IN_RSP];
	int eventnum = 0;
	int eventcount = 0;
	time_t t_of_day;
	struct tm *local;
	int ret = 0;

	if(g_p2ptnp_info.mmap_info->sd_size == 0)
	{
		stListEventResp.channel = htonl(0);
		stListEventResp.total   = htonl(0);
		stListEventResp.index   = 0;
		stListEventResp.count   = 0;
		stListEventResp.endflag = 1;

		ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_LISTEVENT_RESP, nIOCtrlCmdNum, (char *)&stListEventResp, sizeof(SMsgAVIoctrlListEventResp));
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_LISTEVENT_RESP, ret = %d\n", ret);
	}
	else
	{
		start = 0;
		end = 0x7fffffff;
		event_log_seach(start, end, 0xffffffff, (unsigned long*)&eventnum);

		leftevent = eventnum;
		for(j = 0; j < (eventnum+AVIOCTRL_MAX_REC_NUM_IN_RSP-1)/AVIOCTRL_MAX_REC_NUM_IN_RSP; j++)
		{
			memset(&stListEventResp, 0, sizeof(stListEventResp));

			eventcount = MIN(AVIOCTRL_MAX_REC_NUM_IN_RSP, leftevent);
			event_log_get(eventnum-leftevent, eventcount, envent_info);
			for (i = 0; i < eventcount; i++)
			{
				t_of_day = envent_info[i].start_time;
				local = gmtime( &t_of_day );
				savE[i].stTime.year   = htons(local->tm_year+1900);
				savE[i].stTime.month  = local->tm_mon+1;
				savE[i].stTime.day	  = local->tm_mday;
				savE[i].stTime.hour   = local->tm_hour;
				savE[i].stTime.minute = local->tm_min;
				savE[i].stTime.second = local->tm_sec;
				savE[i].stTime.wday   = local->tm_wday;

				savE[i].event = AVIOCTRL_EVENT_MOTIONDECT;
				savE[i].status = 1;
				savE[i].duration = htons(envent_info[i].end_time-envent_info[i].start_time);
			}

			leftevent -= eventcount;

			stListEventResp.channel = htonl(0);
			stListEventResp.total  = htonl(eventnum);
			stListEventResp.index  = i;
			stListEventResp.count  = eventcount;

			if(0 == leftevent)
			{
				stListEventResp.endflag= 1;
			}
			else
			{
				stListEventResp.endflag= 0;
			}

			dump_string(_F_, _FU_, _L_, "i(%d) j(%d) eventcount(%d) eventnum(%d) leftevent(%d) eventcount(%d) endflag(%d)\n ",
				i, j, eventcount, eventnum, leftevent, eventcount, stListEventResp.endflag);

			memcpy(payload, &stListEventResp, sizeof(SMsgAVIoctrlListEventResp));
			memcpy(payload + sizeof(SMsgAVIoctrlListEventResp), savE, sizeof(SAvEvent)*eventcount);

			payload_len = sizeof(SMsgAVIoctrlListEventResp) + sizeof(SAvEvent)*eventcount;

			ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_LISTEVENT_RESP, nIOCtrlCmdNum, payload, payload_len);
			dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_LISTEVENT_RESP, ret = %d\n", ret);
		}

	}

	return ret;
}

int tnp_reply_event_list(int index, UINT16 nIOCtrlCmdNum)
{
	int send_len = 0;
	int payload_len = 0;
	int ret = 0;

	pthread_mutex_lock(&event_list_lock);

	payload_len = sizeof(tnp_event_msg_head_s) + ntohs(tnp_eventlist_msg.head.event_cnt)*sizeof(tnp_event_msg_s);

	tnp_eventlist_msg.io_head.nDataSize = htonl(sizeof(st_AVIOCtrlHead) + payload_len);
	tnp_eventlist_msg.io_head.nStreamIOType = SIO_TYPE_IOCTRL;
	tnp_eventlist_msg.io_head.nVersion = g_p2ptnp_info.gUser[index].tnp_ver;

	tnp_eventlist_msg.ctrl_head.nIOCtrlCmdNum = htons(nIOCtrlCmdNum);
	tnp_eventlist_msg.ctrl_head.nIOCtrlType = htons(IOTYPE_USER_TNP_EVENT_LIST_RESP);
	tnp_eventlist_msg.ctrl_head.nExHeaderSize = htons(0);
	tnp_eventlist_msg.ctrl_head.nIOCtrlDataSize = htons(payload_len);
	tnp_eventlist_msg.ctrl_head.authHead.authResult = htonl(AUTH_OK);

	send_len = sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead) + payload_len;
	ret = PPPP_Write(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, (char *)&tnp_eventlist_msg, send_len);

	pthread_mutex_unlock(&event_list_lock);

	dump_string(_F_, _FU_, _L_, "p2p_send_ctrl_data, msg_type=0x%02x ret=%d sendlen(%d) payload_len(%d)",
						IOTYPE_USER_IPCAM_LISTEVENT_RESP, ret, send_len, payload_len);
	return 0;
}

int reply_tnp_record_play(int index, ENUM_PLAYCONTROL play_control, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlPlayRecordResp stPlaybackResp = {0};
	int ret = 0;

	stPlaybackResp.command = htonl(play_control);
	stPlaybackResp.result = htonl((play_control == AVIOCTRL_RECORD_PLAY_START)?0:-1);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_RECORD_PLAYCONTROL_RESP, nIOCtrlCmdNum, (char *)&stPlaybackResp, sizeof(SMsgAVIoctrlPlayRecordResp));

	return ret;
}

int report_tnp_ipcam_kicked(int index)
{
	tnp_ipcam_kicked_msg_s msg = {0};
	int ret = 0;

	msg.reason = 1;

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_TNP_IPCAM_KICKED, 0, (char *)&msg, sizeof(tnp_ipcam_kicked_msg_s));

	return ret;
}

/*input resolution:0,auto;1,high;2,low;*/
int set_resolution(int index, int usecount, int resolution, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlResolutionMode rsp;
	int ret = 0;

	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_RESOLUTION, resolution = %d\n", resolution);

	if(resolution == 0)
	{
		g_p2ptnp_info.gUser[index].auto_resolution = 1;
	}
	else
	{
		g_p2ptnp_info.gUser[index].auto_resolution = 0;
	}

	g_p2ptnp_info.gUser[index].pre_resolution = g_p2ptnp_info.gUser[index].resolution;
    if(resolution == 4 || resolution == 5 || resolution == 6)
    {
        g_p2ptnp_info.gUser[index].resolution = resolution;
    }
    else
    {
    	g_p2ptnp_info.gUser[index].resolution = (resolution+1)%2;
    }
	//g_p2ptnp_info.gUser[index].resolution = 0;

	if(nIOCtrlCmdNum != -1)
	{
		rsp.resolution = htonl(resolution);//htonl(g_p2ptnp_info.gUser[index].resolution);
		rsp.usecount = htonl(usecount);
		ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_RESOLUTION_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlResolutionMode));
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_RESOLUTION_RESP, ret = %d\n", ret);
	}

	return ret;
}

int get_resolution(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlResolutionMode rsp;
	int resolution = 0;
	int ret = 0;

	if(g_p2ptnp_info.gUser[index].auto_resolution == 1)
	{
		resolution = 0;
	}
	else
	{
		resolution = g_p2ptnp_info.gUser[index].resolution+1;
	}

	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_RESOLUTION, resolution = %d\n", resolution);

	rsp.resolution = htonl(resolution);
	rsp.usecount = htonl(g_p2ptnp_info.gUser[index].usecount);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_RESOLUTION_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlResolutionMode));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_RESOLUTION_RESP, ret = %d\n", ret);

	return ret;
}

/*input speed:1,1X; 4,4X; 8,8X;*/
int set_record_speed(int index, int usecount, int speed, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlRecordSpeed rsp;
	int ret = 0;

	if(speed != 0)
	{
		g_p2ptnp_info.gUser[index].record_speed = speed;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "set_record_speed, param error, speed = 0!\n");
	}

	if(nIOCtrlCmdNum != -1)
	{
		rsp.speed = htonl(g_p2ptnp_info.gUser[index].record_speed);
		rsp.usecount = htonl(usecount);
		ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_SET_RECORD_SPEED_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlRecordSpeed));
		dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_SET_RECORD_SPEED_RESP, ret = %d\n", ret);
	}

	return ret;
}

int get_record_speed(int index, UINT16 nIOCtrlCmdNum)
{
	SMsgAVIoctrlRecordSpeed rsp;
	int speed = 0;
	int ret = 0;

	if(g_p2ptnp_info.gUser[index].record_speed == 0)
	{
		speed = 1;
	}
	else
	{
		speed = g_p2ptnp_info.gUser[index].record_speed;
	}

	rsp.speed = htonl(speed);
	rsp.usecount = htonl(g_p2ptnp_info.gUser[index].usecount);

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_RECORD_SPEED_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsgAVIoctrlRecordSpeed));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_RECORD_SPEED_RESP, ret = %d\n", ret);

	return ret;
}


int get_version(int index, UINT16 nIOCtrlCmdNum)
{
	int ret = 0;

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_VERSION_RESP, nIOCtrlCmdNum, g_p2ptnp_info.mmap_info->version, strlen(g_p2ptnp_info.mmap_info->version));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_VERSION_RESP, ret = %d\n", ret);

	return 0;
}

int get_whiteled_close_status(int index, UINT16 nIOCtrlCmdNum)
{
	SMsAVIoctrlWhiteLedResp rsp;
	int ret = 0;
	int state = 0;

	if(g_p2ptnp_info.mmap_info->hw_ver.white_led_close == '1')
	{
		state = WHITE_LED_ALWAYS_BRIGHT;
	}
	else if(g_p2ptnp_info.mmap_info->hw_ver.white_led_close == '2')
	{
		state = WHITE_LED_AUTO_CLOSE;
	}
	else if(g_p2ptnp_info.mmap_info->hw_ver.white_led_close == '3') 
	{
		state = WHITE_LED_NO_NEED;
	}
	else
	{
		state = WHITE_LED_NOT_DEFINE;
	}
	
	rsp.white_led_close = htonl(state);
	dump_string(_F_, _FU_, _L_, "rsp.white_led_close, state = %d\n", state);

	ret = p2p_send_ctrl_data(index, IOTYPE_GET_WHITE_LIGHT_OFF_STATUS_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsAVIoctrlWhiteLedResp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_GET_WHITE_LIGHT_OFF_STATUS_RESP, ret = %d\n", ret);

	return ret;
}

int get_white_light_status(int index, UINT16 nIOCtrlCmdNum)
{
	SMsAVIoctrlWhiteLedResp rsp;
	int ret = 0;
	int state = 0;
    if(g_p2ptnp_info.mmap_info->hw_ver.white_led_close == '0')
    {
        state = WHITE_LED_STATUS_UNDEFINED;
    }
    else if(g_p2ptnp_info.mmap_info->white_led_mode == WHITE_LED_MODE_ON_E)
    {
        state = WHITE_LED_STATUS_OPEN;
    }
    else if(g_p2ptnp_info.mmap_info->white_led_mode == WHITE_LED_MODE_AUTO_E)
    {
        state = WHITE_LED_STATUS_AUTO;
    }
    else//if(g_p2ptnp_info.mmap_info->white_led_mode == WHITE_LED_MODE_OFF_E)
    {
        state = WHITE_LED_STATUS_CLOSE;
    }
    dump_string(_F_, _FU_, _L_, "rsp.white_led_close, state = %d\n", state);
	rsp.white_led_close = htonl(state);	
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_STATUS_RESP, nIOCtrlCmdNum, (char *)&rsp, sizeof(SMsAVIoctrlWhiteLedResp));
	dump_string(_F_, _FU_, _L_, "IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_STATUS_RESP, ret = %d\n", ret);

	return ret;
}

void restart_device(void)
{
    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_RESTART_DEVICE, NULL, 0) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_day_night_mode send_msg fail!\n");
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_day_night_mode send_msg ok!\n");
    }
}
int get_hw_value_resp(int index, UINT16 nIOCtrlCmdNum)
{
	char hw[HW_NUM+1];
	hw[HW_NUM] = 0;
	int ret = 0;
	char cmd[100] = {0};
	char ret_string[100]={0};
	strcpy(cmd,"/home/app/read_hw | grep hw_ver= | awk 'NR==1{print $5}' |sed 's/hw_ver=//' |sed 's/,//'");

	system_cmd_withret_timeout(cmd, ret_string, sizeof(ret_string), 10);
	//dump_string(_F_, _FU_, _L_, "ret string=%s,size=%d\n",ret_string,strlen(ret_string));

	if((strlen(ret_string)-1) != HW_NUM){ //-1去掉换行符
		dump_string(_F_, _FU_, _L_, "read hw len error!!\n");
		return -1;
	}

	memcpy(hw,ret_string,HW_NUM);
	ret = p2p_send_ctrl_data(index, IOTYPE_GET_DEVICE_PARAM_RESP, nIOCtrlCmdNum,hw,(HW_NUM+1));
	dump_string(_F_, _FU_, _L_, "IOTYPE_GET_DEVICE_PARAM_RESP, ret = %d\n", ret);
	return ret;
}

int reply_hw_value(int index, UINT16 nIOCtrlCmdNum){
	char hw[HW_NUM+1];
	hw[HW_NUM] = 0;
	int ret = 0;
	char cmd[100] = {0};
	char ret_string[100]={0};
	strcpy(cmd,"/home/app/read_hw | grep hw_ver= | awk 'NR==1{print $5}' |sed 's/hw_ver=//' |sed 's/,//'");

	system_cmd_withret_timeout(cmd, ret_string, sizeof(ret_string), 10);
	//dump_string(_F_, _FU_, _L_, "ret string=%s,size=%d\n",ret_string,strlen(ret_string));

	if((strlen(ret_string)-1) != HW_NUM){ //-1去掉换行符
		dump_string(_F_, _FU_, _L_, "read hw len error!!\n");
		return -1;
	}

	memcpy(hw,ret_string,HW_NUM);
	ret = p2p_send_ctrl_data(index, IOTYPE_SET_DEVICE_PARAM_RESP, nIOCtrlCmdNum,hw,(HW_NUM+1));
	dump_string(_F_, _FU_, _L_, "IOTYPE_SET_DEVICE_PARAM_RESP, ret = %d\n", ret);
	return ret;
}


int get_update_url_md5_QGopen(char *url, char *md5)
{
    char cmd[512] = {0};
    char ret_string[2048] = {0};
	char buf[128] = {0};
    char need_update[64] = {0};
    char force_update[64] = {0};
    char tmp_url[256] = {0};
    char fileName[64] ={ 0 };
    char tmp_md5[64] = {0};
	int trycnt = 5;
    sprintf(cmd, "%s -c 144 -url \"%s/vmanager/ipc/firmware/upgrade/app\" "
              "-version %s "
              "-device_id %s "
              "-sname %s ",
              CLOUDAPI_PATH,
              g_p2ptnp_info.mmap_info->api_server,
              g_p2ptnp_info.mmap_info->version,
              g_p2ptnp_info.mmap_info->did,
              "QGopen");
    dump_string(_F_, _FU_, _L_, "cmd = %s\n", cmd);
	while(trycnt > 0)
	{
		trycnt--;
		memset(ret_string, 0, sizeof(ret_string));
		system_cmd_withret_timeout(cmd, ret_string, sizeof(ret_string), 60);
		dump_string(_F_, _FU_, _L_, "cmd = %s\n", cmd);
        memset(buf, 0, sizeof(buf));
        if(TRUE == trans_json_ex_s(buf, sizeof(buf), "code", ret_string) && atoi(buf) == 1)
        {
            memset(need_update, 0, sizeof(need_update));
            memset(force_update, 0, sizeof(force_update));

            if((FALSE == trans_json_ex_s(need_update, sizeof(need_update), "needUpdate", ret_string) || strcmp(need_update, "true") != 0)
				&& (FALSE == trans_json_ex_s(force_update, sizeof(force_update), "forceUpdate", ret_string) || strcmp(force_update, "true") != 0))
            {
                return 0;
            }

            memset(tmp_url, 0, sizeof(tmp_url));
            if(FALSE == trans_json_ex_s(tmp_url, sizeof(tmp_url), "downloadPath", ret_string) || strlen(tmp_url) == 0)
            {
				return 0;
            }
#if 0   //no need
            memset(fileName, 0, sizeof(fileName));
            if(FALSE == trans_json_ex_s(fileName, sizeof(fileName), "fileName", ret_string) || strlen(fileName) == 0)
            {
				return 0;
            }
            strcat(tmp_url,fileName);
#endif
            memset(tmp_md5, 0, sizeof(tmp_md5));
            if(FALSE == trans_json_ex_s(tmp_md5, sizeof(tmp_md5), "md5Code", ret_string) || strlen(tmp_md5) == 0)
            {
				return 0;
            }

            strcpy(url, tmp_url);
            strcpy(md5, tmp_md5);
            return 1;
        }

		sleep(10);
	}

    return 0;
}
int get_update_url_md5(char *url, char *md5)
{
    char cmd[512] = {0};
    char ret_string[2048] = {0};
	char buf[128] = {0};
    char need_update[64] = {0};
    char force_update[64] = {0};
    char tmp_url[256] = {0};
    char tmp_md5[64] = {0};
	int trycnt = 5;
#if 1
    // added by Frank Zhang
    while(trycnt > 0)
	{
		trycnt--;
		memset(&tmp_url,0,sizeof(tmp_url));
		memset(&tmp_md5,0,sizeof(tmp_md5));
        if(xlink_get_download_url(g_p2ptnp_info.mmap_info->mac,tmp_url,tmp_md5) == 0)
        {
            if(strcmp(g_p2ptnp_info.mmap_info->xlinkinfo.auth_code,xlink_get_authcode()) != 0)
            {
                xlink_info info;
                memset(&info,0,sizeof(info));
                memcpy(&info,&g_p2ptnp_info.mmap_info->xlinkinfo,sizeof(info));
                memset(&info.auth_code,0,sizeof(info.auth_code));
                //info.bupdated = 1;
                snprintf(info.auth_code, sizeof(info.auth_code), "%s", xlink_get_authcode());
                if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_XLINK_INFO, (char *)&info, sizeof(info)) < 0)
                {
                    dump_string(_F_, _FU_, _L_, "p2p_set_xlink_info send_msg fail!\n");
                }
                else
                {
                    dump_string(_F_, _FU_, _L_, "p2p_set_xlink_info send_msg ok!\n");
                }
            }
            if(strlen(tmp_url) == 0)
            {
                return 0;
            }            
		    strcpy(url, tmp_url);
            strcpy(md5, tmp_md5);
            return 1;
        }
		sleep(10);
	}
    return 0;
#else
    sprintf(cmd, "%s -c 140 -url \"%s/vmanager/upgrade\" "
              "-uid %s "
              "-sname %s "
              "-protocol %s "
              "-version %s ",
              CLOUDAPI_PATH,
              g_p2ptnp_info.mmap_info->api_server,
              g_p2ptnp_info.mmap_info->p2pid,
              DEVICE_NAME(familymonitor, DEVICE_SUFFIX),
              g_p2ptnp_info.mmap_info->dlproto,
              g_p2ptnp_info.mmap_info->version);

    dump_string(_F_, _FU_, _L_, "cmd = %s\n", cmd);

	while(trycnt > 0)
	{
		trycnt--;

		memset(ret_string, 0, sizeof(ret_string));
		system_cmd_withret_timeout(cmd, ret_string, sizeof(ret_string), 60);
		dump_string(_F_, _FU_, _L_, "cmd = %s\n", cmd);
		dump_string(_F_, _FU_, _L_, "ret_string = %s\n", ret_string);

        memset(buf, 0, sizeof(buf));
        if(TRUE == trans_json_ex_s(buf, sizeof(buf), "code", ret_string) && atoi(buf) == 20000)
        {
            memset(need_update, 0, sizeof(need_update));
            memset(force_update, 0, sizeof(force_update));

            if((FALSE == trans_json_ex_s(need_update, sizeof(need_update), "needUpdate", ret_string) || strcmp(need_update, "true") != 0)
				&& (FALSE == trans_json_ex_s(force_update, sizeof(force_update), "forceUpdate", ret_string) || strcmp(force_update, "true") != 0))
            {
                return 0;
            }

            memset(tmp_url, 0, sizeof(tmp_url));
            if(FALSE == trans_json_ex_s(tmp_url, sizeof(tmp_url), "downloadPath", ret_string) || strlen(tmp_url) == 0)
            {
				return 0;
            }

            memset(tmp_md5, 0, sizeof(tmp_md5));
            if(FALSE == trans_json_ex_s(tmp_md5, sizeof(tmp_md5), "md5Code", ret_string) || strlen(tmp_md5) == 0)
            {
				return 0;
            }

            strcpy(url, tmp_url);
            strcpy(md5, tmp_md5);
            return 1;
        }

		sleep(10);
	}
    return 0;
#endif
}

int do_update(int index, UINT16 nIOCtrlCmdNum)
{
    char cmd[1024] = {0};
	char url[256] = {0};
	char md5[64] = {0};
    int success = 0;
	int ret = 0;
	g_download_t g_download_info;

	memset(&g_download_info, 0, sizeof(g_download_t));

	if(g_updatestat == 1)
	{
		return -1;
	}

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_do_update_begin");
#ifdef NOT_PLT_API
	success = get_update_url_md5(url, md5);
#else
	success = get_update_url_md5_QGopen(url, md5);
#endif
	if(success == 1)
	{
	    memset(cmd, 0, sizeof(cmd));
		snprintf(g_download_info.url, sizeof(g_download_info.url), "%s", url);
		snprintf(g_download_info.md5, sizeof(g_download_info.md5), "%s", md5);
		if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_DOWNLOAD_INFO, (char *)&g_download_info, sizeof(g_download_t)) < 0)
		{
			dump_string(_F_, _FU_, _L_, "p2p_set_download_info send_msg fail!\n");
		}
		printf("g_download_info.url =%s %s\n",g_download_info.url,g_download_info.md5);
		snprintf(cmd, sizeof(cmd), "killall upgrade_firmware;rm -f /home/%s;rm -f /tmp/sd/%s;rm -f /tmp/update/%s;/backup/tools/upgrade_firmware \"%s\" \"%s\" &",
                IMAGE_NAME, IMAGE_NAME, IMAGE_NAME,
                 url, md5);
		system(cmd);
		g_updatestat = 1;
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "cloudAPI get_update_url_md5 failed url = %s, md5 = %s\n", url, md5);
		g_updatestat = 4;
	}

	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_UPDATE_RSP, nIOCtrlCmdNum, g_p2ptnp_info.mmap_info->version, strlen(g_p2ptnp_info.mmap_info->version));
	dump_string(_F_, _FU_, _L_,"IOTYPE_USER_IPCAM_UPDATE_RSP, ret = %d\n", ret);

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_do_update_end");

	return 0;
}


int p2p_send_ctrl_data(int index, ENUM_AVIOCTRL_MSGTYPE msg_type, UINT16 nIOCtrlCmdNum, char *payload, int payload_len)
{
	char send_buf[1024] = {0};
	int send_len = 0;
	st_AVStreamIOHead *io_stream_head = NULL;
	st_AVIOCtrlHead *io_ctrl_head = NULL;
	int ret = 0;

	io_stream_head = (st_AVStreamIOHead *)send_buf;
	io_stream_head->nDataSize = htonl(sizeof(st_AVIOCtrlHead) + payload_len);
	io_stream_head->nStreamIOType = SIO_TYPE_IOCTRL;
	io_stream_head->nVersion = g_p2ptnp_info.gUser[index].tnp_ver;

	io_ctrl_head = (st_AVIOCtrlHead *)(send_buf + sizeof(st_AVStreamIOHead));
	io_ctrl_head->nIOCtrlType = htons(msg_type);
	io_ctrl_head->nIOCtrlCmdNum = htons(nIOCtrlCmdNum);
	io_ctrl_head->nExHeaderSize = htons(0);
	io_ctrl_head->nIOCtrlDataSize = htons(payload_len);
	io_ctrl_head->authHead.authResult = htonl(AUTH_OK);

	if(payload_len != 0)
	{
		memcpy(send_buf + sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead), payload, payload_len);
	}

	send_len = sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead) + payload_len;

	ret = PPPP_Write(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, send_buf, send_len);

	dump_string(_F_, _FU_, _L_, "p2p_send_ctrl_data, msg_type=0x%02x\n", msg_type);

	return ret;
}

int p2p_send_ctrl_data_ext(int index, ENUM_AVIOCTRL_MSGTYPE msg_type, UINT16 nIOCtrlCmdNum, char *payload, int payload_len)
{
	char send_buf[4096] = {0};
	int send_len = 0;
	st_AVStreamIOHead *io_stream_head = NULL;
	st_AVIOCtrlHead *io_ctrl_head = NULL;
	int ret = 0;

	io_stream_head = (st_AVStreamIOHead *)send_buf;
	io_stream_head->nDataSize = htonl(sizeof(st_AVIOCtrlHead) + payload_len);
	io_stream_head->nStreamIOType = SIO_TYPE_IOCTRL;
	io_stream_head->nVersion = g_p2ptnp_info.gUser[index].tnp_ver;

	io_ctrl_head = (st_AVIOCtrlHead *)(send_buf + sizeof(st_AVStreamIOHead));
	io_ctrl_head->nIOCtrlType = htons(msg_type);
	io_ctrl_head->nIOCtrlCmdNum = htons(nIOCtrlCmdNum);
	io_ctrl_head->nExHeaderSize = htons(0);
	io_ctrl_head->nIOCtrlDataSize = htons(payload_len);
	io_ctrl_head->authHead.authResult = htonl(AUTH_OK);

	if(payload_len != 0)
	{
		memcpy(send_buf + sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead), payload, payload_len);
	}

	send_len = sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead) + payload_len;

	ret = PPPP_Write(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, send_buf, send_len);

	dump_string(_F_, _FU_, _L_, "p2p_send_ctrl_data, msg_type=0x%02x\n", msg_type);

	return ret;
}
/*
unsigned char *frame_data ����������ָ�룬������sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t)
int payload_len רָ�������ݣ�������sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t)��Ϣ��

*/
int p2p_send_frame_data(int index, char is_real, ENUM_STREAM_IO_TYPE stream_type, ENUM_FRAMEFLAG video_frame_type, const fshare_attr_t *frame_attr, unsigned char *frame_data, int payload_len)
{
	st_AVStreamIOHead *io_stream_head = NULL;
	FRAMEINFO_t *frame_head = NULL;
	char encrypt_key[20] = {0};
	char encrypt_buf[32] = {0};
	CHANNEL_TYPE channel = 0;
	UINT32 buf_size = 0;
	//int max_cache_size = 0;
	int send_len = 0;
	UINT32 i_frame_cache_size = 0;
	int elapsed_ms = 0;
	int bitrate = 0;
	int ret = 0;
	unsigned char* real_data = NULL;

	if(frame_data == NULL)
	{
		return -1;
	}

	//payload_len = 1000;

	real_data = frame_data + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

	memcpy(encrypt_key, g_p2ptnp_info.gUser[index].password, 15);
	encrypt_key[15] = '0';

	io_stream_head = (st_AVStreamIOHead *)frame_data;
	io_stream_head->nDataSize = htonl(sizeof(FRAMEINFO_t) + payload_len);
	io_stream_head->nStreamIOType = stream_type;
	io_stream_head->nVersion = g_p2ptnp_info.gUser[index].tnp_ver;

	frame_head = (FRAMEINFO_t *)(frame_data + sizeof(st_AVStreamIOHead));
	if(stream_type == SIO_TYPE_VIDEO)
	{
		if(is_real == 1)
		{
			if(video_frame_type == IPC_FRAME_FLAG_IFRAME)
			{
				channel = CHANNEL_VIDEO_REALTIME_IFRAME;
				//max_cache_size = MAX_I_FRAME_CACHE_SIZE;
			}
			else
			{
				channel = CHANNEL_VIDEO_REALTIME_PFRAME;
				//max_cache_size = MAX_REALTIME_P_FRAME_CACHE_SIZE;
			}
		    /* dump_string(_F_, _FU_, _L_, "cover_state:%d",frame_head->cover_state); */
			frame_head->cover_state = g_p2ptnp_info.mmap_info->video_occlusion;
		}
		else
		{
			if(video_frame_type == IPC_FRAME_FLAG_IFRAME)
			{
				channel = CHANNEL_VIDEO_RECORD_IFRAME;
				//max_cache_size = MAX_I_FRAME_CACHE_SIZE;
			}
			else
			{
				channel = CHANNEL_VIDEO_RECORD_PFRAME;
				//max_cache_size = MAX_RECORD_P_FRAME_CACHE_SIZE;
			}
			frame_head->cover_state = 0;
		}

		g_p2ptnp_info.gUser[index].video_seq++;

		if(frame_attr->type & FSHARE_IS_H265)
		{
			frame_head->codec_id  = htons(MEDIA_CODEC_VIDEO_H265);
		}
		else
		{
			frame_head->codec_id  = htons(MEDIA_CODEC_VIDEO_H264);
		}
		frame_head->flags = video_frame_type;
		frame_head->ptz_state = frame_attr->stat;
		frame_head->width = htons(g_p2ptnp_info.gUser[index].width);
		frame_head->height = htons(g_p2ptnp_info.gUser[index].height);
		frame_head->sequence = htons(g_p2ptnp_info.gUser[index].video_seq);
		//frame_head->timestamp = htonl(frame_attr->sec - 3600*8);
		frame_head->timestamp = htonl(frame_attr->sec);
		frame_head->inloss = g_p2ptnp_info.mmap_info->in_packet_loss;
		frame_head->outloss = g_p2ptnp_info.mmap_info->out_packet_loss;

		if(g_p2ptnp_info.gUser[index].encrypt == 1 && video_frame_type == IPC_FRAME_FLAG_IFRAME && payload_len >= 36)
		{
			AesSetKey(&aes, (unsigned char *)encrypt_key, 16, NULL, AES_ENCRYPTION);
			AesCbcEncrypt(&aes, (unsigned char *)encrypt_buf, (const unsigned char*)(real_data + 4), 16);
			memcpy(real_data + 4, encrypt_buf, 16);
			AesSetKey(&aes, (unsigned char *)encrypt_key, 16, NULL, AES_ENCRYPTION);
			AesCbcEncrypt(&aes, (unsigned char *)encrypt_buf, (const unsigned char*)(real_data + 20), 16);
			memcpy(real_data + 20, encrypt_buf, 16);
		}
	}
	else if(stream_type == SIO_TYPE_AUDIO)
	{
		channel = CHANNEL_AUDIO;
		//max_cache_size = MAX_REALTIME_P_FRAME_CACHE_SIZE;
		g_p2ptnp_info.gUser[index].audio_seq++;
		frame_head->codec_id  = htons(MEDIA_CODEC_AUDIO_AAC);
		frame_head->flags = (AUDIO_SAMPLE_32K << 2) | (AUDIO_DATABITS_16 << 1) | AUDIO_CHANNEL_STERO;
		frame_head->sequence = htons(g_p2ptnp_info.gUser[index].audio_seq);
		//frame_head->timestamp = htonl(frame_attr->sec - 3600*8);
		frame_head->timestamp = htonl(frame_attr->sec);

        if(g_p2ptnp_info.gUser[index].tnp_ver > TNP_VERSION_1 && g_p2ptnp_info.gUser[index].encrypt == 1)
		{
		    int encrypt_block_len = payload_len/16;
            AesSetKeyDirect(&aes, (const unsigned char *)encrypt_key, 16, NULL, AES_ENCRYPTION);
            int i = 0;
            for(i=0; i<encrypt_block_len; i++)
            {
                AesEncryptDirect(&aes, (unsigned char *)encrypt_buf, (const unsigned char*)(real_data + 16*i));
                memcpy(real_data+16*i, encrypt_buf, 16);
            }
		}
	}
	else
	{
		return -1;
	}

	frame_head->timestamp_ms = htonl(frame_attr->ts);
	frame_head->usecount = g_p2ptnp_info.gUser[index].usecount;
	frame_head->cam_index = (is_real == 1)?0:1;
	frame_head->isday = 0;

	if(g_p2ptnp_info.mmap_info->debug_mode == 1 && g_p2ptnp_info.gUser[index].use_test_auth == 1)
	{
		memset_s(real_data, payload_len, 0, payload_len);
	}

	if(g_p2ptnp_info.gUser[index].auto_resolution == 1 && g_p2ptnp_info.gUser[index].calc_bitrate == 1)
	{
		if(is_real == 1)
		{
			p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_VIDEO_REALTIME_IFRAME, &i_frame_cache_size, NULL);
		}
		else
		{
			p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_VIDEO_RECORD_IFRAME, &i_frame_cache_size, NULL);
		}

		if(i_frame_cache_size == 0 || (stream_type == SIO_TYPE_VIDEO && video_frame_type == IPC_FRAME_FLAG_IFRAME))
		{
			elapsed_ms = tnp_calc_timecost_result(&g_p2ptnp_info.gUser[index].g_tv);
			if(elapsed_ms != 0)
			{
				bitrate = (g_p2ptnp_info.gUser[index].i_frame_left_size - i_frame_cache_size)/elapsed_ms;
				//dump_string(_F_, _FU_, _L_, "%d ms elapsed to send %d byte, bitrate %d kBps!\n", elapsed_ms, g_p2ptnp_info.gUser[index].i_frame_left_size - i_frame_cache_size, bitrate);
				g_p2ptnp_info.gUser[index].i_frame_left_size = i_frame_cache_size;
				g_p2ptnp_info.gUser[index].calc_bitrate = 0;

				p2p_set_immediate_bitrate(bitrate);

				if(bitrate > 70 && g_p2ptnp_info.gUser[index].resolution == 1)
				{
					g_p2ptnp_info.gUser[index].resolution_switch_counter++;
				}
				else if(bitrate < 40 && g_p2ptnp_info.gUser[index].resolution == 0)
				{
					g_p2ptnp_info.gUser[index].resolution_switch_counter++;
				}
				else
				{
					g_p2ptnp_info.gUser[index].resolution_switch_counter = 0;
				}

				if(g_p2ptnp_info.gUser[index].resolution_switch_counter >= 5)
				{
					dump_string(_F_, _FU_, _L_, "switch resolution!\n");
					g_p2ptnp_info.gUser[index].resolution = (g_p2ptnp_info.gUser[index].resolution + 1)%2;
					g_p2ptnp_info.gUser[index].resolution_switch_counter = 0;
				}
			}
		}
	}

	p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, channel, &buf_size, NULL);
	if(g_p2ptnp_info.gUser[index].first_i_frame_sended == 0 && g_p2ptnp_info.gUser[index].video_seq > 1 && stream_type == SIO_TYPE_VIDEO && video_frame_type == IPC_FRAME_FLAG_IFRAME && buf_size == 0)
	{
		g_p2ptnp_info.gUser[index].first_i_frame_sended = 1;
		p2p_set_tnp_connect_success();

	}

	send_len = sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t) + payload_len;
	if(g_p2ptnp_info.gUser[index].auto_resolution == 1 && stream_type == SIO_TYPE_VIDEO && video_frame_type == IPC_FRAME_FLAG_IFRAME)
	{
		if(g_p2ptnp_info.gUser[index].calc_bitrate == 0)
		{
			tnp_calc_timecost_init(&g_p2ptnp_info.gUser[index].g_tv);
			g_p2ptnp_info.gUser[index].calc_bitrate = 1;
		}

		g_p2ptnp_info.gUser[index].i_frame_left_size = buf_size + send_len;
	}
	//dump_string(_F_, _FU_, _L_, "%s %s, %s, usecount=%d, timestamp=%d, seqnum=%d, size=%d\n", (is_real == 1)?"realtime":"record", (stream_type == SIO_TYPE_VIDEO)?"video":"audio", (video_frame_type == IPC_FRAME_FLAG_IFRAME)?"i frame":"p frame", frame_head->usecount, ntohl(frame_head->timestamp), ntohs(frame_head->sequence), send_len);

	ret = PPPP_Write(g_p2ptnp_info.gUser[index].SessionHandle, channel, (char *)frame_data, send_len);

    if(0 != g_p2ptnp_info.gUser[index].videoStartTime)
    {
        unsigned int costTime = 0;
        costTime = g_p2ptnp_info.mmap_info->systick - g_p2ptnp_info.gUser[index].videoStartTime;
        if(costTime > 10)// 1s
        {
            char debug_log[128] = {0};
            char uid[8] = {0};
            strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
            snprintf(debug_log, sizeof(debug_log), "uid=%s,p2pfirstframecosttime=%ums", uid, costTime*100);
            p2p_debug_log(0, debug_log);
        }
        g_p2ptnp_info.gUser[index].videoStartTime = 0;
        dump_string(_F_, _FU_, _L_, "p2p send first frame, cost time = %u ms.\n", costTime*100);
    }

	//dump_string(_F_, _FU_, _L_, "p2p_send_frame_data, stream_type=0x%02x\n", stream_type);

	return ret;
}
#if 0
int send_realtime_video(int index, int resolution)
{
	fshare_attr_t frame_attr = {0};
	ENUM_FRAMEFLAG video_frame_type = 0;
	unsigned char *ptr_data = NULL;
	int offset = 0;
	int size = 0;
	int left_size = 0;
	unsigned int ts = 0;
	unsigned int buf_size = 0;
	int channel = 0;
	int max_cache_size = 0;
	int ret = 0;
	int check_type_ret = 0;

	if(g_p2ptnp_info.gUser[index].buff == NULL)
	{
		g_p2ptnp_info.gUser[index].buff = (unsigned char*)malloc(g_p2ptnp_info.gUser[index].max_buff_size);
	}

	ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

	if(g_p2ptnp_info.gUser[index].video_index == -1 || g_p2ptnp_info.gUser[index].pre_resolution != g_p2ptnp_info.gUser[index].resolution || g_p2ptnp_info.gUser[index].force_i_frame == 1)
	{
		ret = p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_VIDEO_REALTIME_IFRAME, &buf_size, NULL);

		if(ret >= 0)
		{
			if(buf_size > MAX_I_FRAME_CACHE_SIZE)
			{
				return -1;
			}
		}
		else
		{
			return -1;
		}
		g_p2ptnp_info.gUser[index].pre_resolution = g_p2ptnp_info.gUser[index].resolution;
		g_p2ptnp_info.gUser[index].force_i_frame = 0;
		left_size = g_p2ptnp_info.gUser[index].max_buff_size - sizeof(st_AVStreamIOHead) - sizeof(FRAMEINFO_t);
		must_get_next_video_frame(NAL_SPS, resolution, ptr_data, &g_p2ptnp_info.gUser[index].buff, left_size, &g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr);
		ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

		g_p2ptnp_info.gUser[index].width = frame_attr.vpara.width;
		g_p2ptnp_info.gUser[index].height = frame_attr.vpara.height;
		offset += frame_attr.size;
		size += frame_attr.size;
		left_size -= frame_attr.size;
		must_get_next_video_frame(NAL_ALL, resolution, ptr_data + offset, &g_p2ptnp_info.gUser[index].buff, left_size, &g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr);
		ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

		offset += frame_attr.size;
		size += frame_attr.size;
		left_size -= frame_attr.size;
		must_get_next_video_frame(NAL_ALL, resolution, ptr_data + offset, &g_p2ptnp_info.gUser[index].buff, left_size, &g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr);
		ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

		size += frame_attr.size;

		g_p2ptnp_info.gUser[index].cur_ts = frame_attr.timestamp;
		ret = p2p_send_frame_data(index, 1, SIO_TYPE_VIDEO, IPC_FRAME_FLAG_IFRAME, frame_attr, g_p2ptnp_info.gUser[index].buff, size);
		//dump_string(_F_, _FU_, _L_, "send_realtime_video send i frame, ret = %d\n", ret);
	}
	else
	{
		#if 1
		/*choked, force i frame*/
		//if(MediaDataVideoGetNewestIFrameTs(resolution, &ts) == 0)
		{
			//printf("force_i_frame 0x%x 0x%x\n", ts, g_p2ptnp_info.gUser[index].cur_ts);
			//if(ts > g_p2ptnp_info.gUser[index].cur_ts && (ts - g_p2ptnp_info.gUser[index].cur_ts) >= 2000)
			{
				if(MediaDataVideoGetNewestFrameTs(resolution, &ts) == 0)
				{
					if((ts - g_p2ptnp_info.gUser[index].cur_ts) >= 4100)
					{
						g_p2ptnp_info.gUser[index].force_i_frame = 1;
								//printf("force_i_frame 0x%x 0x%x\n", ts, g_p2ptnp_info.gUser[index].cur_ts);
						return 0;
					}
				}
			}
		}
		#endif

		check_type_ret = MediaDataGetNextVideoFrameType(resolution, ptr_data, g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr);

		if(-3==check_type_ret)
		{
			g_p2ptnp_info.gUser[index].force_i_frame = 1;
			printf("force_i_frame 0x%x 0x%x\n", ts, g_p2ptnp_info.gUser[index].cur_ts);
			return 0;
		}
		else if(0==check_type_ret)
		{
			ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

			if(NAL_SPS == frame_attr.vpara.frametype)
			{
				channel = CHANNEL_VIDEO_REALTIME_IFRAME;
				max_cache_size = MAX_I_FRAME_CACHE_SIZE;
			}
			else
			{
				channel = CHANNEL_VIDEO_REALTIME_PFRAME;
				max_cache_size = MAX_REALTIME_P_FRAME_CACHE_SIZE;
				#if 0
				PPPP_Check_Buffer(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_VIDEO_REALTIME_IFRAME, &buf_size, NULL);
				if(buf_size > MAX_REALTIME_P_FRAME_CACHE_SIZE)
				{
					//printf("wait I frame to send\n");
					//return -1;
				}
				#endif
			}

			p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, channel, &buf_size, NULL);

			if(buf_size > max_cache_size)
			{
				return -1;
			}

			left_size = g_p2ptnp_info.gUser[index].max_buff_size - sizeof(st_AVStreamIOHead) - sizeof(FRAMEINFO_t);
			ret = get_next_video_frame(NAL_ALL, resolution, ptr_data, &g_p2ptnp_info.gUser[index].buff, left_size, &g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr, 0);
			if(ret >= 0)
			{
				ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
				if(frame_attr.vpara.frametype == NAL_SPS)
				{
					g_p2ptnp_info.gUser[index].width = frame_attr.vpara.width;
					g_p2ptnp_info.gUser[index].height = frame_attr.vpara.height;
					offset += frame_attr.size;
					size += frame_attr.size;
					left_size -= frame_attr.size;
					must_get_next_video_frame(NAL_ALL, resolution, ptr_data + offset, &g_p2ptnp_info.gUser[index].buff, left_size, &g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr);
					ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
					offset += frame_attr.size;
					size += frame_attr.size;
					left_size -= frame_attr.size;

					must_get_next_video_frame(NAL_ALL, resolution, ptr_data + offset, &g_p2ptnp_info.gUser[index].buff, left_size, &g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr);
					ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
					size += frame_attr.size;
					//size += 10;
					video_frame_type = IPC_FRAME_FLAG_IFRAME;
				}
				else
				{
					if(frame_attr.vpara.frametype == NAL_IDR_SLICE)
					{
						video_frame_type = IPC_FRAME_FLAG_IFRAME;
					}
					else if(frame_attr.vpara.frametype == NAL_SLICE)
					{
					video_frame_type = IPC_FRAME_FLAG_PBFRAME;
					}
					else
					{
						return -1;
					}
					size = frame_attr.size;
					//size = 10;
				}

				g_p2ptnp_info.gUser[index].cur_ts = frame_attr.timestamp;
				ret = p2p_send_frame_data(index, 1, SIO_TYPE_VIDEO, video_frame_type, frame_attr, g_p2ptnp_info.gUser[index].buff, size);
				//printf("timestamp(0x%x)\n", frame_attr.timestamp);
				//dump_string(_F_, _FU_, _L_, "send_realtime_video send %s frame, ret = %d\n", (video_frame_type==IPC_FRAME_FLAG_IFRAME)?"i":"p", ret);
			}
		}
		else
		{
			//printf("other error check_type_ret(%d)\n", check_type_ret);
			return 0;
		}
	}

	return ret;
}

int send_realtime_audio(int index)
{
    fshare_attr_t frame_attr = {0};
	unsigned char *ptr_data = NULL;
	int ret = 0;
	unsigned int buf_size = 0;

	ret = p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_AUDIO, &buf_size, NULL);

	if(ret >= 0)
	{
		if(buf_size > MAX_AUDIO_FRAME_CACHE_SIZE)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	if(g_p2ptnp_info.gUser[index].buff == NULL)
	{
		g_p2ptnp_info.gUser[index].buff = (unsigned char*)malloc(g_p2ptnp_info.gUser[index].max_buff_size);
	}

	ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

	if(g_p2ptnp_info.gUser[index].audio_index == -1)
	{
		ret = get_next_audio_frame(NAL_AUD, ptr_data, g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].audio_index, &frame_attr, 0);
	}
	else
	{
		ret = get_next_audio_frame(NAL_ALL, ptr_data, g_p2ptnp_info.gUser[index].max_buff_size, &g_p2ptnp_info.gUser[index].audio_index, &frame_attr, 0);
	}

	if(ret >= 0)
	{
		//dump_string(_F_, _FU_, _L_, "drop one audio frame, buf_size(%d) low_voice(%d)\n", buf_size, frame_attr.apara.low_voice);
		if(buf_size > 2*1024)
		{
			if(frame_attr.apara.low_voice>0)
			{
				//dump_string(_F_, _FU_, _L_, "drop one audio frame, buf_size = %d\n", buf_size);
				return 0;
			}
		}

		ret = p2p_send_frame_data(index, 1, SIO_TYPE_AUDIO, -1, frame_attr, g_p2ptnp_info.gUser[index].buff, frame_attr.size);
		//dump_string(_F_, _FU_, _L_, "send_realtime_audio, ret = %d\n", ret);
	}

    return ret;
}

int do_realtime_play(int index)
{
	if(g_p2ptnp_info.gUser[index].bVideoRequested == 1)
	{
		send_realtime_video(index, g_p2ptnp_info.gUser[index].resolution);

		if(g_p2ptnp_info.gUser[index].bAudioRequested == 1)
		{
			send_realtime_audio(index);
		}
	}
	return 0;
}
#endif
int send_realtime_video(int index, int buf_start, fshare_attr_t *fattr)
{
    st_User *user = &g_p2ptnp_info.gUser[index];
    if (fattr->type & FSHARE_NAL_SPS)
    {
        memcpy(user->sps, user->buff + buf_start, fattr->size);
        user->sps_len = fattr->size;
        user->vps_len = 0;
        if (fattr->attr_type == FSHARE_ATTR_VPARA)
        {
            user->width = fattr->vpara.width;
            user->height = fattr->vpara.height;
        }
        return 0;
    }
    if (fattr->type & FSHARE_NAL_PPS)
    {
        memcpy(user->pps, user->buff + buf_start, fattr->size);
        user->pps_len = fattr->size;
        return 0;
    }
    if (fattr->type & FSHARE_NAL_VPS)
    {
        memcpy(user->vps, user->buff + buf_start, fattr->size);
        user->vps_len = fattr->size;
        return 0;
    }
    ENUM_FRAMEFLAG video_frame_type;
    int channel;
	int max_cache_size;
    if (fattr->type & FSHARE_NAL_IDR)
    {
        buf_start -= user->vps_len + user->sps_len + user->pps_len;
        unsigned char *buf = user->buff + buf_start;
        memcpy(buf, user->vps, user->vps_len);
        buf += user->vps_len;
        memcpy(buf, user->sps, user->sps_len);
        buf += user->sps_len;
        memcpy(buf, user->pps, user->pps_len);
        fattr->size += user->vps_len + user->sps_len + user->pps_len;
        video_frame_type = IPC_FRAME_FLAG_IFRAME;
        channel = CHANNEL_VIDEO_REALTIME_IFRAME;
        max_cache_size = MAX_I_FRAME_CACHE_SIZE;
    }
    else
    {
        video_frame_type = IPC_FRAME_FLAG_PBFRAME;
        channel = CHANNEL_VIDEO_REALTIME_PFRAME;
        max_cache_size = MAX_REALTIME_P_FRAME_CACHE_SIZE;
    }
    int count_down = 0;
    for (;;)
    {
        unsigned int buf_size = 0;
        int ret = p2p_checkbuf(user->SessionHandle, channel, &buf_size, NULL);
        if (ret != 0)
        {
            return ret;
        }
        if (buf_size <= max_cache_size)
        {
            break;
        }
        if (count_down > 20)
        {
            loge("p2p_checkbuf(%d) error,max_cache_size:%d!",channel,max_cache_size);
            user->force_i_frame = 1;
            char debug_log[128] = {0};
            char uid[8] = {0};
            strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
            snprintf(debug_log, sizeof(debug_log), "uid=%s,p2pcheckbuf=2s", uid);
            p2p_debug_log(1, debug_log);
            return -1;
        }
        ms_sleep(100);
        count_down++;
    }
    user->cur_ts = fattr->ts;
    buf_start -= sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
    int ret = p2p_send_frame_data(index, 1, SIO_TYPE_VIDEO, video_frame_type, fattr, user->buff + buf_start,
                                  fattr->size);
    unsigned int newest_ts;
    if (fshare_get_newest_ts(&newest_ts) == 0)
    {
        if ((int)newest_ts - (int)user->cur_ts >= 4100)
        {
             //user->force_i_frame = 1;
        }
    }
    return ret;
}
int send_realtime_audio(int index, int buf_start, const fshare_attr_t *fattr)
{
    st_User *user = &g_p2ptnp_info.gUser[index];
    int count_down = 0;
    for (;;)
    {
        unsigned int buf_size = 0;
        int ret = p2p_checkbuf(user->SessionHandle, CHANNEL_AUDIO, &buf_size, NULL);
        if (ret != 0)
        {
            return ret;
        }
        if (buf_size <= MAX_AUDIO_FRAME_CACHE_SIZE)
        {
            break;
        }
        if (count_down > 20)
        {
            return -1;
        }
        ms_sleep(100);
        count_down++;
    }
    buf_start -= sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
    return p2p_send_frame_data(index, 1, SIO_TYPE_AUDIO, -1, fattr, user->buff + buf_start, fattr->size);
}
int do_realtime_play(int index, int begin_playing)
{
    fshare_reader_id_t reader_id = FSHARE_READER_P2P + index;
	static int last_send_seq[MAX_SESSION_NUM] = {0};
    st_User *user = &g_p2ptnp_info.gUser[index];
    unsigned short read_mask = user->resolution == 0 ? FSHARE_CH_VID : FSHARE_CH_VID_SUB;
    if (begin_playing || user->pre_resolution != user->resolution || user->force_i_frame == 1)
    {
        read_mask |= FSHARE_NAL_SPS;
        user->pre_resolution = user->resolution;
        user->force_i_frame = 0;
    }
    if (user->bAudioRequested == 1)
    {
        read_mask |= FSHARE_CH_AUD;
    }
    if (user->fshare_read_mask != read_mask)
    {
        fshare_set_read_mask(reader_id, read_mask);
        user->fshare_read_mask = read_mask;
    }
    fshare_attr_t fattr;
    int buf_start = sizeof(user->vps) + sizeof(user->sps) + sizeof(user->pps) \
        + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
    int frame_size;
    if (begin_playing)
    {
        fshare_set_read_pos(reader_id, 0);
        frame_size = fshare_must_read_newest(reader_id, &user->buff, (int *)&user->max_buff_size, buf_start, &fattr);
		last_send_seq[index] = fattr.seq;
    }
    else
    {
        frame_size = fshare_must_read(reader_id, &user->buff, (int *)&user->max_buff_size, buf_start, &fattr);
    }
    if (frame_size > 0)
    {
        if (fattr.type & FSHARE_CH_AUD)
        {
            send_realtime_audio(index, buf_start, &fattr);
        }
        else
        {
			if((fattr.seq - last_send_seq[index]) > 3){
				if((fattr.type & FSHARE_NAL_IDR) || (fattr.type & FSHARE_NAL_SPS) || (fattr.type & FSHARE_NAL_PPS)){
					//I sps pps  send frame
					//printf("send frame type=%x\n",fattr.type);
				}
				else{//丢掉
					return 0;
				}
			}
			last_send_seq[index] = fattr.seq;
            send_realtime_video(index, buf_start, &fattr);
        }
    }
	return 0;
}

int send_record_video(int index, mp4trackinfo *mp4info, time_t replaytime, int resolution)
{
    unsigned char sps_pps_buf[sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t) + 200];
	unsigned char *sps_pps_ptr = NULL;
	fshare_attr_t frame_attr = {0};
	unsigned char *ptr_data = NULL;
	unsigned int buf_size = 0;
	int channel = 0;
	int max_cache_size = 0;
	int count_down = 0;
	int size = 0;
	int ret = 0;
	//int trycnt = 0;

	if(g_p2ptnp_info.gUser[index].buff == NULL)
	{
		g_p2ptnp_info.gUser[index].buff = (unsigned char*)malloc(g_p2ptnp_info.gUser[index].max_buff_size);
	}

	ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);
	sps_pps_ptr =  sps_pps_buf + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

    int is_sync;
	size = get_video_replay_frame(ptr_data, mp4info, g_p2ptnp_info.gUser[index].max_buff_size, &is_sync, g_p2ptnp_info.gUser[index].record_speed);
	if(size > 0)
	{
        int vps_len = 0;
        const unsigned char *vps = mp4read_get_vps(mp4info->handle, mp4info->videotrack, &vps_len);
        if (vps_len > 0)
        {
            frame_attr.type = FSHARE_IS_H265; // p2p_send_frame_data() use this flag when send video frame
        }

		do
		{
			if (is_sync)
			{
				static char tag[4] = {0x00, 0x00, 0x00, 0x01};
				int sps_len = 0, pps_len = 0;
				///unsigned int sps_buf_size = 0;
				///unsigned int left_size = 0;
                const unsigned char *sps = mp4read_get_sps(mp4info->handle, mp4info->videotrack, &sps_len);
				const unsigned char *pps = mp4read_get_pps(mp4info->handle, mp4info->videotrack, &pps_len);

				///sps_buf_size = sizeof(sps_pps_buf);
				///left_size = sps_buf_size - sizeof(st_AVStreamIOHead) - sizeof(FRAMEINFO_t);
				///get_next_video_frame(NAL_SPS, resolution, sps_pps_ptr, &g_p2ptnp_info.gUser[index].buff, left_size, &sps_buf_size, &g_p2ptnp_info.gUser[index].video_index, &frame_attr, 0);
                int width, height;
                mp4read_get_video_info(mp4info->handle, mp4info->videotrack, &width, &height);
                frame_attr.vpara.width = width;
                frame_attr.vpara.height = height;
				g_p2ptnp_info.gUser[index].width = frame_attr.vpara.width;
				g_p2ptnp_info.gUser[index].height = frame_attr.vpara.height;
				frame_attr.sec = replaytime + mp4info->video_sampleid*mp4info->video_timescale/1000;
				frame_attr.ts = replaytime*1000 + mp4info->video_sampleid*mp4info->video_timescale;

				channel = CHANNEL_VIDEO_RECORD_IFRAME;
				max_cache_size = MAX_I_FRAME_CACHE_SIZE;
				count_down = 0;
				while(1)
				{
					ret = p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, channel, &buf_size, NULL);
					if(0==ret)
					{
						if(buf_size > max_cache_size)
						{
							if(count_down > 100)
							{
								return -1;
							}
							else
							{
								count_down++;
								ms_sleep(20);
								continue;
							}
						}
						else
						{
							break;
						}
					}
					else
					{
						return ret;
					}
				}

                if (vps_len > 0)
                {
                    memset(sps_pps_buf, 0, sps_pps_ptr - sps_pps_buf);
                    memcpy(sps_pps_ptr, tag, 4);
                    memcpy(sps_pps_ptr + 4, vps, vps_len);
                    ret = p2p_send_frame_data(index, 0, SIO_TYPE_VIDEO, IPC_FRAME_FLAG_IFRAME, &frame_attr,
                                              sps_pps_buf, vps_len + 4);
                }

				memset(sps_pps_buf, 0, sps_pps_ptr - sps_pps_buf);
				memcpy(sps_pps_ptr, tag, 4);
				memcpy(sps_pps_ptr + 4, sps, sps_len);
				ret = p2p_send_frame_data(index, 0, SIO_TYPE_VIDEO, IPC_FRAME_FLAG_IFRAME, &frame_attr, sps_pps_buf, sps_len + 4);
				//dump_string(_F_, _FU_, _L_, "send_record_video send sps, replay_time = %ld, time_stamp = %ld, ret = %d\n", g_p2ptnp_info.gUser[index].replay_time, frame_attr.timestamp, ret);

				memset(sps_pps_buf, 0, sps_pps_ptr - sps_pps_buf);
				memcpy(sps_pps_ptr, tag, 4);
				memcpy(sps_pps_ptr + 4, pps, pps_len);
				ret = p2p_send_frame_data(index, 0, SIO_TYPE_VIDEO, IPC_FRAME_FLAG_IFRAME, &frame_attr, sps_pps_buf, pps_len + 4);
				//dump_string(_F_, _FU_, _L_, "send_record_video send pps, replay_time = %ld, time_stamp = %ld, ret = %d\n", g_p2ptnp_info.gUser[index].replay_time, frame_attr.timestamp, ret);

				ret = p2p_send_frame_data(index, 0, SIO_TYPE_VIDEO, IPC_FRAME_FLAG_IFRAME, &frame_attr, g_p2ptnp_info.gUser[index].buff, size);
				//dump_string(_F_, _FU_, _L_, "send_record_video send i frame, replay_time = %ld, time_stamp = %ld, ret = %d\n", g_p2ptnp_info.gUser[index].replay_time, frame_attr.timestamp, ret);
            }
			else
			{
				channel = CHANNEL_VIDEO_RECORD_PFRAME;
				max_cache_size = MAX_REALTIME_P_FRAME_CACHE_SIZE;
				count_down = 0;
				while(1)
				{
					ret = p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, channel, &buf_size, NULL);
					if(0==ret)
					{
						if(buf_size > max_cache_size)
						{
							if(count_down > 100)
							{
								return -1;
							}
							else
							{
								count_down++;
								ms_sleep(20);
								continue;
							}
						}
						else
						{
							break;
						}
					}
					else
					{
						return ret;
					}
				}
				frame_attr.sec = replaytime + mp4info->video_sampleid*mp4info->video_timescale/1000;
				frame_attr.ts = replaytime*1000 + mp4info->video_sampleid*mp4info->video_timescale;
				ret = p2p_send_frame_data(index, 0, SIO_TYPE_VIDEO, IPC_FRAME_FLAG_PBFRAME, &frame_attr, g_p2ptnp_info.gUser[index].buff, size);
				//dump_string(_F_, _FU_, _L_, "send_record_video send p frame, replay_time = %ld, time_stamp = %ld, ret = %d\n", g_p2ptnp_info.gUser[index].replay_time, frame_attr.timestamp, ret);
			}

#if 0
			if(ret < 0)
			{
				trycnt++;
				//dump_string(_F_, _FU_, _L_, "send fail so resend %d\n", trycnt);
				if(trycnt > 20)
				{
					return ret;
				}
				ms_sleep(100);
			}
#endif
		}
		while(ret == 0);
	}
	else if(size == -1)
	{
		g_p2ptnp_info.gUser[index].file_switch = 1;
		return -1;
	}

	return ret;
}

int send_record_audio(int index, mp4trackinfo *mp4info, time_t replaytime)
{
	fshare_attr_t frame_attr = {0};
	unsigned char *ptr_data = NULL;
	int size = 0;
	int ret = 0;
	unsigned int buf_size = 0;

	ret = p2p_checkbuf(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_AUDIO, &buf_size, NULL);

	if(ret >= 0)
	{
		if(buf_size > MAX_AUDIO_FRAME_CACHE_SIZE)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	if(g_p2ptnp_info.gUser[index].buff == NULL)
	{
		g_p2ptnp_info.gUser[index].buff = (unsigned char*)malloc(g_p2ptnp_info.gUser[index].max_buff_size);
	}

	ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

	size = get_audio_replay_frame(ptr_data, mp4info, g_p2ptnp_info.gUser[index].max_buff_size);
	if(size > 0)
	{
		frame_attr.sec = replaytime + mp4info->audio_sampleid*mp4info->audio_timescale/1000;
		frame_attr.ts = replaytime*1000 + mp4info->audio_sampleid*mp4info->audio_timescale;

		ret = p2p_send_frame_data(index, 0, SIO_TYPE_AUDIO, -1, &frame_attr, g_p2ptnp_info.gUser[index].buff, size);
		//dump_string(_F_, _FU_, _L_, "send_record_audio, ret = %d\n", ret);
	}

	return ret;
}

int do_record_play(int index)
{
	SMsgAVIoctrlPlayRecord *p = NULL;
	unsigned char *ptr_data = NULL;
	int do_init_mp4file = 0;
	unsigned int max_buff_size = 0;

	if(g_p2ptnp_info.gUser[index].buff == NULL)
	{
		g_p2ptnp_info.gUser[index].buff = (unsigned char*)malloc(g_p2ptnp_info.gUser[index].max_buff_size);
	}

	ptr_data = g_p2ptnp_info.gUser[index].buff + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t);

	p = &g_p2ptnp_info.gUser[index].record_ctrl;

	if(0!=g_p2ptnp_info.gUser[index].record_crtl_refreshed)
	{
		g_p2ptnp_info.gUser[index].record_crtl_refreshed = 0;
		close_replay_frame(&g_p2ptnp_info.gUser[index].mp4info);

		dump_string(_F_, _FU_, _L_, "record play control [%d] chn %d\n", index, ntohl(p->channel));
		dump_string(_F_, _FU_, _L_, "	   : command=0x%X\n", ntohl(p->command));
		dump_string(_F_, _FU_, _L_, "	   : Param=%d\n",  ntohl(p->Param));
		dump_string(_F_, _FU_, _L_, "	   : stTimeDay=%d-%d-%d W:%d %d:%d:%d\n",
							ntohs(p->stTimeDay.year),p->stTimeDay.month,p->stTimeDay.day, p->stTimeDay.wday,
							p->stTimeDay.hour,p->stTimeDay.minute,p->stTimeDay.second);

		g_p2ptnp_info.gUser[index].replay_time = mymktime(ntohs(p->stTimeDay.year),p->stTimeDay.month, p->stTimeDay.day,
											 p->stTimeDay.hour,p->stTimeDay.minute,p->stTimeDay.second);

		if(REGION_CHINA == g_p2ptnp_info.mmap_info->region_id)
		{
			g_p2ptnp_info.gUser[index].replay_time = g_p2ptnp_info.gUser[index].replay_time - g_p2ptnp_info.mmap_info->ts;
			dump_string(_F_, _FU_, _L_, "convert replay_time:%d\n", g_p2ptnp_info.gUser[index].replay_time);
		}

		do_init_mp4file = 1;
	}

	if(g_p2ptnp_info.gUser[index].pre_resolution != g_p2ptnp_info.gUser[index].resolution)
	{
		g_p2ptnp_info.gUser[index].pre_resolution = g_p2ptnp_info.gUser[index].resolution;
		close_replay_frame(&g_p2ptnp_info.gUser[index].mp4info);

		g_p2ptnp_info.gUser[index].replay_time = g_p2ptnp_info.gUser[index].replay_time+
			g_p2ptnp_info.gUser[index].mp4info.video_sampleid*g_p2ptnp_info.gUser[index].mp4info.video_timescale/1000;

		do_init_mp4file = 1;
		dump_string(_F_, _FU_, _L_, "change resolution");
	}

	if(g_p2ptnp_info.gUser[index].pre_record_speed != g_p2ptnp_info.gUser[index].record_speed
        #if 0
        && ((g_p2ptnp_info.gUser[index].pre_record_speed > 1 && g_p2ptnp_info.gUser[index].record_speed == 1)
            || (g_p2ptnp_info.gUser[index].pre_record_speed <= 1 && g_p2ptnp_info.gUser[index].record_speed > 1))
        #endif
            )
	{
		g_p2ptnp_info.gUser[index].pre_record_speed = g_p2ptnp_info.gUser[index].record_speed;
		close_replay_frame(&g_p2ptnp_info.gUser[index].mp4info);

		g_p2ptnp_info.gUser[index].replay_time = g_p2ptnp_info.gUser[index].replay_time+
			g_p2ptnp_info.gUser[index].mp4info.video_sampleid*g_p2ptnp_info.gUser[index].mp4info.video_timescale/1000;

		do_init_mp4file = 1;
		dump_string(_F_, _FU_, _L_, "change record speed");
	}

	if(g_p2ptnp_info.gUser[index].file_switch == 1)
	{
		close_replay_frame(&g_p2ptnp_info.gUser[index].mp4info);
		g_p2ptnp_info.gUser[index].replay_time += g_p2ptnp_info.gUser[index].playDuration;
		g_p2ptnp_info.gUser[index].file_switch = 0;
		do_init_mp4file = 1;
		dump_string(_F_, _FU_, _L_, "do file_switch\n");
	}

	if(1==do_init_mp4file)
	{
		char filename[256] = {0};
		unsigned int  rcd_start_time = 0, fileDuration = 0;

        if(g_p2ptnp_info.gUser[index].record_speed < 1)
        {
            g_p2ptnp_info.gUser[index].record_speed = 1;
        }
        else if(g_p2ptnp_info.gUser[index].record_speed > 32)
        {
            g_p2ptnp_info.gUser[index].record_speed = 32;
        }

		do_init_mp4file = 0;

		rcd_start_time = get_filename_by_time(g_p2ptnp_info.gUser[index].replay_time, filename, sizeof(filename), &fileDuration);

		if(rcd_start_time > 0)
		{
			max_buff_size = g_p2ptnp_info.gUser[index].max_buff_size - sizeof(st_AVStreamIOHead) - sizeof(FRAMEINFO_t);
            g_p2ptnp_info.gUser[index].playDuration = fileDuration;
			if(init_replay_frame(ptr_data, &g_p2ptnp_info.gUser[index].buff, filename, (unsigned int*)&g_p2ptnp_info.gUser[index].replay_time,
				rcd_start_time, fileDuration, g_p2ptnp_info.gUser[index].resolution, g_p2ptnp_info.gUser[index].record_speed, &g_p2ptnp_info.gUser[index].mp4info, max_buff_size, &g_p2ptnp_info.gUser[index].max_buff_size) > 0)
			{
				dump_string(_F_, _FU_, _L_, "init_replay_frame file(%s) success", filename);
			}
			else
			{
				g_p2ptnp_info.gUser[index].bVideoRequested = 1;
				g_p2ptnp_info.gUser[index].bRecordPlay = 0;
				dump_string(_F_, _FU_, _L_, "init_replay_frame file(%s) fail", filename);
				return -1;
			}
		}
		else
		{
			g_p2ptnp_info.gUser[index].bVideoRequested = 1;
			g_p2ptnp_info.gUser[index].bRecordPlay = 0;
			dump_string(_F_, _FU_, _L_, "got file(%s) fail", filename);
			return -1;
		}
	}

	send_record_video(index, &g_p2ptnp_info.gUser[index].mp4info, g_p2ptnp_info.gUser[index].replay_time/* + g_p2ptnp_info.mmap_info->ts*/,
		g_p2ptnp_info.gUser[index].resolution);
	if(g_p2ptnp_info.gUser[index].bAudioRequested == 1 && g_p2ptnp_info.gUser[index].record_speed <= 1)
	{
		send_record_audio(index, &g_p2ptnp_info.gUser[index].mp4info, g_p2ptnp_info.gUser[index].replay_time/* + g_p2ptnp_info.mmap_info->ts*/);
	}

	return 0;
}

int do_speaker(int index, char *recv_buf)
{
	int recv_len = 0;
	int expect_len = 0;
	int total_len = 0;
	unsigned char audio_data_buf[1024] = {0};
	st_AVStreamIOHead *io_stream_head = NULL;
	FRAMEINFO_t *frame_head = NULL;
	short codec_id = 0;
	fshare_attr_t info = {0};
    static volatile unsigned short fshare_w_seq = 0;
	int ret = 0;
	//int i = 0;
	//int framesize = 324;

	io_stream_head = (st_AVStreamIOHead *)recv_buf;
	expect_len = ntohl(io_stream_head->nDataSize);

	recv_len = expect_len;

	//printf("do_speaker rcv(%d)\n", recv_len);

	if((recv_len>0)&&(recv_len<1024))
	{
		ret = PPPP_Read(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_AUDIO, recv_buf + sizeof(st_AVStreamIOHead), &recv_len, 10);
		//dump_string(_F_, _FU_, _L_, "expect_len = %d, recv_len = %d\n", expect_len, recv_len);

		if(ret == ERROR_PPPP_SUCCESSFUL && expect_len == recv_len)
		{
			frame_head = (FRAMEINFO_t *)(recv_buf + sizeof(st_AVStreamIOHead));
			total_len = sizeof(st_AVStreamIOHead) + ntohl(io_stream_head->nDataSize);

			codec_id = ntohs(frame_head->codec_id);

			//dump_string(_F_, _FU_, _L_, "sequence = %d\n", ntohs(frame_head->sequence));
			//dump_string(_F_, _FU_, _L_, "timestamp = %d\n", ntohl(frame_head->timestamp));
			//dump_string(_F_, _FU_, _L_, "codec_id = %d\n", ntohs(frame_head->codec_id));

			//if(codec_id == SPEAKER_G726_TAG)
			if(1)
			{
				//dump_string(_F_, _FU_, _L_, "SPEAKER_AAC_TAG\n");

				if(ntohl(frame_head->timestamp) != 0)
				{
					total_len -= (sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t));
                    if(g_p2ptnp_info.gUser[index].tnp_ver > TNP_VERSION_1 && g_p2ptnp_info.gUser[index].encrypt == 1)
                    {
                        if(0 == strlen(g_p2ptnp_info.gUser[index].password))
                        {
                            dump_string(_F_, _FU_, _L_, "p2p audio decrypt, password is NULL\n");
                            return 0;
                        }
                        char *real_data = recv_buf+sizeof(st_AVStreamIOHead)+sizeof(FRAMEINFO_t);
                        int decrypt_block_len = total_len/16;
                        char decrypt_key[20] = {0};
                        memcpy(decrypt_key, g_p2ptnp_info.gUser[index].password, 15);
                        decrypt_key[15] = '0';
                        AesSetKeyDirect(&aes_dec, (const unsigned char *)decrypt_key, 16, NULL, AES_DECRYPTION);
                        int i = 0;
                        for(i=0; i<decrypt_block_len; i++)
                        {
                            AesDecryptDirect(&aes_dec, (unsigned char*)(audio_data_buf+16*i), (const unsigned char*)(real_data+16*i));
                        }
                        memcpy(audio_data_buf+16*decrypt_block_len, real_data+decrypt_block_len*16, total_len%16);
                    }
                    else
                    {
                        memcpy(audio_data_buf, recv_buf + sizeof(st_AVStreamIOHead) + sizeof(FRAMEINFO_t), total_len);
                    }

					info.size = total_len;
					info.ts = ntohl(frame_head->timestamp);

					//dump_mem("audio mem", info.size - 4, audio_data_buf + 4, info.size - 4);

					///MediaDataPut(MMAP_CHN_REPLY_AUD, audio_data_buf, info.size, &info);
                    info.seq = ++fshare_w_seq;
                    info.type = FSHARE_CH_AUD_REPLY;

					#if 0
						FILE *pfile;
						pfile = fopen("/tmp/sd/fromPhone.aac", "ab");
						if (pfile == NULL)
						{
							loge("ao aac failed!\n");						}
						else
						{
							//loge("ok!\n");
						}
						fwrite(audio_data_buf, 1, total_len, pfile);
						fclose(pfile);
					#endif

                    fshare_write(audio_data_buf, &info);

			#if 0
					info.size = framesize;
					info.timestamp = ntohl(frame_head->timestamp);

					//dump_mem("audio mem", info.size - 4, audio_data_buf + 4, info.size - 4);

					for(i=0;i<total_len/framesize;i++)
					{
						MediaDataPut(MMAP_CHN_REPLY_AUD, audio_data_buf+i*framesize, info.size, &info);
						//dump_mem("audio mem", 16, audio_data_buf+i*framesize, 16);
					}
			#endif

				}
			}
			else if(codec_id == CHN_REPORT_TAG)
			{
				//dump_string(_F_, _FU_, _L_, "CHN_REPORT_TAG\n");
			}
			else if(codec_id == CHN_PACKETLOSS_REPORT_TAG)
			{
				//dump_string(_F_, _FU_, _L_, "CHN_PACKETLOSS_REPORT_TAG\n");
			}
		}
	}

	return 0;
}

int start_speaker(int index)
{
	char recv_buf[1088] = {0};
	int recv_len = 0;
	int expect_len = 0;
	st_AVStreamIOHead *io_stream_head = NULL;
	int ret = 0;

	expect_len = sizeof(st_AVStreamIOHead);
	recv_len = expect_len;
	ret = PPPP_Read(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_AUDIO, recv_buf, &recv_len, 10);
	//dump_string(_F_, _FU_, _L_, "expect_len = %d, recv_len = %d\n", expect_len, recv_len);
	io_stream_head = (st_AVStreamIOHead *)recv_buf;
	if(ret != ERROR_PPPP_SUCCESSFUL)
	{
		if(io_stream_head->nVersion == 0 && io_stream_head->nStreamIOType == 0)
		{
			//dump_string(_F_, _FU_, _L_, "PPPP_Read fail, ret = %d!\n", ret);
			return -1;
		}
	}

	//dump_string(_F_, _FU_, _L_, "io_stream_head len = %d\n", ntohl(io_stream_head->nDataSize));
	//dump_string(_F_, _FU_, _L_, "io_stream_head type = %d\n", io_stream_head->nStreamIOType);

	if(io_stream_head->nStreamIOType != SIO_TYPE_AUDIO)
	{
		//dump_string(_F_, _FU_, _L_, "io_stream_head type error!\n");
		return -1;
	}

	#if 0
	if(ntohl(io_stream_head->nDataSize) != sizeof(FRAMEINFO_t) + AUDIO_DATA_FIX_LEN)
	{
		//dump_string(_F_, _FU_, _L_, "io_stream_head len error!\n");
		return -1;
	}
	#endif

	//if(io_stream_head->nVersion == tnp_version)
	{
		do_speaker(index, recv_buf);
	}

	return 0;
}

void *speaker_worker(void *arg)
{
	int i = 0;
	int nospeaker = 1;

	for(;;)
	{
		nospeaker = 1;

		for(i=0;i<MAX_SESSION_NUM;i++)
		{
			if(USER_STATE_USED==g_p2ptnp_info.gUser[i].bUsed)
			{
				start_speaker(i);
				nospeaker = 0;
			}
		}

		if(1==nospeaker)
		{
			ms_sleep(20);
		}
	}

	pthread_exit(0);
}

// added by Frank Zhang
void *report_version_worker(void *arg)
{
	for(;;)
	{
	    if(xlink_report_version(g_p2ptnp_info.mmap_info->mac) >= 0)
	    {
	        if(strcmp(g_p2ptnp_info.mmap_info->xlinkinfo.auth_code,xlink_get_authcode()) != 0)
            {
                xlink_info info;
                memset(&info,0,sizeof(info));
                memcpy(&info,&g_p2ptnp_info.mmap_info->xlinkinfo,sizeof(info));
                memset(&info.auth_code,0,sizeof(info.auth_code));
                //info.bupdated = 0;
                snprintf(info.auth_code, sizeof(info.auth_code), "%s", xlink_get_authcode());
                if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_XLINK_INFO, (char *)&info, sizeof(info)) < 0)
                {
                    dump_string(_F_, _FU_, _L_, "p2p_set_xlink_info send_msg fail!\n");
                    return -1;
                }
                else
                {
                    dump_string(_F_, _FU_, _L_, "p2p_set_xlink_info send_msg ok!\n");
                }
            }
	        break;
	    }
		sleep(10);
	}
	pthread_exit(0);
}

#ifdef YI_RTMP_CLIENT

int p2ptnp_send_rtmp(int status)
{
	if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_RTMP_CHANGE, (char *)&status, sizeof(status)) < 0)
	{
		printf("p2ptnp_send_rtmp send_msg fail!\n");
		return -1;
	}
	else
	{
		printf("p2ptnp_send_rtmp send_msg ok!\n");
	}
    return 0;
}
#endif

int p2p_send_auth_result(int index, ENUM_AVIOCTRL_MSGTYPE ioctrl_type, UINT16 nIOCtrlCmdNum, int result)
{
	char send_buf[1024] = {0};
	int send_len = 0;
	st_AVStreamIOHead *io_stream_head = NULL;
	st_AVIOCtrlHead *io_ctrl_head = NULL;
	int ret = 0;

	io_stream_head = (st_AVStreamIOHead *)send_buf;
	io_stream_head->nDataSize = htonl(sizeof(st_AVIOCtrlHead));
	io_stream_head->nStreamIOType = SIO_TYPE_IOCTRL;
	io_stream_head->nVersion = g_p2ptnp_info.gUser[index].tnp_ver;

	io_ctrl_head = (st_AVIOCtrlHead *)(send_buf + sizeof(st_AVStreamIOHead));
	io_ctrl_head->nIOCtrlCmdNum = htons(nIOCtrlCmdNum);
	io_ctrl_head->nExHeaderSize = htons(0);
	io_ctrl_head->nIOCtrlDataSize = htons(0);

	switch(ioctrl_type)
	{
		case IOTYPE_USER_IPCAM_DEVINFO_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_DEVINFO_RESP);
			break;

		case IOTYPE_USER_IPCAM_LISTEVENT_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_LISTEVENT_RESP);
			break;

		case IOTYPE_USER_TNP_EVENT_LIST_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_TNP_EVENT_LIST_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_RESOLUTION:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_RESOLUTION_RESP);
			break;

		case IOTYPE_USER_IPCAM_GET_RESOLUTION:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_RESOLUTION_RESP);
			break;

		case IOTYPE_USER_IPCAM_GET_VERSION:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_GET_VERSION_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_SILENT_MODE:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_SILENT_MODE_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_LIGHT:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_LIGHT_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_MIRROR_FLIP:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_MIRROR_FLIP_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_RECORD_MOD:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_RECORD_MOD_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_UPDATE_URI:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_UPDATE_URI_RESP_V2);
			break;

		case IOTYPE_USER_IPCAM_SET_TF_FORMATE:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_TF_FORMATE_RESP);
			break;

		case IOTYPE_USER_IPCAM_AUTH_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_AUTH_RESP);
			break;
		default:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_RESP);
			break;
	}

	io_ctrl_head->authHead.authResult = htonl(result);

	send_len = sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead);

	ret = PPPP_Write(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, send_buf, send_len);

	dump_string(_F_, _FU_, _L_, "p2p_send_auth_result, index=%d, type=0x%02x, resp_type=0x%02x, result=%d\n", index, ioctrl_type, ntohs(io_ctrl_head->nIOCtrlType), result);

	return ret;
}

int p2p_send_unsupported_version_reply(int index, ENUM_AVIOCTRL_MSGTYPE ioctrl_type, UINT16 nIOCtrlCmdNum)
{
	char send_buf[1024] = {0};
	int send_len = 0;
	st_AVStreamIOHead *io_stream_head = NULL;
	st_AVIOCtrlHead *io_ctrl_head = NULL;
	int ret = 0;

	io_stream_head = (st_AVStreamIOHead *)send_buf;
	io_stream_head->nDataSize = htonl(sizeof(st_AVIOCtrlHead));
	io_stream_head->nStreamIOType = SIO_TYPE_IOCTRL;
	io_stream_head->nVersion = tnp_version;

	io_ctrl_head = (st_AVIOCtrlHead *)(send_buf + sizeof(st_AVStreamIOHead));
	io_ctrl_head->nIOCtrlCmdNum = htons(nIOCtrlCmdNum);
	io_ctrl_head->nExHeaderSize = htons(0);
	io_ctrl_head->nIOCtrlDataSize = htons(0);

	switch(ioctrl_type)
	{
		case IOTYPE_USER_IPCAM_DEVINFO_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_DEVINFO_RESP);
			break;

		case IOTYPE_USER_IPCAM_LISTEVENT_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_LISTEVENT_RESP);
			break;

		case IOTYPE_USER_TNP_EVENT_LIST_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_TNP_EVENT_LIST_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_RESOLUTION:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_RESOLUTION_RESP);
			break;

		case IOTYPE_USER_IPCAM_GET_RESOLUTION:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_RESOLUTION_RESP);
			break;

		case IOTYPE_USER_IPCAM_GET_VERSION:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_GET_VERSION_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_SILENT_MODE:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_SILENT_MODE_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_LIGHT:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_LIGHT_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_MIRROR_FLIP:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_MIRROR_FLIP_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_RECORD_MOD:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_RECORD_MOD_RESP);
			break;

		case IOTYPE_USER_IPCAM_SET_UPDATE_URI:

			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_UPDATE_URI_RESP_V2);
			break;

		case IOTYPE_USER_IPCAM_SET_TF_FORMATE:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_SET_TF_FORMATE_RESP);
			break;

		case IOTYPE_USER_IPCAM_AUTH_REQ:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_AUTH_RESP);
			break;

		default:
			io_ctrl_head->nIOCtrlType = htons(IOTYPE_USER_IPCAM_RESP);
			break;
	}

	io_ctrl_head->authHead.authResult = htonl(AUTH_UNSUPPORTED_VERSION);

	send_len = sizeof(st_AVStreamIOHead) + sizeof(st_AVIOCtrlHead);

	ret = PPPP_Write(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, send_buf, send_len);

	dump_string(_F_, _FU_, _L_, "p2p_send_auth_result, index=%d, type=0x%02x, resp_type=0x%02x\n", index, ioctrl_type, ntohs(io_ctrl_head->nIOCtrlType));

	return ret;
}

int do_auth(unsigned char *auth_info, int index)
{
	char local_info[64] = {0};
	char local_hmac[64] = {0};
	char local_base64[64] = {0};
	char auth_nonce[32]= {0};
    char auth_cmd_nonce[32]= {0};
	char auth_base64[32]= {0};
	char tmp_info[32] = {0};
	int i = 0;

	snprintf(tmp_info, sizeof(tmp_info), "%s", auth_info);
	sscanf((char *)tmp_info, "%[0-9A-Za-z],%s", auth_nonce, auth_base64);
	//dump_string(_F_, _FU_, _L_, "auth_nonce=%s, auth_base64=%s\n", auth_nonce, auth_base64);

	if(factory_mode == 1)
	{
		return AUTH_OK;
	}

	if(g_p2ptnp_info.mmap_info->debug_mode == 1)
	{
	    if(strncmp(auth_nonce, g_p2ptnp_info.mmap_info->p2pid, 15) == 0 && strncmp(auth_base64, g_p2ptnp_info.mmap_info->p2pid, 15) == 0)
	    {
			g_p2ptnp_info.gUser[index].use_test_auth = 1;
			return AUTH_OK;
	    }
	}

	if(strlen(g_p2ptnp_info.gUser[index].password) == 0)
	{
	    if(g_p2ptnp_info.gUser[index].tnp_ver > TNP_VERSION_1)
        {
    	    if(strlen(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_session_nonce) == 0)
            {
                strncpy(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_session_nonce, auth_nonce, P2P_AUTH_SESSION_NONCE_LEN);
            }
            else if(0 != strncmp(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_session_nonce, auth_nonce, P2P_AUTH_SESSION_NONCE_LEN))
            {
            	dump_string(_F_, _FU_, _L_, "session nonce not match!\n");
                return AUTH_BAD_SESSION_NONCE;
            }

            strncpy(auth_cmd_nonce, auth_nonce+P2P_AUTH_SESSION_NONCE_LEN, P2P_AUTH_CMD_NONCE_LEN);
        }
        else
        {
            strncpy(auth_cmd_nonce, auth_nonce, sizeof(auth_cmd_nonce)-1);
        }

		for(i = g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce; i < g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce + MAX_P2P_AUTH_NONCE; i++)
		{
			if(strcmp(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[i%MAX_P2P_AUTH_NONCE], auth_cmd_nonce) == 0)
			{
				dump_string(_F_, _FU_, _L_, "lately used nonce!\n");
				return AUTH_BAD_NONCE;
			}
		}

        dump_string(_F_, _FU_, _L_, "tmp_pwd:%s,pwd:%s,pre_pwd:%s\n",g_p2ptnp_info.mmap_info->tmp_pwd,g_p2ptnp_info.mmap_info->pwd,g_p2ptnp_info.mmap_info->pre_pwd);

		if(strlen(g_p2ptnp_info.mmap_info->pwd) != 0)
		{
			snprintf(local_info, sizeof(local_info), "user=xiaoyiuser&nonce=%s", auth_nonce);
			hmac_sha1(g_p2ptnp_info.mmap_info->pwd, strlen(g_p2ptnp_info.mmap_info->pwd), local_info, strlen(local_info), local_hmac);
			base64_encode((unsigned char *)local_hmac, local_base64, 20);
			dump_string(_F_, _FU_, _L_, "local_hmac:%s,local_pass=%s, local_base64=%s auth_base64:%s\n",local_hmac, g_p2ptnp_info.mmap_info->pwd, local_base64,auth_base64);

			if(memcmp(local_base64, auth_base64, 15) == 0)
			{
				strncpy(g_p2ptnp_info.gUser[index].password, g_p2ptnp_info.mmap_info->pwd, sizeof(g_p2ptnp_info.gUser[index].password));
				memset(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], 0, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
				strncpy(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], auth_cmd_nonce, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
				g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce = (g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce+1)%MAX_P2P_AUTH_NONCE;
				p2p_set_pwd_used_cnt();
				return AUTH_OK;
			}
            else if(strlen(g_p2ptnp_info.mmap_info->tmp_pwd) != 0 && 0 != strcmp(g_p2ptnp_info.mmap_info->pwd, g_p2ptnp_info.mmap_info->tmp_pwd))
            {
    			hmac_sha1(g_p2ptnp_info.mmap_info->tmp_pwd, strlen(g_p2ptnp_info.mmap_info->tmp_pwd), local_info, strlen(local_info), local_hmac);
    			base64_encode((unsigned char *)local_hmac, local_base64, 20);

    			if(memcmp(local_base64, auth_base64, 15) == 0)
    			{
    				strncpy(g_p2ptnp_info.gUser[index].password, g_p2ptnp_info.mmap_info->tmp_pwd, sizeof(g_p2ptnp_info.gUser[index].password));
    				memset(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], 0, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
    				strncpy(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], auth_cmd_nonce, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
    				g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce = (g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce+1)%MAX_P2P_AUTH_NONCE;
                    dump_string(_F_, _FU_, _L_, "p2p session use tmp password\n");
    				return AUTH_OK;
    			}
            }
		}
		else if(strlen(g_p2ptnp_info.mmap_info->pre_pwd) != 0)
		{
			snprintf(local_info, sizeof(local_info), "user=xiaoyiuser&nonce=%s", auth_nonce);
			hmac_sha1(g_p2ptnp_info.mmap_info->pre_pwd, strlen(g_p2ptnp_info.mmap_info->pre_pwd), local_info, strlen(local_info), local_hmac);
			base64_encode((unsigned char *)local_hmac, local_base64, 20);
			//dump_string(_F_, _FU_, _L_, "local_pass=%s, local_base64=%s\n", g_p2ptnp_info.mmap_info->pre_pwd, local_base64);

			if(memcmp(local_base64, auth_base64, 15) == 0)
			{
				strncpy(g_p2ptnp_info.gUser[index].password, g_p2ptnp_info.mmap_info->pre_pwd, sizeof(g_p2ptnp_info.gUser[index].password));
				memset(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], 0, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
				strncpy(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], auth_cmd_nonce, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
				g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce = (g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce+1)%MAX_P2P_AUTH_NONCE;
				p2p_set_pwd_used_cnt();
				return AUTH_OK;
			}
		}
		else
		{
			dump_string(_F_, _FU_, _L_, "send 01 DISPATCH_SET_P2P_PWDWRONG msg\n");
			return AUTH_FAIL;
		}
	}
	else
	{
		if(g_p2ptnp_info.gUser[index].tnp_ver > TNP_VERSION_1)
        {
    	    if(strlen(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_session_nonce) == 0)
            {
                strncpy(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_session_nonce, auth_nonce, P2P_AUTH_SESSION_NONCE_LEN);
            }
            else if(0 != strncmp(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_session_nonce, auth_nonce, P2P_AUTH_SESSION_NONCE_LEN))
            {
            	dump_string(_F_, _FU_, _L_, "session nonce not match!\n");
                return AUTH_BAD_SESSION_NONCE;
            }

            strncpy(auth_cmd_nonce, auth_nonce+P2P_AUTH_SESSION_NONCE_LEN, P2P_AUTH_CMD_NONCE_LEN);
        }
        else
        {
            strncpy(auth_cmd_nonce, auth_nonce, sizeof(auth_cmd_nonce)-1);
        }

		for(i = g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce; i < g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce + MAX_P2P_AUTH_NONCE; i++)
		{
			if(strcmp(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[i%MAX_P2P_AUTH_NONCE], auth_cmd_nonce) == 0)
			{
				dump_string(_F_, _FU_, _L_, "lately used nonce!\n");
				return AUTH_BAD_NONCE;
			}
		}

		snprintf(local_info, sizeof(local_info), "user=xiaoyiuser&nonce=%s", auth_nonce);
		hmac_sha1(g_p2ptnp_info.gUser[index].password, strlen(g_p2ptnp_info.gUser[index].password), local_info, strlen(local_info), local_hmac);
		base64_encode((unsigned char *)local_hmac, local_base64, 20);
		//dump_string(_F_, _FU_, _L_, "local_pass=%s, local_base64=%s\n", g_p2ptnp_info.gUser[index].password, local_base64);

		if(memcmp(local_base64, auth_base64, 15) == 0)
		{
			memset(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], 0, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
			strncpy(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce], auth_cmd_nonce, sizeof(g_p2ptnp_info.gUser[index].p2p_nonce.p2p_auth_cmd_nonce[g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce]));
			g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce = (g_p2ptnp_info.gUser[index].p2p_nonce.cur_nonce+1)%MAX_P2P_AUTH_NONCE;
			return AUTH_OK;
		}
		else
		{
			dump_string(_F_, _FU_, _L_, "send 02 DISPATCH_SET_P2P_PWDWRONG msg\n");
			return AUTH_FAIL;
		}

	}

	dump_string(_F_, _FU_, _L_, "send 03 DISPATCH_SET_P2P_PWDWRONG msg\n");
	return AUTH_FAIL;
}

int add_viewer(int index)
{
	int i = 0;

	pthread_mutex_lock(&viewer_table_lock);

	for(i = 0; i < MAX_VIEWING_NUM; i++)
	{
		if(g_p2ptnp_info.viewer_table[i] == -1)
		{
			g_p2ptnp_info.viewer_table[i] = index;
			pthread_mutex_unlock(&viewer_table_lock);
			return 0;
		}
	}

	pthread_mutex_unlock(&viewer_table_lock);

	return -1;
}

int remove_viewer(int index)
{
	int i = 0, j = 0;

	pthread_mutex_lock(&viewer_table_lock);

	for(i = 0; i < MAX_VIEWING_NUM; i++)
	{
		if(g_p2ptnp_info.viewer_table[i] == index)
		{
			for(j = i; j < MAX_VIEWING_NUM - 1; j++)
			{
				g_p2ptnp_info.viewer_table[j] = g_p2ptnp_info.viewer_table[j + 1];
			}
			g_p2ptnp_info.viewer_table[j] = -1;
			pthread_mutex_unlock(&viewer_table_lock);
			return 0;
		}
	}

	pthread_mutex_unlock(&viewer_table_lock);

	return -1;
}

int kick_earliest_viewer()
{
	int index  = g_p2ptnp_info.viewer_table[0];

	report_tnp_ipcam_kicked(index);

	sleep(3);

	remove_viewer(index);
	g_p2ptnp_info.gUser[index].bUsed = USER_STATE_CLOSED;

	return 0;
}

int get_video_viewing_session_num()
{
	int index = 0;
	int count = 0;

	for(index = 0; index < MAX_SESSION_NUM; index++)
	{
		if(g_p2ptnp_info.gUser[index].view_state == 1)
		{
			count++;
		}
	}

	return count;
}
#if defined(PRODUCT_R40GA)
int p2p_get_white_light_alarm_time(int index, UINT16 nIOCtrlCmdNum)
{
	SMsAVIoctrlWhiteLightAlarmTime Rsp;
	int ret = 0;
	memset(&Rsp, 0, sizeof(SMsAVIoctrlWhiteLightAlarmTime));
	dump_string(_F_, _FU_, _L_, "white_light_alarm_time: %d\n",g_p2ptnp_info.mmap_info->white_light_alarm_time);
	Rsp.white_light_alarm_time = htonl(g_p2ptnp_info.mmap_info->white_light_alarm_time);
	ret = p2p_send_ctrl_data(index, IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_ALARM_TIME_RESP, nIOCtrlCmdNum, (char *)&Rsp, sizeof(SMsAVIoctrlWhiteLightAlarmTime));
	return ret;
}
int p2p_set_white_light_alarm_time(int alarm_time)
{
	int count_down = 0;

    if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_WHITE_LIGHT_ALARM_TIME, (char *)&alarm_time, sizeof(alarm_time)) < 0)
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_white_light_alarm_time %d send_msg fail!\n", alarm_time);
        return -1;
    }
    else
    {
        dump_string(_F_, _FU_, _L_, "p2p_set_white_light_alarm_time %d send_msg ok!\n", alarm_time);

    	count_down = 10;
		while(count_down)
		{
			count_down--;
			if(g_p2ptnp_info.mmap_info->white_light_alarm_time == alarm_time)
			{
        		break;
			}
			usleep(100*1000);
		}

		return 0;
    }
}

#endif
void myDoIOCtrl(INT32 iIndex, CHAR *pData)
{
	st_AVIOCtrlHead *io_ctrl_head = NULL;
	ENUM_AVIOCTRL_MSGTYPE nIOCtrlType = 0;
	UINT16 nExHeaderSize = 0;
	UINT16 nIOCtrlCmdNum = 0;
	UINT16 nIOCtrlDataSize = 0;
	char url[512] = {0};
	int value_net = 0;
	int value = 0;
	int auth_ret = 0;

	if(pData == NULL)
	{
		return;
	}

	io_ctrl_head = (st_AVIOCtrlHead *)pData;
	nIOCtrlType = ntohs(io_ctrl_head->nIOCtrlType);
	nIOCtrlCmdNum = ntohs(io_ctrl_head->nIOCtrlCmdNum);
	nExHeaderSize = ntohs(io_ctrl_head->nExHeaderSize);
	nIOCtrlDataSize = ntohs(io_ctrl_head->nIOCtrlDataSize);

	if(nExHeaderSize != 0)
	{
		//do something
	}

	auth_ret = do_auth(io_ctrl_head->authHead.authInfo, iIndex);

	dump_string(_F_, _FU_, _L_, "auth_ret(..): %d", auth_ret);
	if(auth_ret != AUTH_OK || nIOCtrlType == IOTYPE_USER_IPCAM_AUTH_REQ)
	{
		p2p_send_auth_result(iIndex, nIOCtrlType, nIOCtrlCmdNum, auth_ret);
		return;
	}

	switch(nIOCtrlType)
	{
		case IOTYPE_USER_IPCAM_START_KEY:
		{
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_START_KEY\n", iIndex);
			SMsgAVIoctrlUseCount *uc_p = NULL;

			g_p2ptnp_info.gUser[iIndex].video_index = -1;
			g_p2ptnp_info.gUser[iIndex].bRecordPlay = 0;
			g_p2ptnp_info.gUser[iIndex].encrypt = 1;
			uc_p = (SMsgAVIoctrlUseCount *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			g_p2ptnp_info.gUser[iIndex].usecount = ntohl(uc_p->usecount);
			g_p2ptnp_info.gUser[iIndex].bVideoRequested = 1;
			if(g_p2ptnp_info.gUser[iIndex].view_state == 0)
			{
				p2p_send_viewing();
				g_p2ptnp_info.gUser[iIndex].view_state = 1;
			}

			break;
		}

		case IOTYPE_USER_TNP_IPCAM_START_KEY:
		{
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_TNP_IPCAM_START_KEY\n", iIndex);
			tnp_ipcamstart_msg_s *tis_p = NULL;
			int view_count = 0;
			int play_flag = 0;

			tis_p = (tnp_ipcamstart_msg_s *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			view_count = get_video_viewing_session_num();
			if(g_p2ptnp_info.gUser[iIndex].view_state == 0 && view_count + 1 > MAX_VIEWING_NUM)
			{
				if(tis_p->cmd_vesion >= TNP_IPCAM_CMD_VER_1)
				{
					kick_earliest_viewer();
					play_flag = 1;
				}
				else
				{
					dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, reach MAX_VIEWING_NUM\n", iIndex);
					play_flag = 0;
				}
			}
			else
			{
				play_flag = 1;
			}

			if(play_flag == 1)
			{
				set_resolution(iIndex, tis_p->usecount, tis_p->resolution, -1);
				g_p2ptnp_info.gUser[iIndex].usecount = tis_p->usecount;
				g_p2ptnp_info.gUser[iIndex].video_index = -1;
				g_p2ptnp_info.gUser[iIndex].bRecordPlay = 0;
				g_p2ptnp_info.gUser[iIndex].encrypt = 1;
				g_p2ptnp_info.gUser[iIndex].bVideoRequested = 1;
				if(g_p2ptnp_info.gUser[iIndex].view_state == 0)
				{
					p2p_send_viewing();
					g_p2ptnp_info.gUser[iIndex].view_state = 1;
					view_count++;
					add_viewer(iIndex);
				}
                g_p2ptnp_info.gUser[iIndex].videoStartTime = g_p2ptnp_info.mmap_info->systick;
			}

			break;
		}

		case IOTYPE_USER_TNP_IPCAM_START_REPLAY_KEY:
		{
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_TNP_IPCAM_START_REPLAY_KEY\n", iIndex);
			tnp_ipcamreplay_msg_s *tir_p = NULL;
			int view_count = 0;
			int play_flag = 0;

			tir_p = (tnp_ipcamreplay_msg_s *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			view_count = get_video_viewing_session_num();
			if(g_p2ptnp_info.gUser[iIndex].view_state == 0 && view_count + 1 > MAX_VIEWING_NUM)
			{
				if(tir_p->cmd_vesion >= TNP_IPCAM_CMD_VER_1)
				{
					kick_earliest_viewer();
					play_flag = 1;
				}
				else
				{
					dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, reach MAX_VIEWING_NUM\n", iIndex);
					play_flag = 0;
				}
			}
			else
			{
				play_flag = 1;
			}

			if(play_flag == 1)
			{
				set_resolution(iIndex, tir_p->usecount, tir_p->resolution, -1);
				if(g_p2ptnp_info.mmap_info->sd_size> 0 && (gEventLog != NULL && gEventLog->num > 0))
				{
					memset(&g_p2ptnp_info.gUser[iIndex].record_ctrl, 0, sizeof(SMsgAVIoctrlPlayRecord));
					memcpy(&g_p2ptnp_info.gUser[iIndex].record_ctrl.stTimeDay, &(tir_p->replay_time), sizeof(STimeDay));
					g_p2ptnp_info.gUser[iIndex].bRecordPlay = 1;
					g_p2ptnp_info.gUser[iIndex].encrypt = 1;
					g_p2ptnp_info.gUser[iIndex].usecount = tir_p->usecount;
					g_p2ptnp_info.gUser[iIndex].bVideoRequested = 1;
					g_p2ptnp_info.gUser[iIndex].record_ctrl.command = htonl(AVIOCTRL_RECORD_PLAY_START);
					g_p2ptnp_info.gUser[iIndex].record_ctrl.usecount = tir_p->usecount;
					g_p2ptnp_info.gUser[iIndex].record_crtl_refreshed = 1;
					reply_tnp_record_play(iIndex, AVIOCTRL_RECORD_PLAY_START, nIOCtrlCmdNum);
					dump_string(_F_, _FU_, _L_, "do_replay\n");
				}
				else
				{
					g_p2ptnp_info.gUser[iIndex].video_index = -1;
					g_p2ptnp_info.gUser[iIndex].bRecordPlay = 0;
					g_p2ptnp_info.gUser[iIndex].encrypt = 1;
					g_p2ptnp_info.gUser[iIndex].usecount = tir_p->usecount;
					g_p2ptnp_info.gUser[iIndex].bVideoRequested = 1;
					reply_tnp_record_play(iIndex, AVIOCTRL_RECORD_PLAY_STOP, nIOCtrlCmdNum);
					dump_string(_F_, _FU_, _L_, "do_replay but no sd card\n");
				}
				if(g_p2ptnp_info.gUser[iIndex].view_state == 0)
				{
					p2p_send_viewing();
					g_p2ptnp_info.gUser[iIndex].view_state = 1;
					view_count++;
					add_viewer(iIndex);
				}
			}

			break;
		}

		case IOTYPE_USER_IPCAM_STOP:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_STOP\n", iIndex);
			g_p2ptnp_info.gUser[iIndex].bVideoRequested = 0;
			g_p2ptnp_info.gUser[iIndex].bAudioRequested = 0;
			if(g_p2ptnp_info.gUser[iIndex].view_state == 1)
			{
				p2p_send_stop_viewing();
			}
			g_p2ptnp_info.gUser[iIndex].view_state = 0;
			remove_viewer(iIndex);
			break;

		case IOTYPE_USER_TNP_EVENT_LIST_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_TNP_EVENT_LIST_REQ\n", iIndex);
			tnp_reply_event_list(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_AUDIOSTART:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_AUDIOSTART\n", iIndex);
			g_p2ptnp_info.gUser[iIndex].audio_index = -1;
			g_p2ptnp_info.gUser[iIndex].bAudioRequested = 1;
			break;

		case IOTYPE_USER_IPCAM_AUDIOSTOP:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_AUDIOSTOP\n", iIndex);
			g_p2ptnp_info.gUser[iIndex].bAudioRequested = 0;
			break;

		case IOTYPE_USER_IPCAM_SPEAKERSTART:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SPEAKERSTART\n", iIndex);
			g_p2ptnp_info.gUser[iIndex].bSpeakerStart = 1;

			//fengwu add
			if(nIOCtrlCmdNum == 1) // earphone mode
			{
				if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_APP_MODE_EARPHONE, NULL, 0) < 0)
    			{
        			dump_string(_F_, _FU_, _L_, "RMM_APP_MODE_EARPHONE send_msg fail!\n");
    			}
			}
			else if (nIOCtrlCmdNum == 2) // speaker mode
			{
				if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_APP_MODE_SPKER, NULL, 0) < 0)
    			{
        			dump_string(_F_, _FU_, _L_, "RMM_APP_MODE_SPKER send_msg fail!\n");
    			}

			}
			else
			{
				if(p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, RMM_APP_MODE_SPKER, NULL, 0) < 0)
    			{
        			dump_string(_F_, _FU_, _L_, "RMM_APP_MODE_SPKER send_msg fail!\n");
    			}
			}
			break;

		case IOTYPE_USER_IPCAM_SPEAKERSTOP:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SPEAKERSTOP\n", iIndex);
			g_p2ptnp_info.gUser[iIndex].bSpeakerStart = 0;
			break;

		case IOTYPE_USER_IPCAM_DEVINFO_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_DEVINFO_REQ\n", iIndex);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_DEVINFO_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_LISTEVENT_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_LISTEVENT_REQ\n", iIndex);
			reply_event_list(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_RECORD_PLAYCONTROL_KEY:
		{
			SMsgAVIoctrlPlayRecord *pr_p = NULL;
			pr_p = (SMsgAVIoctrlPlayRecord *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_RECORD_PLAYCONTROL_KEY p->command(0x%x)\n", iIndex, ntohl(pr_p->command));

			if(AVIOCTRL_RECORD_PLAY_START == ntohl(pr_p->command) || AVIOCTRL_RECORD_PLAY_SEEKTIME == ntohl(pr_p->command))
			{
				if(g_p2ptnp_info.mmap_info->sd_size> 0 && (gEventLog != NULL && gEventLog->num > 0))
				{
					memset(&g_p2ptnp_info.gUser[iIndex].record_ctrl, 0, sizeof(SMsgAVIoctrlPlayRecord));
					memcpy(&g_p2ptnp_info.gUser[iIndex].record_ctrl, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, sizeof(SMsgAVIoctrlPlayRecord));
					g_p2ptnp_info.gUser[iIndex].record_crtl_refreshed = 1;
					g_p2ptnp_info.gUser[iIndex].usecount = pr_p->usecount;
					g_p2ptnp_info.gUser[iIndex].bRecordPlay = 1;
					g_p2ptnp_info.gUser[iIndex].encrypt = 1;
					g_p2ptnp_info.gUser[iIndex].bVideoRequested = 1;
					dump_string(_F_, _FU_, _L_, "do_replay\n");
				}
				else
				{
					g_p2ptnp_info.gUser[iIndex].video_index = -1;
					g_p2ptnp_info.gUser[iIndex].bRecordPlay = 0;
					g_p2ptnp_info.gUser[iIndex].encrypt = 1;
					g_p2ptnp_info.gUser[iIndex].usecount = pr_p->usecount;
					g_p2ptnp_info.gUser[iIndex].bVideoRequested = 1;
					dump_string(_F_, _FU_, _L_, "do_replay but no sd card\n");
				}
				if(g_p2ptnp_info.gUser[iIndex].view_state == 0)
				{
					p2p_send_viewing();
					g_p2ptnp_info.gUser[iIndex].view_state = 1;
				}
			}
			else
			{
				g_p2ptnp_info.gUser[iIndex].bRecordPlay = 0;
				g_p2ptnp_info.gUser[iIndex].bVideoRequested = 0;
				close_replay_frame(&g_p2ptnp_info.gUser[iIndex].mp4info);
				dump_string(_F_, _FU_, _L_, "do_replay stop\n");
				if(g_p2ptnp_info.gUser[iIndex].view_state == 1)
				{
					p2p_send_stop_viewing();
					g_p2ptnp_info.gUser[iIndex].view_state = 0;
				}
			}
			break;
		}

		case IOTYPE_USER_IPCAM_SET_RESOLUTION:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_RESOLUTION\n", iIndex);
			SMsgAVIoctrlResolutionMode *rsl_p = NULL;
			rsl_p = (SMsgAVIoctrlResolutionMode *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			g_p2ptnp_info.gUser[iIndex].usecount = ntohl(rsl_p->usecount);
			set_resolution(iIndex, ntohl(rsl_p->usecount), ntohl(rsl_p->resolution), nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_GET_RESOLUTION:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_RESOLUTION\n", iIndex);
			get_resolution(iIndex, nIOCtrlCmdNum);
			break;

        case IOTYPE_USER_IPCAM_SET_RECORD_SPEED:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_RECORD_SPEED\n", iIndex);
            SMsgAVIoctrlRecordSpeed *spd_p = NULL;
            spd_p = (SMsgAVIoctrlRecordSpeed *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
            g_p2ptnp_info.gUser[iIndex].usecount = ntohl(spd_p->usecount);
            set_record_speed(iIndex, ntohl(spd_p->usecount), ntohl(spd_p->speed), nIOCtrlCmdNum);
            break;

        case IOTYPE_USER_IPCAM_GET_RECORD_SPEED:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_RECORD_SPEED\n", iIndex);
            get_record_speed(iIndex, nIOCtrlCmdNum);
            break;

		case IOTYPE_USER_IPCAM_GET_VERSION:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_VERSION\n", iIndex);
			get_version(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_SILENT_MODE:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_SILENT_MODE\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			if(value == 0)
			{
				p2p_set_power(DISPATCH_SET_POWER_ON);
			}
			else if(value == 1)
			{
				p2p_set_power(DISPATCH_SET_POWER_OFF);
			}
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_SILENT_MODE_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_LIGHT:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_LIGHT\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			if(value == 0)
			{
				p2p_set_light(DISPATCH_SET_LIGHT_ON);
			}
			else if(value == 1)
			{
				p2p_set_light(DISPATCH_SET_LIGHT_OFF);
			}
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_LIGHT_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_MIRROR_FLIP:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_MIRROR_FLIP\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			if(value == 1)
			{
				p2p_set_mirror_flip(DISPATCH_SET_MIRROR_ON);
			}
			else if(value == 0)
			{
				p2p_set_mirror_flip(DISPATCH_SET_MIRROR_OFF);
			}
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_MIRROR_FLIP_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_RECORD_MOD:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_RECORD_MOD\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			if(value == 0)
			{
				p2p_set_motion_record(DISPATCH_SET_MOTION_RCD);
			}
			else if(value == 1)
			{
				p2p_set_motion_record(DISPATCH_SET_ALWAYS_RCD);
			}
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_RECORD_MOD_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_MOTION_DETECT:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_MOTION_DETECT\n", iIndex);
			SMsAVIoctrlMotionDetectCfg *mdc_p = NULL;
			mdc_p = (SMsAVIoctrlMotionDetectCfg *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			p2p_set_motion_detect(iIndex, mdc_p, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_GET_MOTION_DETECT:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_MOTION_DETECT\n", iIndex);
			p2p_get_motion_detect(iIndex, nIOCtrlCmdNum);
			break;
		//case 0x1230:   //运动控制按钮 当做人形检测 
        case IOTYPE_USER_IPCAM_SET_ALARM_MODE:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ALARM_MODE\n", iIndex);
            SMsAVIoctrlAlarmMode *am_p = NULL;
            am_p = (SMsAVIoctrlAlarmMode *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
            if((htonl(am_p->alarm_mode) == 2 ) && (nIOCtrlType == 0x1230)){
				p2p_set_alarm_mode(0);
			}
			else{
				p2p_set_alarm_mode(htonl(am_p->alarm_mode));
			}
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ALARM_MODE_RESP, nIOCtrlCmdNum);
            break;

#ifdef HAVE_FEATURE_FACE
		case IOTYPE_USER_IPCAM_SET_FACE_ENABLE:
	            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_FACE_ENABLE\n", iIndex);
	            SMsAVIoctrlFaceEnable *fc_p = NULL;
	            fc_p = (SMsAVIoctrlFaceEnable *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
	            #if !defined(NOT_PLT_API)
	            p2p_set_human_face(ntohl(fc_p->face_enable));
	            #else
	            p2p_set_human_face(htonl(fc_p->face_enable));
	            #endif
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_FACE_ENABLE_RESP, nIOCtrlCmdNum);
	            break;
#endif
		case IOTYPE_USER_IPCAM_SET_UPDATE_URI:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_UPDATE_URI\n", iIndex);
			memset_s(url, sizeof(url), 0, sizeof(url));
			memcpy_s(url, sizeof(url), pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, nIOCtrlDataSize);
			do_update(iIndex, nIOCtrlCmdNum);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_UPDATE_URI_RESP_V2, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_TF_FORMATE:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_TF_FORMATE\n", iIndex);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_TF_FORMATE_RESP, nIOCtrlCmdNum);
			p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, DISPATCH_SET_SD_FORMAT, NULL, 0);
			break;

		case IOTYPE_USER_IPCAM_SET_DAYNIGHT_MODE:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_DAYNIGHT_MODE\n", iIndex);
			SMsAVIoctrlDayNightMode *dn_p = NULL;
			dn_p = (SMsAVIoctrlDayNightMode *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			value = ntohl(dn_p->mode);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			p2p_set_day_night_mode(RMM_SET_DAY_NIGHT_MODE, value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_DAYNIGHT_MODE_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_ALARM_SENSITIVITY:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ALARM_SENSITIVITY\n", iIndex);
			SMsAVIoctrlSensitivityCfg *sst_p = NULL;
			sst_p = (SMsAVIoctrlSensitivityCfg *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			p2p_set_alarm_sensitivity(htonl(sst_p->sensitivity));
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ALARM_SENSITIVITY_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_VIDEO_BACKUP_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_VIDEO_BACKUP_REQ\n", iIndex);
			video_backup_state_set *bus_p = NULL;
			bus_p = (video_backup_state_set *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			p2p_set_video_backup_state(iIndex, bus_p, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_GET_VIDEO_BACKUP_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_VIDEO_BACKUP_REQ\n", iIndex);
			p2p_get_video_backup_state(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_ENCODING_MODE_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ENCODING_MODE_REQ\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			p2p_set_encode_mode(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ENCODING_MODE_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_HIGH_RESOLUTION_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_HIGH_RESOLUTION_REQ\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value = %d\n", value);
			p2p_set_high_resolution(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_HIGH_RESOLUTION_RESP, nIOCtrlCmdNum);
			break;

#if 1
		case IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERIFY_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERITY_REQ\n", iIndex);
			//char *code_in = (char *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			//IaaAec_VerifyKey(code_in);
			//int iLen = IaaAec_GetKeyLen();
			//IaaAec_GenKey(g_p2ptnp_info.mmap_info->aec_key);
			reply_aec_key_verify(iIndex, nIOCtrlCmdNum);
			break;
#else
		case IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERIFY_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_DO_MSTAR_AEC_VERITY_REQ\n", iIndex);
			char *code_in = (char *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			IaaAec_VerifyKey(code_in);
			int iLen = IaaAec_GetKeyLen();
			char *code_out = (char*)malloc(iLen+1);
			if(NULL == code_out)
			{
				loge("malloc code_out fail\n");
				break;
			}
			IaaAec_GenKey(code_out);
			reply_aec_key_verify(iIndex, nIOCtrlCmdNum, code_out);
			free(code_out);
			break;
#endif

		case IOTYPE_USER_PTZ_PRESET_ADD_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_PRESET_ADD_REQ\n", iIndex);
			p2p_ptz_preset_add(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PTZ_PRESET_DEL_REQ:
		{
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_PRESET_DEL_REQ\n", iIndex);
			SMsgAVIoctrlPTZPresetCall *ppc_p = NULL;
			ppc_p = (SMsgAVIoctrlPTZPresetCall *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_preset_del(iIndex, ntohl(ppc_p->preset_id), nIOCtrlCmdNum);
			break;
		}

		case IOTYPE_USER_PTZ_PRESET_CALL_REQ:
		{
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_PRESET_CALL_REQ\n", iIndex);
			SMsgAVIoctrlPTZPresetCall *ppc_p = NULL;
			ppc_p = (SMsgAVIoctrlPTZPresetCall *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_preset_call(iIndex, ntohl(ppc_p->preset_id), nIOCtrlCmdNum);
			break;
		}

		case IOTYPE_USER_PTZ_SET_CURISE_STAY_TIME_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_SET_CURISE_STAY_TIME_REQ\n", iIndex);
			SMsgAVIoctrlPTZCruiseStayTime *cst_p = NULL;
			cst_p = (SMsgAVIoctrlPTZCruiseStayTime *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_set_cruise_stay_time(iIndex, ntohl(cst_p->cruise_mode), ntohl(cst_p->stay_time), nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PTZ_SET_CRUISE_PERIOD_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_SET_CRUISE_PERIOD_REQ\n", iIndex);
			SMsgAVIoctrlPTZCruisePeroidSet *cps_p = NULL;
			cps_p = (SMsgAVIoctrlPTZCruisePeroidSet *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_set_cruise_period(iIndex, ntohl(cps_p->start_time), ntohl(cps_p->end_time), nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PTZ_SET_MOTION_TRACK_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_SET_MOTION_TRACK_REQ\n", iIndex);
			SMsgAVIoctrlPTZMotionTrackSet *mts_p = NULL;
			mts_p = (SMsgAVIoctrlPTZMotionTrackSet *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_set_motion_track(iIndex, ntohl(mts_p->motion_track_switch), nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PTZ_SET_CRUISE_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_SET_CRUISE_REQ\n", iIndex);
			SMsgAVIoctrlPTZCruiseSet *pcs_p = NULL;
			pcs_p = (SMsgAVIoctrlPTZCruiseSet *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_set_cruise(iIndex, ntohl(pcs_p->cruise_switch), nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PTZ_DIRECTION_CTRL:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_DIRECTION_CTRL\n", iIndex);
			SMsgAVIoctrlPTZDireCtrl *pdc_p = NULL;
			pdc_p = (SMsgAVIoctrlPTZDireCtrl *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_direction_ctrl(ntohl(pdc_p->direction), ntohl(pdc_p->speed));
			break;

		case IOTYPE_USER_PTZ_DIRECTION_CTRL_STOP:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_DIRECTION_CTRL_STOP\n", iIndex);
			p2p_ptz_direction_ctrl_stop();
			break;

		case IOTYPE_USER_PTZ_HOME:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_HOME\n", iIndex);
			p2p_ptz_home();
			break;

		case IOTYPE_USER_PTZ_JUMP_TO_POINT:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PTZ_JUMP_TO_POINT\n", iIndex);
			SMsgAVIoctrlPTZJumpPointSet *pjps_p = NULL;
			pjps_p = (SMsgAVIoctrlPTZJumpPointSet *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
			p2p_ptz_jump_to_point(ntohl(pjps_p->transverse_proportion), ntohl(pjps_p->longitudinal_proportion));
			break;

		case IOTYPE_USER_PANORAMA_CAPTURE_START:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PANORAMA_CAPTURE_START\n", iIndex);
			p2p_start_panorama_capture(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PANORAMA_CAPTURE_ABORT:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PANORAMA_CAPTURE_ABORT\n", iIndex);
			p2p_abort_panorama_capture(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_PANORAMA_CAPTURE_SCHEDULE_POLLING:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_PANORAMA_CAPTURE_SCHEDULE_POLLING\n", iIndex);
			p2p_schedule_panorama_capture_report(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_GET_FACTORY_TEST_INFO_REQ:
			reply_factory_test_info(iIndex, nIOCtrlCmdNum);
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_FACTORY_TEST_INFO_REQ\n", iIndex);
			break;

		case IOTYPE_USER_IPCAM_TRIGGER_SYNC_INFO_FROM_SERVER_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_TRIGGER_SYNC_INFO_FROM_SERVER_REQ\n", iIndex);
			p2p_sync_info_from_server(iIndex, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_LDC:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_LDC\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_ldc(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_LDC_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_BABY_CRY:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_BABY_CRY\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_baby_cry(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_BABY_CRY_RSP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_MIC_VOLUME:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_MIC_VOLUME\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_mic_volume(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_MIC_VOLUME_RESP, nIOCtrlCmdNum);
			break;

        case IOTYPE_USER_IPCAM_SET_VIEWPOINT_TRACE:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_VIEWPOINT_TRACE\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_viewpoint_trace(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_VIEWPOINT_TRACE_RESP, nIOCtrlCmdNum);
			break;

        case IOTYPE_USER_IPCAM_SET_VOICE_CTRL_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_VOICE_CTRL_REQ\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_voice_ctrl(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_VOICE_CTRL_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_LAPSE_VIDEO:
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_LAPSE_VIDEO, value = %d\n", iIndex, value);
			p2p_set_lapse_video(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_LAPSE_VIDEO_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_AUDIO_MODE:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_AUDIO_MODE\n", iIndex);
			int *pAudioMode;
			pAudioMode = (int *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
			p2p_set_audio_mode(htonl(*pAudioMode));
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_AUDIO_MODE_RESP, nIOCtrlCmdNum);
			break;

        case IOTYPE_USER_IPCAM_SET_ABNORMAL_SOUND:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ABNORMAL_SOUND\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_abnormal_sound(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ABNORMAL_SOUND_RESP, nIOCtrlCmdNum);
			break;

        case IOTYPE_USER_IPCAM_SET_ABNORMAL_SOUND_SENSITIVITY:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ABNORMAL_SOUND_SENSITIVITY\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_abnormal_sound_sensitivity(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ABNORMAL_SOUND_SENSITIVITY_RESP, nIOCtrlCmdNum);
			break;

		case IOTYPE_USER_IPCAM_SET_WHITE_LED_MODE:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_WHITE_LED_MODE\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_white_led_mode(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_WHITE_LED_MODE_RESP, nIOCtrlCmdNum);
			break;
		case IOTYPE_SET_WHITE_LIGHT_OFF: //white_led 30s need close.
		{
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_SET_WHITE_LIGHT_OFF\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			p2p_set_white_led_close(value);
			reply_dev_info(iIndex, IOTYPE_SET_WHITE_LIGHT_OFF_RESP, nIOCtrlCmdNum);
			break;
		}
		case IOTYPE_GET_WHITE_LIGHT_OFF_STATUS: //app get state white_led 30s need close.
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_GET_WHITE_LIGHT_OFF_STATUS\n", iIndex);
			get_whiteled_close_status(iIndex, nIOCtrlCmdNum);
			break;
        case IOTYPE_USER_IPCAM_SET_ALARM_DIDI_NEW:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ALARM_DIDI_NEW\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value:%d, \n", value);
            ///close 1
            // open 2
            value--;
			p2p_set_alarm(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ALARM_DIDI_NEW_RESP, nIOCtrlCmdNum);
            break;

        case IOTYPE_USER_IPCAM_SET_ALARM_DIDI:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_ALARM_DIDI\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "value:%d, \n", value);
			p2p_set_alarm(value);
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_ALARM_DIDI_RESP, nIOCtrlCmdNum);
            break;
        #if defined(PRODUCT_R40GA)
        case IOTYPE_USER_IPCAM_SET_WHITE_LIGHT_ALARM_TIME:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_WHITE_LIGHT_ALARM_TIME\n", iIndex);
			memcpy_s(&value_net, 4, pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize, 4);
			value = ntohl(value_net);
			dump_string(_F_, _FU_, _L_, "set white_light_alarm_time:%d \n", value);
			p2p_set_white_light_alarm_time(value);
 	        reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_WHITE_LIGHT_ALARM_TIME_RESP, nIOCtrlCmdNum);
            break;
        case IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_ALARM_TIME:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_ALARM_TIME\n", iIndex);
            p2p_get_white_light_alarm_time(iIndex, nIOCtrlCmdNum);
            break;
        #endif
        case IOTYPE_USER_IPCAM_RESET_DEVICE_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_RESET_DEVICE_REQ\n", iIndex);
            p2p_set_soft_reset();
			reply_dev_info(iIndex, IOTYPE_USER_IPCAM_RESET_DEVICE_RESP, nIOCtrlCmdNum);
            break;
        case IOTYPE_USER_IPCAM_RESET_DEVICE_RESP:

            break;
        case IOTYPE_USER_IPCAM_SET_WIFI_INFO:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_WIFI_INFO\n", iIndex);
            char ssid[64]={0};
            char pwd[64]={0};
            char ap_bindkey[42]={0};
            int wifi_mode=0;
            wifi_mode = (g_p2ptnp_info.mmap_info->wifi_mode == WIFI_AP && g_p2ptnp_info.mmap_info->start_with_reset == 0)?WIFI_AP_BIND:WIFI_STATION;
            char *message=(char *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
            if((strlen(message)>0)&&(strlen(message)<171))
            {
                sscanf(message,"%s\n%s\n%s",ssid,pwd,ap_bindkey);
            }
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, get message(%s)\n\tssid(%s) pwd(%s) bindkey(%s)\n", iIndex,message,ssid,pwd,ap_bindkey);
            p2p_send_wifi_conf_msg(g_p2ptnp_info.mqfd_dispatch, MODE_AP, ssid, pwd, ap_bindkey);
            p2p_send_wifi_work_mode(g_p2ptnp_info.mqfd_dispatch, wifi_mode, g_p2ptnp_info.mmap_info->ap_tnp_did);
            reply_dev_info(iIndex, IOTYPE_USER_IPCAM_SET_WIFI_INFO_RESP, nIOCtrlCmdNum);
            break;
        case IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_STATUS:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_WHITE_LIGHT_STATUS\n", iIndex);
			get_white_light_status(iIndex, nIOCtrlCmdNum);
            break;
        case IOTYPE_USER_RESTART_DEVICE_REQ:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_RESTART_DEVICE_REQ\n", iIndex);
            reply_dev_info(iIndex, IOTYPE_USER_RESTART_DEVICE_RESP, nIOCtrlCmdNum);
            restart_device();
            break;
		#if defined(PRODUCT_H31BG) 	
        case IOTYPE_USER_IPCAM_SET_RECORD_MIC_REQ:
			//SMsgAVIoctrlMicAudioReq *micaudio_p = NULL;
			//micaudio_p = (SMsgAVIoctrlMicAudioReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_RECORD_MIC_REQ\n", iIndex);
            set_mic_audio(iIndex, (SMsgAVIoctrlMicAudioReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize)), nIOCtrlCmdNum);
			break;
        case IOTYPE_USER_IPCAM_GET_RECORD_MIC_REQ:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_RECORD_MIC_REQ\n", iIndex);
			get_mic_audio(iIndex, nIOCtrlCmdNum);
			break;	
        case IOTYPE_USER_IPCAM_SET_AUTO_OTA_REQ:
			//SMsgAVIoctrlAutoOTAReq *autoota_p = NULL;
			//autoota_p = (SMsgAVIoctrlAutoOTAReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize));
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_AUTO_OTA_REQ\n", iIndex);
			set_auto_ota(iIndex,(SMsgAVIoctrlAutoOTAReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize)) , nIOCtrlCmdNum);
			break;
        case IOTYPE_USER_IPCAM_GET_AUTO_OTA_REQ:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_AUTO_OTA_REQ\n", iIndex);
			get_auto_ota(iIndex, nIOCtrlCmdNum);
            break;	
		case IOTYPE_USER_IPCAM_SET_NEW_WIFI_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_NEW_WIFI_REQ\n", iIndex);
			p2p_set_new_wifi(iIndex,(SMsgAVIoctrlNewWifiReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize)) , nIOCtrlCmdNum);
			break;
		case IOTYPE_USER_IPCAM_SET_WATER_MARK_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_WATER_MARK_REQ\n", iIndex);
			set_water_mark(iIndex, (SMsgAVIoctrlWatermarkReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize)), nIOCtrlCmdNum);
			break;
		case IOTYPE_USER_IPCAM_GET_WATER_MARK_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_WATER_MARK_REQ\n", iIndex);
			get_water_mark(iIndex, nIOCtrlCmdNum);
			break;	
		case IOTYPE_USER_IPCAM_SET_TIMESTAMP_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_TIMESTAMP_REQ\n", iIndex);
			set_del_timestamp(iIndex, (unsigned int *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize)),nIOCtrlDataSize, nIOCtrlCmdNum);
			break;
        case IOTYPE_USER_IPCAM_SET_MOTION_DETECTION_REQ:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_MOTION_DETECTION_REQ\n", iIndex);
			set_motion_detection(iIndex,(SMsgAVIoctrlMotionDetectionReq *)((pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize)) , nIOCtrlCmdNum);
			break;
        case IOTYPE_USER_IPCAM_GET_MOTION_DETECTION_REQ:
            dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_MOTION_DETECTION_REQ\n", iIndex);
			get_motion_detection(iIndex, nIOCtrlCmdNum);
            break;	
		#endif			
#ifdef AP_MODE
        case IOTYPE_USER_IPCAM_SET_AP_MODE_REQ:
            {
                int ret = -1;
                dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_SET_AP_MODE_REQ\n", iIndex);
                SMsgAVIoctrlApConfResp *rapc_p = NULL;
                rapc_p = (SMsgAVIoctrlApConfResp *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
                dump_string(_F_, _FU_, _L_, "ap_enable: %d, ssid: %s, pwd: %s\n", rapc_p->ap_enable, rapc_p->ssid, rapc_p->pwd);
                ret = p2p_set_ap_conf(rapc_p->ap_enable, rapc_p->ssid, rapc_p->pwd);
                if(ret != 0){
                    reply_set_ap_conf(iIndex, nIOCtrlCmdNum, 0);
                }else{
                    reply_set_ap_conf(iIndex, nIOCtrlCmdNum, 1);
                    system(RESTART_AP);
                }
            }
            break;
        case IOTYPE_USER_IPCAM_GET_AP_MODE_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_AP_MODE_REQ\n", iIndex);
			reply_get_ap_conf(iIndex, nIOCtrlCmdNum);
            break;
        case IOTYPE_USER_IPCAM_GET_DAY_EVENT_LIST_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_DAY_EVENT_LIST_REQ\n", iIndex);
            p2p_alert_days_refresh();
            reply_day_event_list(iIndex, nIOCtrlCmdNum);
            break;
        case IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_REQ:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_USER_IPCAM_GET_ALARM_EVENT_LIST_REQ \n", iIndex);
            int start_time = 0;
            int end_time = 0;
            int *p = (int *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
            start_time = ntohl(*(p+1));
            end_time = ntohl(*(p+2));
            dump_string(_F_, _FU_, _L_, "start time: %d, end time: %d\n", start_time, end_time);
            p2p_alert_event_refresh(start_time, end_time);
			reply_alert_event_list(iIndex, nIOCtrlCmdNum);
			break;
#endif

		case IOTYPE_SET_DEVICE_PARAM:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_SET_DEVICE_PARAM \n", iIndex);
			char *hw_data=(char *)(pData + sizeof(st_AVIOCtrlHead) + nExHeaderSize);
            if(strlen(hw_data) == HW_NUM)
            {
				char cmd[100]={0};
				sprintf(cmd,"/home/app/write_hw %s",hw_data);
                system(cmd);
            }
			else{
				dump_string(_F_, _FU_, _L_, "p2p set hw size err!!!\n");
			}
			reply_hw_value(iIndex,nIOCtrlCmdNum);
		break;

		case IOTYPE_GET_DEVICE_PARAM:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): %d, IOTYPE_GET_DEVICE_PARAM \n", iIndex);
			get_hw_value_resp(iIndex,nIOCtrlCmdNum);
		break;

		default:
			dump_string(_F_, _FU_, _L_, "myDoIOCtrl(..): Unknown command 0x%02x\n", nIOCtrlType);
			break;
	}

	if(factory_mode == 1)
	{
		g_p2ptnp_info.gUser[iIndex].encrypt = 0;
	}

	return;
}

void myReleaseUser(st_User *pstUser)
{
	if(pstUser == NULL)
	{
		return;
	}

	if(pstUser->SessionHandle>=0)
	{
		dump_string(_F_, _FU_, _L_, "start PPPP_ForceClose finish %d\n", pstUser->SessionHandle);
		PPPP_ForceClose(pstUser->SessionHandle);
		dump_string(_F_, _FU_, _L_, "finish PPPP_ForceClose finish %d\n", pstUser->SessionHandle);
	}

	if(pstUser->buff != NULL)
	{
		free(pstUser->buff);
		pstUser->buff = NULL;
	}

	memset(pstUser, 0, sizeof(st_User));
}

int parse_msg(int index)
{
	st_AVStreamIOHead *pStreamIOHead = NULL;
	st_AVIOCtrlHead *io_ctrl_head = NULL;
	char read_buf[1024] = {0};
	int read_len = 0;
	int msg_size = 0;
	int ret = 0;

	read_len = sizeof(st_AVStreamIOHead);

	ret = PPPP_Read(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, read_buf, &read_len, 10);

	/* dump_string(_F_, _FU_, _L_, "ret:%d,read_len:%d\n", ret,read_len); */

	if(!(ret == ERROR_PPPP_TIME_OUT || ret == ERROR_PPPP_SUCCESSFUL))
	{
		g_p2ptnp_info.gUser[index].bUsed = USER_STATE_CLOSED;
		dump_string(_F_, _FU_, _L_, "parse_msg: failed %d SessionHandle(%d)!!\n", ret, g_p2ptnp_info.gUser[index].SessionHandle);
        switch(ret)
        {
            case ERROR_PPPP_NOT_INITIALIZED:
            case ERROR_PPPP_INVALID_PARAMETER:
            case ERROR_PPPP_INVALID_SESSION_HANDLE:
            case ERROR_PPPP_SESSION_DATA_ERROR:
            case ERROR_PPPP_SESSION_CLOSED_INSUFFICIENT_MEMORY:
            {
                char debug_log[128] = {0};
                char uid[8] = {0};
                strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
                snprintf(debug_log, sizeof(debug_log), "uid=%s,readerrcode=%d,session=%d,chn=0", uid, ret, g_p2ptnp_info.gUser[index].SessionHandle);
                p2p_debug_log(1, debug_log);
            }
        }
		return ret;
	}

	if(read_len > 0)
	{
		pStreamIOHead = (st_AVStreamIOHead *)read_buf;
		msg_size = ntohl(pStreamIOHead->nDataSize);
    	dump_string(_F_, _FU_, _L_, "msg_size:%d", msg_size);

		if((msg_size > 0)&&(msg_size < 1024))
		{
			ret = PPPP_Read(g_p2ptnp_info.gUser[index].SessionHandle, CHANNEL_IOCTRL, read_buf + sizeof(st_AVStreamIOHead), &msg_size, 10);

    	    dump_string(_F_, _FU_, _L_, "ret:%d,msg_size:%d", ret,msg_size);
			if(!(ret == ERROR_PPPP_TIME_OUT || ret == ERROR_PPPP_SUCCESSFUL))
			{
				g_p2ptnp_info.gUser[index].bUsed = USER_STATE_CLOSED;
				dump_string(_F_, _FU_, _L_, "parse_msg: failed %d !!\n", ret);
                switch(ret)
                {
                    case ERROR_PPPP_NOT_INITIALIZED:
                    case ERROR_PPPP_INVALID_PARAMETER:
                    case ERROR_PPPP_INVALID_SESSION_HANDLE:
                    case ERROR_PPPP_SESSION_DATA_ERROR:
                    case ERROR_PPPP_SESSION_CLOSED_INSUFFICIENT_MEMORY:
                    {
                        char debug_log[128] = {0};
                        char uid[8] = {0};
                        strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
                        snprintf(debug_log, sizeof(debug_log), "uid=%s,readerrcode2=%d,session=%d,chn=0", uid, ret, g_p2ptnp_info.gUser[index].SessionHandle);
                        p2p_debug_log(1, debug_log);
                    }
                }
				return ret;
			}

			if(msg_size > 0)
			{
			    dump_string(_F_, _FU_, _L_, "nVersion:%d,tnp_version:%d",pStreamIOHead->nVersion,tnp_version);
				if(pStreamIOHead->nVersion == tnp_version)
				//if(1)
				{
					//PPPP_Set_DRW_Mode(g_p2ptnp_info.gUser[index].SessionHandle, (factory_mode == 1)?0:PPPP_DRW_MODE_CH0_CH2_CH4_RELIABLE);
					//PPPP_Set_DRW_Mode(g_p2ptnp_info.gUser[index].SessionHandle, 0xe);
					//dump_string(_F_, _FU_, _L_, "cur p2p version %d(%d)\n", index, tnp_version);
					g_p2ptnp_info.gUser[index].tnp_ver = tnp_version;
					myDoIOCtrl(index, read_buf + sizeof(st_AVStreamIOHead));
				}
				else if(pStreamIOHead->nVersion > tnp_version)
				{
					dump_string(_F_, _FU_, _L_, "unsupport version\n");
					io_ctrl_head = (st_AVIOCtrlHead *)(read_buf + sizeof(st_AVStreamIOHead));
					p2p_send_unsupported_version_reply(index, ntohs(io_ctrl_head->nIOCtrlType), ntohs(io_ctrl_head->nIOCtrlCmdNum));
				}
				else
				{
					//low version compatible
					g_p2ptnp_info.gUser[index].tnp_ver = pStreamIOHead->nVersion;
					if(TNP_VERSION_1==g_p2ptnp_info.gUser[index].tnp_ver)
					{
						myDoIOCtrl(index, read_buf + sizeof(st_AVStreamIOHead));
					}
                    else if(TNP_VERSION_2==g_p2ptnp_info.gUser[index].tnp_ver)
                    {
						myDoIOCtrl(index, read_buf + sizeof(st_AVStreamIOHead));
					}
				}
			}
		}
	}

	return read_len;
}

void *tnp_worker(void *arg)
{
	int index = 0;
	//unsigned int timeout_tick = g_p2ptnp_info.mmap_info->systick + 10*60*5;
	int ret = 0;
    int realtime_playing = 0;

	index  = *((int*)arg);
	pthread_detach(pthread_self());

	g_p2ptnp_info.gUser[index].max_buff_size = 120*1024;
    g_p2ptnp_info.gUser[index].force_i_frame = 1;

    dump_string(_F_, _FU_, _L_, "entry tnp_worker");

	while(1)
	{
		if(g_p2ptnp_info.gUser[index].bUsed == USER_STATE_CLOSED)
		{
			dump_string(_F_, _FU_, _L_, "2 s(%d %d %d)\n", g_p2ptnp_info.gUser[index].SessionHandle, g_p2ptnp_info.gUser[index].bRecordPlay, ret);
			break;
		}

		#if 0
		//if(g_p2ptnp_info.gUser[index].bSpeakerStart == 1)
		{
			if(0==start_speaker(index))
			{
				continue;
			}
		}
		#endif

		ret = parse_msg(index);

		#if 0
		if(ret > 0)
		{
			timeout_tick = g_p2ptnp_info.mmap_info->systick + 10*60*5;
		}

		if(timeout_tick < g_p2ptnp_info.mmap_info->systick)
		{
			g_p2ptnp_info.gUser[index].bUsed = USER_STATE_CLOSED;
			dump_string(_F_, _FU_, _L_, "---%d, force session exit!!\n", index);
			break;
		}
		#endif

		if(g_p2ptnp_info.mmap_info->power_mode == POWER_MODE_OFF_E)
		{
			usleep(100*1000);
			continue;
		}
		//dump_string(_F_, _FU_, _L_, "0 s(%d %d %d)\n", g_p2ptnp_info.gUser[index].SessionHandle, g_p2ptnp_info.gUser[index].bRecordPlay, ret);

		if(g_p2ptnp_info.gUser[index].bRecordPlay == 1)
		{
            realtime_playing = 0;
			do_record_play(index);
		}
        else if (g_p2ptnp_info.gUser[index].bVideoRequested == 1)
		{
            int begin_playing;
            if (!realtime_playing)
            {
                begin_playing = 1;
                realtime_playing = 1;
            }
            else
            {
                begin_playing = 0;
            }
			do_realtime_play(index, begin_playing);
		}
        else
        {
            realtime_playing = 0;
        }
		//dump_string(_F_, _FU_, _L_, "1 s(%d %d %d)\n", g_p2ptnp_info.gUser[index].SessionHandle, g_p2ptnp_info.gUser[index].bRecordPlay, ret);
		//ms_sleep(10);
	}
	p2p_send_disconnected();

    close_replay_frame(&g_p2ptnp_info.gUser[index].mp4info);

	myReleaseUser(&g_p2ptnp_info.gUser[index]);

	p2p_send_stop_viewing();

	dump_string(_F_, _FU_, _L_, "---%d, frame_trans exit!!\n", index);

	g_p2ptnp_info.gUser[index].bUsed = USER_STATE_UNUSED;

	pthread_exit(0);
}

void refresh_tnp_event_list()
{
	record_event_t envent_info;
	int eventnum = 0;
	int tmpi=0;
	time_t t_of_day = 0;
	struct tm *local;

    if (NULL == gEventLog)
    {
        CreatEventlogShareMem();
    }

	if(g_p2ptnp_info.mmap_info->sd_size > 0 && (gEventLog != NULL  && gEventLog->num > 0))
	{
		eventnum = gEventLog->num;
		event_log_get(0, 1, &envent_info);
		dump_string(_F_, _FU_, _L_, "prev newest_end_time is %ld\n", tnp_eventlist_msg.newest_end_time);

		if(tnp_eventlist_msg.newest_end_time != envent_info.end_time)
		{
			pthread_mutex_lock(&event_list_lock);

			tnp_eventlist_msg.newest_end_time = envent_info.end_time;

			for(tmpi = 0; tmpi < eventnum; tmpi++)
			{
				event_log_get(tmpi, 1, &envent_info);

				if(REGION_CHINA == g_p2ptnp_info.mmap_info->region_id)
				{
					envent_info.end_time = envent_info.end_time + g_p2ptnp_info.mmap_info->ts;
					envent_info.start_time = envent_info.start_time + g_p2ptnp_info.mmap_info->ts;
				}

				t_of_day = envent_info.start_time;

				local = gmtime(&t_of_day);
				tnp_eventlist_msg.event[tmpi].starttime.year   = htons(local->tm_year+1900);
				tnp_eventlist_msg.event[tmpi].starttime.month  = local->tm_mon+1;
				tnp_eventlist_msg.event[tmpi].starttime.day	   = local->tm_mday;
				tnp_eventlist_msg.event[tmpi].starttime.hour   = local->tm_hour;
				tnp_eventlist_msg.event[tmpi].starttime.minute = local->tm_min;
				tnp_eventlist_msg.event[tmpi].starttime.second = local->tm_sec;
				tnp_eventlist_msg.event[tmpi].starttime.wday   = local->tm_wday;
				tnp_eventlist_msg.event[tmpi].duration = htonl(envent_info.end_time-envent_info.start_time);
			}

			tnp_eventlist_msg.head.event_cnt = htons(eventnum);

			pthread_mutex_unlock(&event_list_lock);

			dump_string(_F_, _FU_, _L_, "after newest_end_time is %ld\n", tnp_eventlist_msg.newest_end_time);
		}
		dump_string(_F_, _FU_, _L_, "got event(%d)", eventnum);
	}
	else
	{
		pthread_mutex_lock(&event_list_lock);

		tnp_eventlist_msg.head.event_cnt = htons(0);

		pthread_mutex_unlock(&event_list_lock);
	}

	return;
}

int check_p2p_user()
{
	int user_index = 0;
	int got_usr = 0;

	for(user_index = 0; user_index < MAX_SESSION_NUM; user_index++)
	{
		if(USER_STATE_USED == g_p2ptnp_info.gUser[user_index].bUsed)
		{
			got_usr += 1;
			//printf("p2p cur user %d SessionHandle(%d)\n", user_index, g_p2ptnp_info.gUser[user_index].SessionHandle);
		}
	}

	g_p2ptnp_info.user_num = got_usr;

	if(g_p2ptnp_info.max_user_num < got_usr)
	{
		g_p2ptnp_info.max_user_num = got_usr;
	}
	/*
	printf("p2p cur user(%d) max_user_num(%d) in_packet_loss(%d) out_packet_loss(%d)\n",
		got_usr, g_p2ptnp_info.max_user_num, g_p2ptnp_info.mmap_info->in_packet_loss,
		g_p2ptnp_info.mmap_info->out_packet_loss);
	*/
	return got_usr;
}

void *state_statistics(void *arg)
{
	char login_stat = 0;
	int count = 0;
	int fail_cnt = 0;
    const int MAX_FAIL_CNT = 20;
	//char buf[32] = {0};
	int prev_cloud_storage_state = 0, prev_video_backup_state = 0;
	int pre_login_stat = -1;
	int pre_wifi_connected = -1;


	if(g_p2ptnp_info.mmap_info->cloud_storage_enable == 1 || g_p2ptnp_info.mmap_info->video_backup_info.enable == 1)
	{
		PPPP_Share_Bandwidth(0);
	}
	else
	{
		PPPP_Share_Bandwidth(1);
	}

	prev_cloud_storage_state = g_p2ptnp_info.mmap_info->cloud_storage_enable;
	prev_video_backup_state = g_p2ptnp_info.mmap_info->video_backup_info.enable;

	while(1)
	{
		if(count%6 == 0)
		{
			refresh_tnp_event_list();
		}
		if(0==check_p2p_user() && g_p2ptnp_info.mmap_info->p2p_viewing_cnt>0)
		{
			p2p_send_clr_viewing();
		}

		if(g_p2ptnp_info.mmap_info->cloud_storage_enable != prev_cloud_storage_state ||
			g_p2ptnp_info.mmap_info->video_backup_info.enable != prev_video_backup_state)
		{
			if(g_p2ptnp_info.mmap_info->cloud_storage_enable == 1 || g_p2ptnp_info.mmap_info->video_backup_info.enable == 1)
			{
				PPPP_Share_Bandwidth(0);
			}
			else
			{
				PPPP_Share_Bandwidth(1);
			}
		}

		prev_cloud_storage_state = g_p2ptnp_info.mmap_info->cloud_storage_enable;
		prev_video_backup_state = g_p2ptnp_info.mmap_info->video_backup_info.enable;

		#if 0
		if(g_p2ptnp_info.user_num > 1)
		{
			memset_s(buf, sizeof(buf), 0, sizeof(buf));
			system_cmd_withret_timeout("/home/app/script/get_mem.sh", buf, sizeof(buf), 60);
			dump_string(_F_, _FU_, _L_, "get_mem.sh(%sKB)\n", buf);

			if(atoi(buf)>2200)
			{
				dump_string(_F_, _FU_, _L_, "!!!!warn(%sKB)!!!!\n", buf);
				exit(0);
			}
		}
		#endif

		#if 0
		if((g_p2ptnp_info.max_user_num>0)&&(g_p2ptnp_info.user_num==0))
		{
			memset_s(buf, sizeof(buf), 0, sizeof(buf));
			system_cmd_withret_timeout("/home/app/script/get_mem.sh", buf, sizeof(buf), 60);
			dump_string(_F_, _FU_, _L_, "get_mem.sh(%sKB)\n", buf);
			if(atoi(buf)>1500)
			{
				dump_string(_F_, _FU_, _L_, "!!!!warn(%sKB)!!!!\n", buf);
				exit(0);
			}
		}
		#endif

		#if defined(PRODUCT_H31BG)
		get_timer_to_localtime();
		#endif

		sleep(2);
		PPPP_LoginStatus_Check(&login_stat);
	    dump_string(_F_, _FU_, _L_, "!!!!login_stat(%d)!!!!\n", login_stat);

		if(0 == login_stat)
		{
            if(pre_login_stat != login_stat)
            {
                char debug_log[128] = {0};
                char uid[8] = {0};
                strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
                pre_wifi_connected = g_p2ptnp_info.mmap_info->wifi_connected;
                snprintf(debug_log, sizeof(debug_log), "uid=%s,tnploginstat=0,preloginstat=%d,wifistat=%d", uid, pre_login_stat,pre_wifi_connected);
                if(-1 == pre_login_stat)
                {
                    p2p_debug_log(0, debug_log);
                }
                else
                {
                    p2p_debug_log(1, debug_log);
                }
                pre_login_stat = login_stat;
            }
            if(0 != pre_wifi_connected && 0 == g_p2ptnp_info.mmap_info->wifi_connected)
            {
                char debug_log[128] = {0};
                char uid[8] = {0};
                strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
                pre_wifi_connected = 0;
                snprintf(debug_log, sizeof(debug_log), "uid=%s,tnploginstat=0,preloginstat=%d,wifistat=0", uid, pre_login_stat);
                p2p_debug_log(1, debug_log);
            }

			dump_string(_F_, _FU_, _L_, "check_login fail %d\n", login_stat);
			p2p_set_tnp_check_login_fail();
			fail_cnt ++;
			check_login_fail++;
		}
		else
		{
            if(pre_login_stat != login_stat)
            {
                char debug_log[128] = {0};
                char uid[8] = {0};
                strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
                snprintf(debug_log, sizeof(debug_log), "uid=%s,tnploginstat=1,preloginstat=%d,wifistat=%d", uid, pre_login_stat,g_p2ptnp_info.mmap_info->wifi_connected);
                if(-1 == pre_login_stat)
                {
                    p2p_debug_log(0, debug_log);
                }
                else
                {
                    p2p_debug_log(1, debug_log);
                }
                pre_login_stat = login_stat;
            }
			pre_wifi_connected = 1;
			p2p_set_tnp_check_login_success();
			fail_cnt = 0;
			check_login_success++;
		}

        static char pre_p2p_pwd[32] = {0};
        if(0 == strlen(pre_p2p_pwd))
        {
            strncpy(pre_p2p_pwd, g_p2ptnp_info.mmap_info->pwd, sizeof(pre_p2p_pwd));
        }
        if(0 != strcmp(pre_p2p_pwd, g_p2ptnp_info.mmap_info->pwd))
        {
            char debug_log[256] = {0};
            char uid[8] = {0};
            strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
            snprintf(debug_log, sizeof(debug_log), "uid=%s,tnppwdchange=1,prepwd=%s,pwd=%s", uid, pre_p2p_pwd+11,g_p2ptnp_info.mmap_info->pwd+11);
            p2p_debug_log(0, debug_log);
            strncpy(pre_p2p_pwd, g_p2ptnp_info.mmap_info->pwd, sizeof(pre_p2p_pwd));
        }

		if(factory_mode == 0)
		{
			if(fail_cnt > MAX_FAIL_CNT)
			{
				dump_string(_F_, _FU_, _L_, "check_login_success = %d, check_login_fail = %d\n", check_login_success, check_login_fail);
				dump_string(_F_, _FU_, _L_, "too many loginfail force exit %d\n", fail_cnt);
				//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_too_may_login_fail");
            #ifndef NOT_PLT_API
                if(g_p2ptnp_info.mmap_info->start_with_reset != 1){
                    p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, CLOUD_SET_DISCONNECTED, NULL, 0);
                    p2p_send_msg(g_p2ptnp_info.mqfd_dispatch, P2P_CHECK_CLOUD_NET, NULL, 0);
                }
            #endif

            #if  defined(PRODUCT_H30GA) || defined(PRODUCT_H31GA) || defined(PRODUCT_H32GA)
                if(g_p2ptnp_info.mmap_info->start_with_reset ==1)
                {
				    dump_string(_F_, _FU_, _L_, "start with reset set bind timeout");
                    p2p_send_msg(g_p2ptnp_info.mqfd_dispatch,DISPATCH_SET_BIND_TIMEOUT,NULL,0);
                }
            #endif

				/* if(0 != g_p2ptnp_info.mmap_info->wifi_connected) */
				if(0 != g_p2ptnp_info.mmap_info->check_net_disconnected)
				{
                    char debug_log[128] = {0};
                    char uid[8] = {0};

				    dump_string(_F_, _FU_, _L_, "exit p2p because net disconnected");
                    strncpy(uid, g_p2ptnp_info.mmap_info->tnp_info.tnp_did+15, 5);
                    snprintf(debug_log, sizeof(debug_log), "uid=%s,wifistat=%d,torestart=1", uid,g_p2ptnp_info.mmap_info->wifi_connected);
                    p2p_debug_log(1, debug_log);

                    exit(0);
				}
			}
		}
		count++;

        if(fail_cnt > MAX_FAIL_CNT)
            fail_cnt = 0;
	}

	pthread_exit(0);
}

void notice_process(UINT64 msg_index, CHAR *content, UINT32 content_len)
{
	CHAR content_resp[512] = {0};
	UINT32 content_resp_len = 0;

	printf("msg_index = %llu, content = %s, content_len = %d\n", msg_index, content, content_len);

	if(strcmp(content, "TurnOn") == 0)
	{
		if(g_p2ptnp_info.mmap_info->power_mode == POWER_MODE_ON_E)
		{
			content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", NOTICE_EXEC_INVALID);
		}
		else
		{
			p2p_set_power(DISPATCH_SET_POWER_ON);
			content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", NOTICE_EXEC_SUCCESS);
		}
	}
	else if(strcmp(content, "TurnOff") == 0)
	{
		if(g_p2ptnp_info.mmap_info->power_mode == POWER_MODE_OFF_E)
		{
			content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", NOTICE_EXEC_INVALID);
		}
		else
		{
			p2p_set_power(DISPATCH_SET_POWER_OFF);
			content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", NOTICE_EXEC_SUCCESS);
		}
	}
	else if(strcmp(content, "OnLine") == 0)
	{
		content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", NOTICE_EXEC_SUCCESS);
	}
    #ifdef YI_RTMP_CLIENT
    else if(strncmp(content, "PUSH", 4) == 0)
    {
        int  fRval       =  0;
        char fString[64] = {0};
        int status = 1;

        printf("[P2P::NOTIFY::RTMP] rtmp: %s\n", content);
        if(trans_json(fString, "\"type\"", content + 5) == TRUE)
        {
            status = atoi(fString);
            printf("[P2P::NOTIFY::RTMP]  type: %s => %d\n", fString, status);
        } else {
            printf("[P2P::NOTIFY::RTMP] type logId failed ...\n");
        }

        fRval = p2ptnp_send_rtmp(status);
        printf("[P2P::NOTIFY::OTA] p2ptnp_send_rtmp = %d\n", fRval);

        content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", ERROR_PPPP_SUCCESSFUL);
    }
    #endif
    else
	{
		content_resp_len = snprintf(content_resp, sizeof(content_resp), "%d", NOTICE_EXEC_NOT_SUPPORT);
	}

	printf("msg_index = %llu, content_resp = %s, content_resp_len = %d\n", msg_index, content_resp, content_resp_len);

	PPPP_SendNoticeToAck(msg_index, content_resp, content_resp_len);

	return;
}

INT32 tnp_proc(char *tnp_init_string, char* tnp_did)
{
	int ret = 0;
	int user_index = 0;
	st_PPPP_NetInfo NetInfo;
	pthread_t worker_thread;
	pthread_t speaker_thread;
	pthread_t state_statistics_thread;
	unsigned int APIVersion;
	int SessionHandle = -1;
	int got_usr = 0;
	st_PPPP_Session SInfo;
	char tnp_license[64] = {0};

    char debug_log[128] = {0};
    char uid[8] = {0};
    strncpy(uid, tnp_did+15, 5);
    snprintf(debug_log, sizeof(debug_log), "uid=%s,processstart=1", uid);
    p2p_debug_log(0, debug_log);

	p2p_set_tnp_init_status(TNP_INIT_STEP_3);
	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_step3");

	memset_s(g_p2ptnp_info.gUser, sizeof(st_User)*MAX_SESSION_NUM, 0, sizeof(st_User)*MAX_SESSION_NUM);

	for(user_index = 0; user_index < MAX_SESSION_NUM; user_index++)
	{
		g_p2ptnp_info.gUser[user_index].bUsed = USER_STATE_UNUSED;
	}
	
	APIVersion = PPPP_GetAPIVersion();

	dump_string(_F_, _FU_, _L_, "PPPP_API Version: %x %d.%d.%d.%d\n",APIVersion,
		(APIVersion & 0xFF000000)>>24, (APIVersion & 0x00FF0000)>>16, (APIVersion & 0x0000FF00)>>8, (APIVersion & 0x000000FF) >> 0 );

	PPPP_Initialize(tnp_init_string, MAX_SESSION_NUM+1+1);

	if(factory_mode != 1)
	{
		PPPP_NetworkDetect(&NetInfo, 10000);
	}

	dump_string(_F_, _FU_, _L_, "PPPP_NetworkDetect() ret = %d\n", ret);
	dump_string(_F_, _FU_, _L_, "-------------- NetInfo: -------------------\n");
	dump_string(_F_, _FU_, _L_, "Internet Reachable     : %s\n", (NetInfo.bFlagInternet == 1) ? "YES":"NO");
	dump_string(_F_, _FU_, _L_, "P2P Server IP resolved : %s\n", (NetInfo.bFlagHostResolved == 1) ? "YES":"NO");
	dump_string(_F_, _FU_, _L_, "P2P Server Hello Ack   : %s\n", (NetInfo.bFlagServerHello == 1) ? "YES":"NO");
	dump_string(_F_, _FU_, _L_, "Local NAT Type         :");

	switch(NetInfo.NAT_Type)
	{
		case 0:
			dump_string(_F_, _FU_, _L_, " Unknow\n");
			break;
		case 1:
			dump_string(_F_, _FU_, _L_, " IP-Restricted Cone\n");
			break;
		case 2:
			dump_string(_F_, _FU_, _L_, " Port-Restricted Cone\n");
			break;
		case 3:
			dump_string(_F_, _FU_, _L_, " Symmetric\n");
			break;
	}

	dump_string(_F_, _FU_, _L_, "My Wan IP : %s\n", NetInfo.MyWanIP);
	dump_string(_F_, _FU_, _L_, "My Lan IP : %s\n", NetInfo.MyLanIP);

	dump_string(_F_, _FU_, _L_, "InitStr(%s)\n", tnp_init_string);
	dump_string(_F_, _FU_, _L_, "did(%s)\n", tnp_did);
	dump_string(_F_, _FU_, _L_, "key(%s)\n", g_p2ptnp_info.mmap_info->key);

	#if 0
	PPPP_Config_Debug(1,
        0x1 << 0 | // API basic flow
        0x1 << 1 | // API Detail Flow
        //0x1 << 2 | // PPPP_Proto
        //0x1 << 4 | // Listen thread
        0x1 << 6 );
        //0x1 << 11); // Lan Search Thread
    #endif

	if((ret = pthread_create(&state_statistics_thread, NULL, &state_statistics, NULL)) == 0)
	{
		pthread_detach(state_statistics_thread);
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "pthread_create state_statistics failed, ret = %d", ret);
		perror("state_statistics failed");
	}

	if((ret = pthread_create(&speaker_thread, NULL, &speaker_worker, NULL)) == 0)
	{
		pthread_detach(speaker_thread);
	}
	else
	{
		dump_string(_F_, _FU_, _L_, "pthread_create speaker_worker failed, ret = %d", ret);
		perror("speaker_worker failed");
	}
	PPPP_SetNoticeToCallback(notice_process);

	p2p_set_tnp_init_status(TNP_INIT_STEP_4);

	if(0 == factory_mode)
	{
        while(strlen(g_p2ptnp_info.mmap_info->tnp_info.tnp_license) == 0)
        {
            sleep(1);
        }
		snprintf(tnp_license, sizeof(tnp_license), "%s", g_p2ptnp_info.mmap_info->tnp_info.tnp_license);
	}
	else
	{
		snprintf(tnp_license, sizeof(tnp_license), "%s", "ABCDEF");
	}

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_step4");

	for(;;)
	{
		SessionHandle = -1;

		SessionHandle = PPPP_Listen(tnp_did, 60*60, 0, (factory_mode == 1)?0:1, g_p2ptnp_info.mmap_info->key, tnp_license);

		if(SessionHandle >= 0)
		{
			got_usr = 0;

			for(user_index = 0; user_index < MAX_SESSION_NUM; user_index++)
			{
				if(USER_STATE_UNUSED == g_p2ptnp_info.gUser[user_index].bUsed)
				{
					got_usr = 1;
					g_p2ptnp_info.cur_usr = user_index;
					break;
				}
			}

			if(0 == got_usr)
			{
				if(SessionHandle >= 0)
				{
					PPPP_ForceClose(SessionHandle);
				}
				dump_string(_F_, _FU_, _L_, "too many session force exit\n");

				write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_too_many_user");

                char debug_log[128] = {0};
                char uid[8] = {0};
                strncpy(uid, tnp_did+15, 5);
                snprintf(debug_log, sizeof(debug_log), "uid=%s,maxsessionnum=%d,torestart=1", uid, MAX_SESSION_NUM);
                p2p_debug_log(1, debug_log);
				exit(0);
			}

			g_p2ptnp_info.gUser[user_index].SessionHandle = SessionHandle;
			g_p2ptnp_info.gUser[user_index].bUsed = USER_STATE_USED;
			#if defined(PRODUCT_H31BG)
			g_p2ptnp_info.gUser[user_index].auto_resolution = 0;
			g_p2ptnp_info.gUser[user_index].resolution  = 1;
			#endif
			dump_string(_F_, _FU_, _L_, "user_index=%d connected SessionHandle(%d)\n", user_index, g_p2ptnp_info.gUser[user_index].SessionHandle);

			p2p_send_connected();
			p2p_set_tnp_init_status(TNP_INIT_STEP_5);
			memset(&SInfo, 0, sizeof(SInfo));
			if(PPPP_Check(SessionHandle, &SInfo) == ERROR_PPPP_SUCCESSFUL)
			{
				if(SInfo.bMode == 0)
				{
					p2p_set_tnp_work_mode(TNP_P2P_MODE);
				}
				else if(SInfo.bMode == 1)
				{
					p2p_set_tnp_work_mode(TNP_RELAY_MODE);
				}
			}

			if(pthread_create(&worker_thread, NULL, &tnp_worker, (void *)&g_p2ptnp_info.cur_usr) == 0)
			{
				//pthread_detach(worker_thread);
				ms_sleep(1000);
			}
			else
			{
				dump_string(_F_, _FU_, _L_, "create tnp_worker fail\n");
				if(SessionHandle >= 0)
				{
					PPPP_ForceClose(SessionHandle);
				}
				g_p2ptnp_info.gUser[user_index].bUsed = USER_STATE_UNUSED;

                char debug_log[128] = {0};
                char uid[8] = {0};
                strncpy(uid, tnp_did+15, 5);
                snprintf(debug_log, sizeof(debug_log), "uid=%s,createtnpworkerfailed=1,torestart=1", uid);
                p2p_debug_log(1, debug_log);
                exit(0);
			}
		}
		else
		{
            switch(SessionHandle)
            {
                case ERROR_PPPP_INVALID_ID:
                case ERROR_PPPP_INVALID_PARAMETER:
                case ERROR_PPPP_KEY_ERROR:
                case ERROR_PPPP_INVALID_PREFIX:
                case ERROR_PPPP_ID_OUT_OF_DATE:
                case ERROR_PPPP_NONCE_ERROR:
                case ERROR_PPPP_TCP_CONNECT_ERROR:
                case ERROR_PPPP_TCP_SOCKET_ERROR:
                {
                    dump_string(_F_, _FU_, _L_, "PPPP_Listen_With_Key failed, ret = %d\n", SessionHandle);
                    char debug_log[256] = {0};
                    char uid[8] = {0};
                    strncpy(uid, tnp_did+15, 5);
                    char key[8] = {0};
                    strncpy(key, g_p2ptnp_info.mmap_info->key+11, 5);
                    snprintf(debug_log, sizeof(debug_log), "uid=%s,listenerrcode=%d,key=%s,server=%s", uid, SessionHandle, key, tnp_init_string);
                    p2p_debug_log(1, debug_log);
                    sleep(60);
                    break;
                }
                case ERROR_PPPP_MAX_SESSION:
                case ERROR_PPPP_NOT_INITIALIZED:
                {
                    dump_string(_F_, _FU_, _L_, "PPPP_Listen_With_Key failed, ret = %d\n", SessionHandle);
                    char debug_log[128] = {0};
                    char uid[8] = {0};
                    strncpy(uid, tnp_did+15, 5);
                    snprintf(debug_log, sizeof(debug_log), "uid=%s,listenerrcode=%d,torestart=1", uid, SessionHandle);
                    p2p_debug_log(1, debug_log);
                    exit(0);
                    break;
                }
                case ERROR_PPPP_TIME_OUT:
                case ERROR_PPPP_USER_LISTEN_BREAK:
                {
                    dump_string(_F_, _FU_, _L_, "PPPP_Listen_With_Key failed, ret = %d\n", SessionHandle);
                    sleep(1);
                    break;
                }

                default:
                    dump_string(_F_, _FU_, _L_, "PPPP_Listen_With_Key failed, ret = %d\n", SessionHandle);
                    sleep(10);
                    break;
            }
		}
	}

	PPPP_DeInitialize();
	return 0;
}

int main(INT32 argc, CHAR **argv)
{
	char tnp_did[32] = {0};
	char tnp_init_string[128] = {0};
	char test_tnp_did[32] = {0};
	char test_tnp_init_string[128] = {0};

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGPIPE);
	int rc = pthread_sigmask (SIG_BLOCK, &signal_mask, NULL);
	if (rc != 0)
	{
		printf("block sigpipe error/n");
	}

	memset_s(&g_p2ptnp_info, sizeof(g_p2ptnp_info), 0, sizeof(g_p2ptnp_info));
	memset_s(g_p2ptnp_info.viewer_table, sizeof(g_p2ptnp_info.viewer_table), -1, sizeof(g_p2ptnp_info.viewer_table));

    if((g_p2ptnp_info.mmap_info = (mmap_info_s *)get_sharemem(MMAP_FILE_NAME, sizeof(mmap_info_s))) == NULL)
    {
        dump_string(_F_, _FU_, _L_, "open share mem fail!\n");
        return -1;
    }

	//#if defined(PRODUCT_H31BG)
   	//dump_string(_F_, _FU_, _L_, "get_sharemem MMAP_FILE_NAME api_server[%s],version:%s\n", g_p2ptnp_info.mmap_info->api_server,g_p2ptnp_info.mmap_info->version);
	//auto_ota_init_alarm_handler();
	//#endif //#if defined(PRODUCT_H31BG)

	CreatEventlogShareMem();

    if(init_mqueue(&g_p2ptnp_info.mqfd_dispatch, MQ_NAME_DISPATCH) != 0)
    {
        dump_string(_F_, _FU_, _L_, "init_mqueue dispatch fail!\n");
        return -1;
    }
    while (fshare_open() != 0)
    {
        ms_sleep(100);
    }
    dump_string(_F_, _FU_, _L_, "fshare_open ok");

	p2p_set_tnp_init_status(TNP_INIT_STEP_1);

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_step1");

	for(;;)
	{
		//if(1 == g_p2ptnp_info.mmap_info->init_finish && ((0 == factory_mode && 1 == g_p2ptnp_info.mmap_info->time_sync) || (1 == factory_mode && 1 == g_p2ptnp_info.mmap_info->wifi_connected)))
		if(1 == g_p2ptnp_info.mmap_info->init_finish && 1 == g_p2ptnp_info.mmap_info->wifi_connected ||
           g_p2ptnp_info.mmap_info->wifi_mode == 1)
		{
			break;
		}
		ms_sleep(100);
	}
 
#if 1 
    // added by Frank Zhang
    xlink_set_authcode(g_p2ptnp_info.mmap_info->xlinkinfo.auth_code);
    //printf("g_p2ptnp_info.mmap_info->xlinkinfo.bupdated:%d\n",g_p2ptnp_info.mmap_info->xlinkinfo.bupdated);
    //if(g_p2ptnp_info.mmap_info->xlinkinfo.bupdated)
    {
        pthread_t report_version_thread;
        if(pthread_create(&report_version_thread, NULL, &report_version_worker, NULL) == 0)
	    {
		    pthread_detach(report_version_thread);
	    }
	    else
	    {
		    dump_string(_F_, _FU_, _L_, "pthread_create report_version_thread failed");
	    }
	}
#endif
	#if defined(PRODUCT_H31BG)
   	dump_string(_F_, _FU_, _L_, "get_sharemem MMAP_FILE_NAME api_server[%s],version:%s\n", g_p2ptnp_info.mmap_info->api_server,g_p2ptnp_info.mmap_info->version);
	auto_ota_init_alarm_handler();
	#endif //#if defined(PRODUCT_H31BG)
	if(access(FACTORY_TEST_WPA_CONF, F_OK) == 0 || g_p2ptnp_info.mmap_info->wifi_mode == 1/*ap mode*/)
	{
		factory_mode = 1;
	}
	
	p2p_set_tnp_init_status(TNP_INIT_STEP_2);

	//write_log(g_p2ptnp_info.mmap_info->is_sd_exist, "tnp_step2");

	if(factory_mode == 1)
	{
		snprintf(test_tnp_init_string, sizeof(test_tnp_init_string), "%s", "MJFKIILIILEHLBHLOPFDPKFIHBCGFGGEHLEJLJIJICAODLANOMJHAPMDOMCOBELOPELMCLPJ");

        if(g_p2ptnp_info.mmap_info->wifi_mode == 1)
        {
            strncpy(test_tnp_did, g_p2ptnp_info.mmap_info->ap_tnp_did, sizeof(g_p2ptnp_info.mmap_info->ap_tnp_did));
        }
        else
        {
		    memcpy(test_tnp_did, g_p2ptnp_info.mmap_info->did, 20);
		    test_tnp_did[0] = 'T';
		    test_tnp_did[7] = '-';
		    test_tnp_did[14] = '-';

		    int i = 0;
		    for(i=0; i<6; i++)
		    {
			    logw("~~~before:did[%d] = %c \n", (i+8), test_tnp_did[i+8]);
		    }
		    letter2num(&test_tnp_did[8]);
		    for(i=0; i<6; i++)
		    {
			    logw("~~~after:did[%d] = %c \n", (i+8), test_tnp_did[i+8]);
		    }
        }
		tnp_proc(test_tnp_init_string, test_tnp_did);
	}
	else
	{
		if(strlen(g_p2ptnp_info.mmap_info->p2pid) == 20)
		{
			if(strlen(g_p2ptnp_info.mmap_info->tnp_info.tnp_init_string) != 0)
			{
				snprintf(tnp_init_string, sizeof(tnp_init_string), "%s", g_p2ptnp_info.mmap_info->tnp_info.tnp_init_string);
			}
			else
			{
				if(g_p2ptnp_info.mmap_info->region_id == REGION_CHINA)
				{
				snprintf(tnp_init_string, sizeof(tnp_init_string), "%s", "MJFBIBLBICELLEHOOKFGPPECGLCJFKHEGKEALBJNIJBJCOAGPIIIBDMDPBDEAELAOGLCCBPBMKCNAHDPAKBM");
				}
			}
			snprintf(tnp_did, sizeof(tnp_did), "%s", g_p2ptnp_info.mmap_info->p2pid);
		}
		else
		{
			while(strlen(g_p2ptnp_info.mmap_info->tnp_info.tnp_init_string) == 0 || strlen(g_p2ptnp_info.mmap_info->tnp_info.tnp_did) == 0)
			{
				ms_sleep(1000);
			}

			snprintf(tnp_init_string, sizeof(tnp_init_string), "%s", g_p2ptnp_info.mmap_info->tnp_info.tnp_init_string);
			snprintf(tnp_did, sizeof(tnp_did), "%s", g_p2ptnp_info.mmap_info->tnp_info.tnp_did);
		}

		tnp_proc(tnp_init_string, tnp_did);
	}

	return 0;
}
