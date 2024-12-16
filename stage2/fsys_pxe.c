/*
 *  PXE file system for GRUB
 *
 *  Copyright (C) 2007 Bean (bean123@126.com)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifdef FSYS_PXE

#include "shared.h"
#include "filesys.h"
#include "pxe.h"

int map_pd = 0;
struct grub_efi_pxe *pxe_entry;
IP4 pxe_sip;
static grub_u8_t pxe_opened = 0;
static grub_u8_t pxe_already_read = 0;
static char filename[128];
static char *pxe_name = filename;
grub_u32_t pxe_http_type = 0; //0/1=http/https
static int pxe_need_read = 0; //0/1=不用读/需要读

static int pxe_open (char* name);
int pxe_mount (void);
int pxe_dir (char *dirname);
unsigned long long pxe_read (unsigned long long buf, unsigned long long len, unsigned int write);
void pxe_close (void);
void pxe_unload (void);
int pxe_allocate(void);

static int tftp_open(void);
//static grub_u32_t tftp_get_size(void);
static grub_size_t tftp_read (char *buf, grub_u64_t len);
int tftp_write (const char *name);

static int http_open(void);
static grub_size_t http_read (char *buf, grub_u64_t len);

s_PXE_FILE_FUNC tftp_file_func = {tftp_open,tftp_read};
s_PXE_FILE_FUNC http_file_func = {http_open,http_read};
s_PXE_FILE_FUNC *pxe_file_func[2]={
	&tftp_file_func,
  &http_file_func,
};

grub_u32_t cur_pxe_type = 0;
grub_u32_t def_pxe_type = 0;

int is_ip6 = 0;
static char *default_server;
static grub_efi_net_interface_t *net_interface;
static grub_efi_net_interface_t *net_default_interface;
struct grub_efi_net_device *net_devices = 0;
BOOTPLAYER *discover_reply = 0;		//引导播放器
unsigned long long hex;


static grub_efi_net_interface_t *match_route (const char *server);
static void pxe_configure (void);
static void http_configure (void);
static grub_efi_ip6_config_manual_address_t *efi_ip6_config_manual_address (grub_efi_ip6_config_protocol_t *ip6_config);
static grub_efi_ip4_config2_manual_address_t * efi_ip4_config_manual_address (grub_efi_ip4_config2_protocol_t *ip4_config);
static grub_err_t efihttp_request (grub_efi_http_t *http, char *server, char *name, int use_https, int headeronly, grub_off_t *file_size);
static grub_efi_handle_t grub_efi_locate_device_path (grub_efi_guid_t *protocol, grub_efi_device_path_t *device_path, grub_efi_device_path_t **r_device_path);
static grub_efi_net_interface_t * grub_efi_net_config_from_handle (grub_efi_handle_t *hnd, struct grub_efi_net_device *netdev, char **device, char **path);
static inline void __attribute__ ((always_inline)) write_char (char *str, grub_size_t *count, grub_size_t max_len, unsigned char ch);
static int grub_isdigit (int c);
unsigned long grub_strtoul (const char * restrict str, const char ** const restrict end, int base);
static inline char *grub_lltoa (char *str, int c, unsigned long long n);
grub_size_t grub_utf8_to_utf16 (grub_uint16_t *dest, grub_size_t destsize, const grub_uint8_t *src, grub_size_t srcsize, const grub_uint8_t **srcend);
grub_uint8_t *grub_utf16_to_utf8 (grub_uint8_t *dest, const grub_uint16_t *src, grub_size_t size);
static int grub_efi_ip4_interface_set_manual_address (struct grub_efi_net_device *dev, grub_efi_net_ip_manual_address_t *net_ip, int with_subnet);
static grub_efi_net_interface_t * grub_efi_ip4_interface_match (struct grub_efi_net_device *dev, grub_efi_net_ip_address_t *ip_address);
static grub_efi_net_interface_t * grub_efi_ip6_interface_match (struct grub_efi_net_device *dev, grub_efi_net_ip_address_t *ip_address);
static void grub_efi_net_add_pxebc_to_cards (void);
static void set_ip_policy_to_static (void);
static grub_efi_handle_t grub_efi_service_binding (grub_efi_handle_t dev, grub_efi_guid_t *service_binding_guid);


static grub_efi_guid_t ip4_config_guid = GRUB_EFI_IP4_CONFIG2_PROTOCOL_GUID;
static grub_efi_guid_t ip6_config_guid = GRUB_EFI_IP6_CONFIG_PROTOCOL_GUID;
static grub_efi_guid_t http_service_binding_guid = GRUB_EFI_HTTP_SERVICE_BINDING_PROTOCOL_GUID;
static grub_efi_guid_t http_guid = GRUB_EFI_HTTP_PROTOCOL_GUID;
static grub_efi_guid_t dhcp4_service_binding_guid = GRUB_EFI_DHCP4_SERVICE_BINDING_PROTOCOL_GUID;
static grub_efi_guid_t dhcp4_guid = GRUB_EFI_DHCP4_PROTOCOL_GUID;
static grub_efi_guid_t dhcp6_service_binding_guid = GRUB_EFI_DHCP6_SERVICE_BINDING_PROTOCOL_GUID;
static grub_efi_guid_t dhcp6_guid = GRUB_EFI_DHCP6_PROTOCOL_GUID;
static grub_efi_guid_t pxe_io_guid = GRUB_EFI_PXE_GUID;

#if 0
static char* pxe_outhex (char* pc, unsigned char c);
static char* pxe_outhex (char* pc, unsigned char c)		//十六进制字节转ASCII码
{
  int i;

  pc += 2;
  for (i = 1; i <= 2; i++)
    {
      unsigned char t;

      t = c & 0xF;
      if (t >= 10)
        t += 'A' - 10;
      else
        t += '0';
      *(pc - i) = t;
      c = c >> 4;
    }
  return pc;
}
#endif

static int pxe_open (char* name)	//pxe打开
{
	net_interface = NULL;
	if (name != pxe_name)
	{
		grub_strcpy (pxe_name, name);
		name = pxe_name;
		pxe_need_read = 1;
	}
  else
  {
    pxe_opened = 1;
    filepos = 0;
    pxe_need_read = 0;
    return 1;
  }
//	pxe_close ();
	/*
	We always use pxe_tftp_open.FileName for full file path.	我们始终使用pxe_tftp_open.FileName作为完整文件路径。名称是相对路径。
	name is a relative path.
	*/
  net_interface = match_route (default_server);  //匹配路线
  if (!net_interface && !(net_interface = net_default_interface))
  {
    printf_errinfo ("disk `%s' no route found\n", name);
    return 0;
  }
  if (!cur_pxe_type)
    pxe_configure ();    //网络接口
  else
    http_configure();   //网络接口

	pxe_opened = pxe_file_func[cur_pxe_type]->open();
	if (!pxe_opened)
	{
    printf_debug ("Err: PXE is not open。\n");
		return 0;
	}
  return 1;
}

int pxe_mount (void)	//pxe挂载
{
  if (current_drive != PXE_DRIVE || ! pxe_entry)	//0x21
    return 0;

  return 1;
}

/* Check if the file DIRNAME really exists. Get the size and save it in		检查文件DIRNAME是否确实存在
   FILEMAX. return 1 if succeed, 0 if fail.  */		//获取尺寸并将其保存在FILEMAX中。 如果成功则返回1，如果失败则返回0
struct pxe_dir_info	//目录信息
{
	char path[512];			//路径 尺寸0x200    e3d64c0  /boot/dir.txt
	char *dir[512];			//目录 尺寸0x1000   e3d66c0  e3d76c0 e3d76c5 e3d76d2 ...    
	char data[];				//数据 尺寸0x2e00   e3d76c0  bcd\0\a bcdedit.exe\0\a boot.sdi\0\a bootmgr.exe\0\a wimboot\0\a
} *P_DIR_INFO = NULL;//尺寸0x4000

int pxe_dir (char *dirname)	//pxe查目录
{
  int ret;
  char ch;
  ret = 1;
  ch = nul_terminate (dirname);		//以00替换止字符串的空格,回车,换行,水平制表符
 
	if (print_possibilities)	//如果存在打印可能性
	{
		char dir_tmp[128];
		char *p_dir;
		ret = grub_strlen(dirname);	//目录尺寸
		p_dir = &dirname[ret];			//目录结束地址

		if (ret && ret <=120)				//存在目录尺寸,并且<=120
		{
			while (ret && dirname[ret] != '/') 	//取子目录
			{
				ret--;
			}
			grub_memmove(dir_tmp,dirname,ret);	//复制子目录
		}
		else
			ret = 0;

		grub_strcpy(&dir_tmp[ret],"/dir.txt");//追加"/dir.txt"
		if (P_DIR_INFO || (P_DIR_INFO = (struct pxe_dir_info*)grub_malloc(16384)))	//建立目录信息缓存
		{
			int i;
			char *p = P_DIR_INFO->data;
			memset(P_DIR_INFO,0,16384);
			if (substring(dir_tmp,P_DIR_INFO->path,1) != 0)	//判断子字符串
			{
				grub_strcpy(P_DIR_INFO->path,dir_tmp);
				if (pxe_open(dir_tmp))
				{
//					if (pxe_read((unsigned long long)(grub_size_t)P_DIR_INFO->data,13312,GRUB_READ))  //13312计算错误
					if (pxe_read((unsigned long long)(grub_size_t)P_DIR_INFO->data,filemax,GRUB_READ))  //替换filemax，是因为读长了会把后面无用的字符串读入  2023-11-24
					{
						P_DIR_INFO->dir[0] = P_DIR_INFO->data;
						for (i = 1;i < 512 && (p = skip_to(0x100,p));++i) //遇到首个"回车,换行",使用'\0'替换.然后跳过之后的"回车,换行,空格,水平制表符",
						{
							P_DIR_INFO->dir[i] = p;
						}
					}
					pxe_close();
				}
			}
			dirname += ret + 1;
			ret = 0;
			for (i = 0; i < 512 && (p = P_DIR_INFO->dir[i]);++i)
			{
				if (*dirname == 0 || substring (dirname, p, 1) < 1)
				{
					ret = 1;
					print_a_completion(p, 1);
				}
			}
		}
		else
			ret = 0;
		if (!ret)
			errnum = ERR_FILE_NOT_FOUND;
		*p_dir = ch;
		return ret;
  }
  pxe_close ();
  if (! pxe_open (dirname))
    {
      errnum = ERR_FILE_NOT_FOUND;
      ret = 0;
    }

  dirname[grub_strlen(dirname)] = ch;
  return ret;
}

/* Read up to SIZE bytes, returned in ADDR.  读取最多SIZE个字节，返回ADDR*/
unsigned long long
pxe_read (unsigned long long buf, unsigned long long len, unsigned int write)	//pxe读
{
  if (write == GRUB_WRITE)	//如果写, 则错误
    return !(errnum = ERR_WRITE);

  if (! pxe_opened)	//如果pxe没有打开, 则错误
    return PXE_ERR_LEN;

  if (!buf || write == GRUB_LISTBLK)
    return 0;

  if (!filepos && pxe_need_read)
  {
    pxe_need_read = 0;
    if (len) //如果未分配内存
      pxe_allocate(); //分配内存

    printf ("Copying data, please wait......\n");
    pxe_already_read = pxe_file_func[cur_pxe_type]->read(efi_pxe_buf, filemax);
  }

  if (!len)
    return 1;
  if (pxe_already_read)
  {
    grub_memmove64 (buf, (unsigned long long)(grub_size_t)(char*)(efi_pxe_buf + filepos), len);
    filepos += len;
    return len;
  }
  
  return 0;
}

void pxe_close (void)	//pxe关闭		grub_pxe_close (struct grub_net_card *dev __attribute__ ((unused)))
{
	if (pxe_opened)
	{
    grub_efi_boot_services_t *b;  //引导服务
    b = grub_efi_system_table->boot_services; //系统表->引导服务
    if (efi_pxe_buf)
      efi_call_1 (b->free_pool, efi_pxe_buf);	//调用(释放池,释放数据)
    efi_pxe_buf = 0;
    pxe_opened = 0;
    pxe_already_read = 0;
    pxe_http_type = 0; //0/1=http/https
    pxe_need_read = 0; //0/1=不用读/需要读
	}
}

void pxe_unload (void)	//pxe卸载
{
}

int pxe_allocate(void) //分配内存
{
	grub_efi_status_t status;
  grub_efi_boot_services_t *b;  //引导服务
  b = grub_efi_system_table->boot_services; //系统表->引导服务
  unsigned long long bytes_needed;

  if (map_pd) //不释放内存
  {
    bytes_needed = ((filemax+4095)&(-4096ULL));
    status = efi_call_4 (b->allocate_pages, GRUB_EFI_ALLOCATE_ANY_PAGES,   
          GRUB_EFI_RESERVED_MEMORY_TYPE,                        //保留内存类型        0
          (grub_efi_uintn_t)bytes_needed >> 12, (unsigned long long *)(grub_size_t)&efi_pxe_buf);	//调用(分配页面,分配类型->任意页面,存储类型->运行时服务数据(6),分配页,地址)  
    if (status != GRUB_EFI_SUCCESS)	//如果失败
    {
      printf_errinfo ("out of map memory: %d\n",(int)status);
      errnum = ERR_WONT_FIT;
      return 0;
    }
  }
  else
  {
    status = efi_call_3 (b->allocate_pool, GRUB_EFI_BOOT_SERVICES_DATA, //启动服务数据        4
                           filemax + 0x200, (void **)(grub_size_t)&efi_pxe_buf); //(分配池,存储器类型->装载数据,分配字节,返回分配地址}
    if (status != GRUB_EFI_SUCCESS)		//失败
    {
      printf_errinfo ("Couldn't allocate pool.");
      return !(errnum = 0x1234);
    }
  }

	memset(efi_pxe_buf,0,filemax);  //2023-11-24
  return 1;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static int tftp_open(void)		//tftp打开
{
	grub_efi_status_t status;

	status = efi_call_10 (pxe_entry->mtftp,					//tftp功能
	    pxe_entry,																	//pxe结构
	    GRUB_EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE,	//TFTP获得文件尺寸
	    NULL,																				//缓存
	    0,
			(grub_efi_uint64_t *)(grub_size_t)&filemax, //缓存尺寸
	    NULL,																				//块尺寸
	    (IP4 *)(grub_size_t)&pxe_sip,						    //服务器IP
	    pxe_name,															//文件名
	    NULL,
	    0);
  if (status != GRUB_EFI_SUCCESS)		//失败
	{
		printf_errinfo ("Couldn't get file size\n");
    return !(errnum = 0x1234);
	}

	filepos = 0;
  return 1;
}
#if 0
static grub_u32_t tftp_get_size(void)			//TFTP获得文件尺寸
{
	grub_efi_status_t status;

	status = efi_call_10 (pxe_entry->mtftp,					//tftp功能
	    pxe_entry,																	//pxe结构
	    GRUB_EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE,	//TFTP获得文件尺寸
	    NULL,																				//缓存
	    0,
			(grub_efi_uint64_t *)(grub_size_t)&filemax, //缓存尺寸
	    NULL,																				//块尺寸
	    (IP4 *)(grub_size_t)&pxe_sip,						    //服务器IP
	    pxe_name,															//文件名
	    NULL,
	    0);
  if (status != GRUB_EFI_SUCCESS)		//失败
	{
		printf_errinfo ("Couldn't get file size\n");
    return !(errnum = 0x1234);
	}

	return filemax;
}
#endif
static grub_size_t
tftp_read (char *buf, grub_u64_t len)  //efi读
{
  grub_efi_status_t status;

	status = efi_call_10 (pxe_entry->mtftp,				//tftp功能
				pxe_entry,															//pxe结构
				GRUB_EFI_PXE_BASE_CODE_TFTP_READ_FILE,	//TFTP读文件
				buf,                                    //缓存
				0,
				(grub_efi_uint64_t *)(grub_size_t)&filemax,//缓存尺寸
				NULL,																		//块尺寸
				(IP4 *)(grub_size_t)&pxe_sip,					  //服务器IP
				pxe_name,												  //文件名
				NULL,
				0);
  if (status != GRUB_EFI_SUCCESS)		//失败
	{
		printf_errinfo ("Couldn't read file.");
    return !(errnum = 0x1234);
	}

  return filemax;
}

int tftp_write (const char *name)		//tftp写  2023-11-24
{
	grub_efi_status_t status;

	status = efi_call_10 (pxe_entry->mtftp,				//tftp功能
				pxe_entry,															//pxe结构
				GRUB_EFI_PXE_BASE_CODE_TFTP_WRITE_FILE, //TFTP写文件
				(char *)efi_pxe_buf,                    //缓存
				1,                                      //可以覆盖服务器上的文件
				(grub_efi_uint64_t *)(grub_size_t)&filemax,//缓存尺寸
				NULL,																		//块尺寸
				(IP4 *)(grub_size_t)&pxe_sip,					  //服务器IP
				(char *)name,													  //文件名
				NULL,
				0);
  if (status != GRUB_EFI_SUCCESS)		//失败
	{
		printf_errinfo ("Couldn't write file.");
    return !(errnum = 0x1234);
	}

  return 1;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//net/efi/http.c
#define GRUB_MAX_UTF16_PER_UTF8 1
#define GRUB_EFI_IP6_PREFIX_LENGTH 64
int prefer_ip6;
static grub_efi_boolean_t request_callback_done;
static grub_efi_boolean_t response_callback_done;

static void
grub_efi_http_request_callback (grub_efi_event_t event __attribute__ ((unused)),
				void *context __attribute__ ((unused))) //请求回调
{
  request_callback_done = 1;
}

static void
grub_efi_http_response_callback (grub_efi_event_t event __attribute__ ((unused)),
				void *context __attribute__ ((unused))) //响应回调
{
  response_callback_done = 1;
}

static int http_open(void)   //http打开
{
  int err;

  err = efihttp_request (net_devices->http, (char *)default_server, (char *)pxe_name, 0, 1, 0);    //请求头部
  if (err)
    return 0;

  err = efihttp_request (net_devices->http, (char *)default_server, (char *)pxe_name, 0, 0, &filemax); //请求获得，返回尺寸
  if (err)
    return 0;

	filepos = 0;
  return 1;
}

static grub_size_t
http_read (char *buf, grub_u64_t len)  //efi读
{
  grub_efi_http_message_t response_message; //响应消息
  grub_efi_http_token_t response_token;     //响应令牌
  grub_efi_status_t status;                 //状态
  grub_size_t sum = 0;                      //和
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services; //引导服务
  grub_efi_http_t *http = net_devices->http;        //http入口

  if (!len) //尺寸为零
  {
    printf_errinfo ("Invalid arguments to EFI HTTP Read\n");  //EFI HTTP读取的参数无效
    return 0;
  }

  efi_call_5 (b->create_event,                  //创建事件
              GRUB_EFI_EVT_NOTIFY_SIGNAL,       //事件的类型       通知信号
              GRUB_EFI_TPL_CALLBACK,            //事件的优先级     回调
              grub_efi_http_response_callback,  //事件处理函数     响应回调
              NULL,                             //传递给事件处理函数的参数
              &response_token.event);           //创建的事件

  while (len)
  {
    //响应消息
    response_message.data.response = NULL;      //响应消息.数据.响应
    response_message.header_count = 0;          //响应消息.标头计数
    response_message.headers = NULL;            //响应消息.标头
    response_message.body_length = len;         //响应消息.体长   设置为654800，他实际读ff82,ffff,8e94等等
    response_message.body = (void *)(grub_size_t)buf; //响应消息.体
    //响应令牌
    response_token.message = &response_message; //响应令牌.消息
    response_token.status = GRUB_EFI_NOT_READY; //响应令牌.状态    还没准备好

    response_callback_done = 0;   //响应回调已完成=0

    status = efi_call_2 (http->response, http, &response_token);  //响应
    if (status != GRUB_EFI_SUCCESS) //失败
    {
      efi_call_1 (b->close_event, response_token.event);    //关闭事件
      printf_errinfo ("Error! status=%d\n", (int)status);   //错误!状态=
      return 0;
    }

    while (!response_callback_done) //等待回调完成
      efi_call_1(http->poll, http); //获得
    //修正下一次参数
    sum += response_message.body_length;  //和
    buf += response_message.body_length;  //缓存
    len -= response_message.body_length;  //剩余尺寸
  }

  efi_call_1 (b->close_event, response_token.event);   //关闭事件
  return sum; //返回读尺寸
}

static void
http_configure (void)  //http配置
{
  grub_efi_http_config_data_t http_config;    //HTTP配置数据
  grub_efi_httpv4_access_point_t httpv4_node; //HTTPv4访问点
  grub_efi_httpv6_access_point_t httpv6_node; //HTTPv6访问点
  grub_efi_status_t status;
  grub_efi_http_t *http = net_devices->http;  //HTTP入口

  grub_memset (&http_config, 0, sizeof(http_config));  //初始化HTTP配置数据
  http_config.http_version = GRUB_EFI_HTTPVERSION11;    //HTTP配置数据.版本=11
  http_config.timeout_millisec = 5000;                  //HTTP配置数据.超时=5000毫秒

  if (prefer_ip6) //如果首选ip6
  {
    grub_efi_uintn_t sz;
    grub_efi_ip6_config_manual_address_t manual_address;//ip6配置手动地址

    http_config.local_address_is_ipv6 = 1;              //HTTP配置数据.本地地址是ipv6 = 0
    sz = sizeof (manual_address);                       //ip6配置手动地址尺寸
    status = efi_call_4 (net_devices->ip6_config->get_data, net_devices->ip6_config,
        GRUB_EFI_IP6_CONFIG_DATA_TYPE_MANUAL_ADDRESS,
        &sz, &manual_address);                          //ip6配置获得手动地址

    if (status == GRUB_EFI_NOT_FOUND)
    {
      printf_errinfo ("The MANUAL ADDRESS is not found\n");
      errnum = 0x1234;
      return ;
    }

    //手动界面将返回缓冲区太小!!!
    if (status != GRUB_EFI_SUCCESS)
    {
      printf_errinfo ("??? %d\n",(int) status);
      errnum = 0x1234;
      return;
    }

    grub_memcpy (httpv6_node.local_address, manual_address.address, sizeof (httpv6_node.local_address));
    httpv6_node.local_port = 0;
    http_config.access_point.ipv6_node = &httpv6_node;
  }
  else  //是ip4
  {
    http_config.local_address_is_ipv6 = 0;               //HTTP配置数据.本地地址是ipv6 = 0
    grub_memset (&httpv4_node, 0, sizeof(httpv4_node)); //HTTPv4访问点初始化
    httpv4_node.use_default_address = 1;                 //HTTPv4访问点.

    //在此处使用随机端口
    //请参阅edk2/NetworkPkg/TcpDxe/TcpDispatcher中的TcpBind().c
    httpv4_node.local_port = 0;
    http_config.access_point.ipv4_node = &httpv4_node;
  }

  status = efi_call_2 (http->configure, http, &http_config);  //配置

  if (status == GRUB_EFI_ALREADY_STARTED)
  {
    return;
  }
  if (status != GRUB_EFI_SUCCESS)
  {
    printf_errinfo ("couldn't configure http protocol, reason: %d\n", (int)status);
    errnum = 0x1234;
    return ;
  }
}

static grub_err_t
efihttp_request (grub_efi_http_t *http, char *server, char *name, int use_https, int headeronly, grub_off_t *file_size) //http请求
{
  grub_efi_http_request_data_t request_data;
  grub_efi_http_message_t request_message;
  grub_efi_http_token_t request_token;
  grub_efi_http_response_data_t response_data;
  grub_efi_http_message_t response_message;
  grub_efi_http_token_t response_token;
  grub_efi_http_header_t request_headers[3];
 // grub_efi_http_header_t request_headers[4];

  grub_efi_status_t status;
  grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
  char url[128];

  //请求标头
  request_headers[0].field_name = (grub_efi_char8_t *)"Host";               //请求标头.字段名称   主机，服务机
  request_headers[0].field_value = (grub_efi_char8_t *)server;              //请求标头.字段值      "192.168.114.1" 
  request_headers[1].field_name = (grub_efi_char8_t *)"Accept";             //请求标头.字段名称   接受
  request_headers[1].field_value = (grub_efi_char8_t *)"*/*";               //请求标头.字段值
  request_headers[2].field_name = (grub_efi_char8_t *)"User-Agent";         //请求标头.字段名称   用户代理
  request_headers[2].field_value = (grub_efi_char8_t *)"UefiHttpBoot/1.0";  //请求标头.字段值
//  request_headers[3].field_name = (grub_efi_char8_t *)"Range";              //请求标头.字段名称   范围        
//  request_headers[3].field_value = (grub_efi_char8_t *)"bytes=0-1023";      //请求标头.字段值     字节范围

  {
    grub_efi_char16_t *ucs2_url;        //ucs2网址
    grub_size_t url_len, ucs2_url_len;  //网址尺寸, ucs2网址尺寸
    const char *protocol = (use_https == 1) ? "https" : "http";   //协议

    
//    if (grub_efi_string_to_ip6_address (server, &address, &rest) && *rest == 0)  //字符串到ip6地址成立  
//      url = grub_xasprintf ("%s://[%s]%s", protocol, server, name); //协议,服务器,名称
    if (is_ip6)  //是ip6
      grub_sprintf (url, "%s://[%s]%s", protocol, server, name); //协议,服务器,名称
    else  //ip4地址
//      url = grub_xasprintf ("%s://%s%s", protocol, server, name);     
      grub_sprintf (url, "%s://%s%s", protocol, server, name);

    url_len = grub_strlen (url);                        //网址尺寸
    ucs2_url_len = url_len * GRUB_MAX_UTF16_PER_UTF8;   //ucs2网址尺寸
    ucs2_url = grub_zalloc ((ucs2_url_len + 1) * sizeof (ucs2_url[0]));

    if (!ucs2_url)
      return errnum = 0x1234;

    ucs2_url_len = grub_utf8_to_utf16 (ucs2_url, ucs2_url_len, (grub_uint8_t *)url, url_len, NULL); /* convert string format from ascii to usc2 */
    ucs2_url[ucs2_url_len] = 0;                 //结束符
//    grub_free (url);
    request_data.url = ucs2_url;                //请求信息.url
  }
  //请求数据.方法
  request_data.method = (headeronly > 0) ? GRUB_EFI_HTTPMETHODHEAD : GRUB_EFI_HTTPMETHODGET;  //头朝前?头:获得
  //请求信息
  request_message.data.request = &request_data; //请求信息.数据请求
  request_message.header_count = 3;             //请求信息.标头计数
//  request_message.header_count = 4;             //请求信息.标头计数
  request_message.headers = request_headers;    //请求信息.标头
  request_message.body_length = 0;              //请求信息.体尺寸
  request_message.body = NULL;                  //请求信息.体

  //请求令牌
  request_token.event = NULL;                   //请求令牌.事件
  request_token.status = GRUB_EFI_NOT_READY;    //请求令牌.状态  未准备好
  request_token.message = &request_message;     //请求令牌.消息

  request_callback_done = 0;                    //请求回调完成=0
  status = efi_call_5 (b->create_event,                  //创建事件
                       GRUB_EFI_EVT_NOTIFY_SIGNAL,       //事件的类型       通知信号
                       GRUB_EFI_TPL_CALLBACK,            //事件的优先级     回调
                       grub_efi_http_request_callback,   //事件处理函数     请求回调
                       NULL,                             //传递给事件处理函数的参数
                       &request_token.event);
  if (status != GRUB_EFI_SUCCESS) //失败
  {
    grub_free (request_data.url);
    printf_errinfo ("Fail to create an event status=%x\n", status);
    return (errnum = 0x1234);
  }

  efi_call_1 (grub_efi_system_table->boot_services->stall, 50000);  //延时50毫秒

  status = efi_call_2 (http->request, http, &request_token); //请求       有时莫名其妙地死在这里，必须重新启动虚拟机!!!!
  if (status != GRUB_EFI_SUCCESS) //失败
  {
    efi_call_1 (b->close_event, request_token.event);   //关闭事件
    grub_free (request_data.url);
    printf_errinfo ("Fail to send a request status=%x\n", status); //12超时  f拒绝访问
    return (errnum = 0x1234);
  }
  /* TODO: Add Timeout */
  while (!request_callback_done)  //等待请求回调完成
    efi_call_1(http->poll, http); //获得
  //响应数据
  response_data.status_code = GRUB_EFI_HTTP_STATUS_UNSUPPORTED_STATUS;  //响应数据.状态代码  0=不受支持的状态
  //响应消息
  response_message.data.response = &response_data;  //响应数据.数据响应
  //herader_count将由HTTP驱动程序在响应时更新
  response_message.header_count = 0;                //响应数据.标头计数
  //标头将由驱动程序在响应时填充
  response_message.headers = NULL;                  //响应数据.标头
  //使用零BodyLength仅接收响应标头
  response_message.body_length = 0;                 //响应数据.体尺寸
  response_message.body = NULL;                     //响应数据.体
  //响应令牌.事件
  response_token.event = NULL;

  status = efi_call_5 (b->create_event,         //创建事件
              GRUB_EFI_EVT_NOTIFY_SIGNAL,       //事件的类型       通知信号
              GRUB_EFI_TPL_CALLBACK,            //事件的优先级     回调
              grub_efi_http_response_callback,  //事件处理函数     响应回调
              NULL,                             //传递给事件处理函数的参数
              &response_token.event);
  if (status != GRUB_EFI_SUCCESS)
  {
    efi_call_1 (b->close_event, request_token.event);   //关闭事件
    grub_free (request_data.url);
    printf_errinfo ("Fail to create an event\n status=%x\n", status);
    return (errnum = 0x1234);
  }
  //响应令牌
  response_token.status = GRUB_EFI_SUCCESS;   //响应令牌.状态  成功
  response_token.message = &response_message; //响应令牌.消息

  efi_call_1 (grub_efi_system_table->boot_services->stall, 50000);  //延时50毫秒

  //等待HTTP响应
  response_callback_done = 0;   //响应回调完成=0
  status = efi_call_2 (http->response, http, &response_token);  //响应
  if (status != GRUB_EFI_SUCCESS)
  {
    efi_call_1 (b->close_event, response_token.event);   //关闭事件
    efi_call_1 (b->close_event, request_token.event);   //关闭事件
    grub_free (request_data.url);
    printf_errinfo ("Fail to receive a response! status=%x\n", status);//68,  69
    return (errnum = 0x1234);    
  }

  /* TODO: Add Timeout */
  while (!response_callback_done)   //等待响应回调完成
    efi_call_1 (http->poll, http);  //获得

  //返回部分内容，是我们请求了范围，不是错误
  if (response_message.data.response->status_code == GRUB_EFI_HTTP_STATUS_206_PARTIAL_CONTENT && request_message.header_count == 4)
    goto aaa;

  if (response_message.data.response->status_code != GRUB_EFI_HTTP_STATUS_200_OK)
  {
    grub_efi_http_status_code_t status_code = response_message.data.response->status_code;

    if (response_message.headers)
      efi_call_1 (b->free_pool, response_message.headers);
    efi_call_1 (b->close_event, response_token.event);   //关闭事件
    efi_call_1 (b->close_event, request_token.event);   //关闭事件
    grub_free (request_data.url);
    if (status_code == GRUB_EFI_HTTP_STATUS_404_NOT_FOUND)  //未找到
    {
      printf_errinfo ("file `%s' not found\n", name);
      return (errnum = 0x1234);  
    }
    else
    {
      printf_errinfo ("unsupported uefi http status code %d\n", status_code);
      return (errnum = 0x1234);  
    }
  }

aaa:
  if (file_size)  //获得文件尺寸
  { 
    int i;
    /* parse the length of the file from the ContentLength header 从ContentLength标头解析文件的长度*/
    for (*file_size = 0, i = 0; i < (int)response_message.header_count; ++i)
    {
//Connection      close                       连接:     关闭
//Content-Type    application/octet-stream    内容类型: 应用程序/八位字节流
//Content-Length  6637568                     内容尺寸: 6637568(ASCII码)
//Server          Indy/9.00.10                服务器:   Indy/9.00.10
//Range           0-1023                      范围:     0-1023字节
      if (!grub_strcmp((const char*)response_message.headers[i].field_name, "Content-Length"))
	    {
//	      *file_size = grub_strtoul((const char*)response_message.headers[i].field_value, 0, 10);
        safe_parse_maxint ((char**)&response_message.headers[i].field_value, &hex);
        *file_size = hex;
	      break;
	    }
    }
  }

  if (response_message.headers)
    efi_call_1 (b->free_pool, response_message.headers);
  efi_call_1 (b->close_event, response_token.event);   //关闭事件
  efi_call_1 (b->close_event, request_token.event);   //关闭事件
  grub_free (request_data.url);

  return GRUB_ERR_NONE;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//net/efi/pxe.c
static void
pxe_configure (void) //pxe配置
{
  grub_efi_pxe_t *pxe = (is_ip6) ? net_devices->ip6_pxe : net_devices->ip4_pxe; //首选ip6,则选择ip6_pxe，否则选择ip4_pxe
  grub_efi_pxe_mode_t *mode = pxe->mode;

  if (!mode->started) //如果未启动
  {
    grub_efi_status_t status;
    status = efi_call_2 (pxe->start, pxe, is_ip6);  //启动

    if (status != GRUB_EFI_SUCCESS) //失败
      printf_debug ("Couldn't start PXE\n"); //无法启动PXE
  }

  printf_debug ("PXE STARTED: %u\n", mode->started);       //PXE已启动：
  printf_debug ("PXE USING IPV6: %u\n", mode->using_ipv6); //使用IPV6的PXE：

  if (mode->using_ipv6) //如果使用ipv6
  {
    grub_efi_ip6_config_manual_address_t *manual_address;
    manual_address = efi_ip6_config_manual_address (net_devices->ip6_config);  //获得ip6配置手动地址

    if (manual_address &&
            grub_memcmp ((const char *)manual_address->address, (const char *)mode->station_ip.v6, sizeof (manual_address->address)) != 0)  //复制站ipv6作为手动地址成功
    {
      grub_efi_status_t status;
      grub_efi_pxe_ip_address_t station_ip;

      grub_memcpy (station_ip.v6.addr, manual_address->address, sizeof (station_ip.v6.addr));
      status = efi_call_3 (pxe->set_station_ip, pxe, (grub_u32_t *)(grub_size_t)&station_ip, NULL);  //设置站ip

      if (status != GRUB_EFI_SUCCESS)
	      printf_debug ("Couldn't set station ip\n");

      grub_free (manual_address);
    }
  }
  else
  {
    grub_efi_ip4_config2_manual_address_t *manual_address;
    manual_address = efi_ip4_config_manual_address (net_devices->ip4_config);  //获得ip4配置手动地址

    if (manual_address &&
            grub_memcmp ((const char *)manual_address->address, (const char *)mode->station_ip.v4, sizeof (manual_address->address)) != 0)  //复制站ipv4作为手动地址成功
    {
      grub_efi_status_t status;
      grub_efi_pxe_ip_address_t station_ip;
      grub_efi_pxe_ip_address_t subnet_mask;

      grub_memcpy (station_ip.v4.addr, manual_address->address, sizeof (station_ip.v4.addr));
      grub_memcpy (subnet_mask.v4.addr, manual_address->subnet_mask, sizeof (subnet_mask.v4.addr));

      status = efi_call_3 (pxe->set_station_ip, pxe, (grub_u32_t *)(grub_size_t)&station_ip, (grub_u32_t *)(grub_size_t)&subnet_mask);//设置站ip

      if (status != GRUB_EFI_SUCCESS)
	      printf_debug ("Couldn't set station ip\n");

      grub_free (manual_address);
    }
  }
#if 0
  if (mode->using_ipv6)
  {
    printf_debug ("PXE STATION IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",   //PXE站IP:
          mode->station_ip.v6.addr[0],
          mode->station_ip.v6.addr[1],
          mode->station_ip.v6.addr[2],
          mode->station_ip.v6.addr[3],
          mode->station_ip.v6.addr[4],
          mode->station_ip.v6.addr[5],
          mode->station_ip.v6.addr[6],
          mode->station_ip.v6.addr[7],
          mode->station_ip.v6.addr[8],
          mode->station_ip.v6.addr[9],
          mode->station_ip.v6.addr[10],
          mode->station_ip.v6.addr[11],
          mode->station_ip.v6.addr[12],
          mode->station_ip.v6.addr[13],
          mode->station_ip.v6.addr[14],
          mode->station_ip.v6.addr[15]);
  }
  else
  {
    printf_debug ("PXE STATION IP: %d.%d.%d.%d\n",   //PXE站IP:
          mode->station_ip.v4.addr[0],
          mode->station_ip.v4.addr[1],
          mode->station_ip.v4.addr[2],
          mode->station_ip.v4.addr[3]);
    printf_debug ("PXE SUBNET MASK: %d.%d.%d.%d\n",  //PXE子网掩码:
          mode->subnet_mask.v4.addr[0],
          mode->subnet_mask.v4.addr[1],
          mode->subnet_mask.v4.addr[2],
          mode->subnet_mask.v4.addr[3]);
  }
#endif
  /* TODO: Set The Station IP to the IP2 Config */
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//kern/misc.c

union printf_arg
{
  /* Yes, type is also part of union as the moment we fill the value
     we don't need to store its type anymore (when we'll need it, we'll
     have format spec again. So save some space.  */
  enum
    {
      INT, LONG, LONGLONG,
      UNSIGNED_INT = 3, UNSIGNED_LONG, UNSIGNED_LONGLONG,
      STRING
    } type;
  long long ll;
};

struct printf_args
{
  union printf_arg prealloc[32];
  union printf_arg *ptr;
  grub_size_t count;
};

static int grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0, struct printf_args *args);
static void parse_printf_args (const char *fmt0, struct printf_args *args, va_list args_in);

static inline void __attribute__ ((always_inline))
write_char (char *str, grub_size_t *count, grub_size_t max_len, unsigned char ch)
{
  if (*count < max_len)
    str[*count] = ch;

  (*count)++;
}

static int
grub_isdigit (int c)
{
  return (c >= '0' && c <= '9');
}

static inline void
grub_reverse (char *str)
{
  char *p = str + grub_strlen (str) - 1;

  while (str < p)
  {
    char tmp;

    tmp = *str;
    *str = *p;
    *p = tmp;
    str++;
    p--;
  }
}

static inline char *
grub_lltoa (char *str, int c, unsigned long long n)
{
  unsigned base = ((c == 'x') || (c == 'X')) ? 16 : 10;
  char *p;

  if ((long long) n < 0 && c == 'd')
  {
    n = (unsigned long long) (-((long long) n));
    *str++ = '-';
  }

  p = str;

  if (base == 16)
    do
    {
      unsigned d = (unsigned) (n & 0xf);
      *p++ = (d > 9) ? d + ((c == 'x') ? 'a' : 'A') - 10 : d + '0';
    }
    while (n >>= 4);
  else
    /* BASE == 10 */
    do
    {
      grub_uint64_t m;
#if defined(__i386__)
//      n = (unsigned long long)grub_divmod64 (~0ULL - n, 10, &m);
      n = grub_divmod64 (n, 10, &m);
#else
//      n = (unsigned long long)((~0ULL - n) / 10);
      n = (unsigned long long)(n / 10);
#endif
//     n = grub_divmod64 (n, 10, &m);
      *p++ = m + '0';
    }
    while (n);

  *p = 0;
  grub_reverse (str);
  return p;
}

static void
free_printf_args (struct printf_args *args)
{
  if (args->ptr != args->prealloc)
    grub_free (args->ptr);
}

static int grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0, struct printf_args *args);
static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args)
{
  char c;
  grub_size_t n = 0;
  grub_size_t count = 0;
  const char *fmt;
  fmt = fmt0;

  while ((c = *fmt++) != 0)
  {
    unsigned int format1 = 0;
    unsigned int format2 = ~ 0U;
    char zerofill = ' ';
    char rightfill = 0;
    grub_size_t curn;

    if (c != '%')
    {
      write_char (str, &count, max_len,c);
      continue;
    }
    if (*fmt == '%')
    {
      write_char (str, &count, max_len, '%');
      fmt++;
      continue;
    }

    curn = n++;
rescan:

    if (*fmt =='-')
    {
      rightfill = 1;
      fmt++;
    }
    /* Read formatting parameters.  */
    if (grub_isdigit (*fmt))
    {
      if (fmt[0] == '0')
        zerofill = '0';
//      format1 = grub_strtoul (fmt, &fmt, 10);
      safe_parse_maxint ((char**)&fmt, &hex);
      format1 = hex;
    }
    if (*fmt == '.')
      fmt++;

    if (grub_isdigit (*fmt))
//      format2 = grub_strtoul (fmt, &fmt, 10);
    {
      safe_parse_maxint ((char**)&fmt, &hex);
      format2 = hex;
    }

    if (*fmt == '*')
    {
      fmt++;
      format1 = (unsigned long) args->ptr[curn].ll;
      curn++;
    }

    if (*fmt == '$')
    {
      curn = format1 - 1;
      fmt++;
      format1 = 0;
      format2 = ~ 0U;
      zerofill = ' ';
      rightfill = 0;
      goto rescan;
    }

    c = *fmt++;
    if (c == 'l')
      c = *fmt++;
    if (c == 'l')
      c = *fmt++;
    if (c == '%')
    {
      write_char (str, &count, max_len,c);
      n--;
      continue;
    }
    if (curn >= args->count)
      continue;

    long long curarg = args->ptr[curn].ll;
    switch (c)
    {
      case 'p':
        write_char (str, &count, max_len, '0');
        write_char (str, &count, max_len, 'x');
        c = 'x';
      /* Fall through. */
      case 'x':
      case 'X':
      case 'u':
      case 'd':
      {
        char tmp[32];
        const char *p = tmp;
        grub_size_t len;
        grub_size_t fill;

        len = grub_lltoa (tmp, c, curarg) - tmp;
        fill = len < format1 ? format1 - len : 0;
        if (! rightfill)
          while (fill--)
            write_char (str, &count, max_len, zerofill);

        while (*p)
          write_char (str, &count, max_len, *p++);

        if (rightfill)
          while (fill--)
            write_char (str, &count, max_len, zerofill);
      }
        break;
      case 'c':
        write_char (str, &count, max_len,curarg & 0xff);
        break;
      case 'C':
      {
        grub_uint32_t code = curarg;
        int shift;
        unsigned mask;

        if (code <= 0x7f)
	      {
          shift = 0;
          mask = 0;
	      }
        else if (code <= 0x7ff)
	      {
          shift = 6;
          mask = 0xc0;
	      }
        else if (code <= 0xffff)
	      {
          shift = 12;
          mask = 0xe0;
	      }
        else if (code <= 0x10ffff)
	      {
          shift = 18;
          mask = 0xf0;
	      }
        else
	      {
          code = '?';
          shift = 0;
          mask = 0;
	      }

        write_char (str, &count, max_len,mask | (code >> shift));
        for (shift -= 6; shift >= 0; shift -= 6)
          write_char (str, &count, max_len,0x80 | (0x3f & (code >> shift)));
      }
        break;
      case 's':
      {
        grub_size_t len = 0;
        grub_size_t fill;
        const char *p = ((char *) (grub_addr_t) curarg) ? : "(null)";
        grub_size_t i;

        while (len < format2 && p[len])
          len++;

        fill = len < format1 ? format1 - len : 0;

        if (!rightfill)
          while (fill--)
            write_char (str, &count, max_len, zerofill);

        for (i = 0; i < len; i++)
          write_char (str, &count, max_len,*p++);

        if (rightfill)
          while (fill--)
            write_char (str, &count, max_len, zerofill);
      }
        break;
      default:
        write_char (str, &count, max_len,c);
        break;
    }
  }

  if (count < max_len)
    str[count] = '\0';
  else
    str[max_len] = '\0';

  return count;
}

int grub_vsnprintf (char *str, grub_size_t n, const char *fmt, va_list ap);
int
grub_vsnprintf (char *str, grub_size_t n, const char *fmt, va_list ap)
{
  grub_size_t ret;
  struct printf_args args;

  if (!n)
    return 0;

  n--;
  parse_printf_args (fmt, &args, ap);
  ret = grub_vsnprintf_real (str, n, fmt, &args);
  free_printf_args (&args);

  return ret < n ? ret : n;
}

int grub_snprintf (char *str, grub_size_t n, const char *fmt, ...);
int
grub_snprintf (char *str, grub_size_t n, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vsnprintf (str, n, fmt, ap);
  va_end (ap);

  return ret;
}

#if 0
//ASCII码转数字(源，返回结束地址，进制)   0/8/10/16  返回目的
//如果源是十进制(31 33 00)，base无论是0、10，都正确(d)。base是16，则错误(13)。
//如果源是十六进制(30 78 31 33)，base无论是0、16，都正确(13)。base是10，则错误(0)。
unsigned long long grub_strtoull (const char * restrict str, const char ** const restrict end, int base);
unsigned long long
grub_strtoull (const char * restrict str, const char ** const restrict end, int base)
{
  unsigned long long num = 0;
  int found = 0;

  //跳过空白
  // grub_isspace检查*str='\0'
  while (grub_isspace (*str))
    str++;

  //如果未指定，请猜测基数。前缀“0x”表示16，前缀“0”表示8。
  if (str[0] == '0')
  {
    if (str[1] == 'x')
    {
      if (base == 0 || base == 16)
	    {
	      base = 16;  //16进制
	      str += 2;   //移动到数值
	    }
    }
    else if (base == 0 && str[1] >= '0' && str[1] <= '7')  //8进制
      base = 8;
  }

  if (base == 0)
    base = 10;  //10进制

  while (*str)
  {
    unsigned long digit;
    digit = grub_tolower (*str) - '0';
    if (digit > 9)
    {
      digit += '0' - 'a' + 10;
      //digit<=9 检查以防止大于“9”但小于“a”的字符被读取为数字
      if (digit >= (unsigned long) base || digit <= 9)
        break;
    }
    if (digit >= (unsigned long) base)
      break;

    found = 1;
    /* NUM * BASE + DIGIT > ~0ULL */
    num = num * base + digit;
    str++;
  }

  if (! found)
  {
    if (end)
      *end = (char *) str;
    printf_errinfo ("unrecognized number\n");  //无法识别的数字
    return 0;
  }

  if (end)
    *end = (char *) str;

  return num;
}

unsigned long
grub_strtoul (const char * restrict str, const char ** const restrict end, int base)
{
  unsigned long long num;

  num = grub_strtoull (str, end, base);

  return (unsigned long) num;
}
#endif

void *
grub_calloc (grub_size_t nmemb, grub_size_t size);
void *
grub_calloc (grub_size_t nmemb, grub_size_t size) //分配
{
  void *ret;
  grub_size_t sz = 0;

  if (grub_mul (nmemb, size, &sz))
  {
    printf_errinfo ("overflow is detected");
    return NULL;
  }

  ret = grub_memalign (0, sz);
  if (!ret)
    return NULL;

  grub_memset (ret, 0, sz);
  return ret;
}

static grub_err_t
parse_printf_arg_fmt (const char *fmt0, struct printf_args *args,
		      int fmt_check, grub_size_t max_args)
{
  const char *fmt;
  char c;
  grub_size_t n = 0;

  args->count = 0;

  COMPILE_TIME_ASSERT (sizeof (int) == sizeof (grub_uint32_t));
  COMPILE_TIME_ASSERT (sizeof (int) <= sizeof (long long));
  COMPILE_TIME_ASSERT (sizeof (long) <= sizeof (long long));
  COMPILE_TIME_ASSERT (sizeof (long long) == sizeof (void *)
		       || sizeof (int) == sizeof (void *));

  fmt = fmt0;
  while ((c = *fmt++) != 0)
  {
    if (c != '%')
      continue;

    if (*fmt =='-')
      fmt++;

    while (grub_isdigit (*fmt))
      fmt++;

    if (*fmt == '$')
    {
      if (fmt_check)
        return printf_errinfo ("positional arguments are not supported");
      fmt++;
    }

    if (*fmt =='-')
      fmt++;

    while (grub_isdigit (*fmt))
      fmt++;

    if (*fmt =='.')
      fmt++;

    while (grub_isdigit (*fmt))
      fmt++;

    if (*fmt == '*')
    {
      args->count++;
      fmt++;
    }

    c = *fmt++;
    if (c == 'l')
      c = *fmt++;
    if (c == 'l')
      c = *fmt++;

    switch (c)
    {
      case 'p':
      case 'x':
      case 'X':
      case 'u':
      case 'd':
      case 'c':
      case 'C':
      case 's':
        args->count++;
        break;
      case '%':
      /* "%%" is the escape sequence to output "%". */
        break;
      default:
        if (fmt_check)
          return printf_errinfo ("unexpected format");
        break;
    }
  }

  if (fmt_check && args->count > max_args)
    return printf_errinfo ("too many arguments");

  if (args->count <= ARRAY_SIZE (args->prealloc))
    args->ptr = args->prealloc;
  else
  {
    args->ptr = grub_calloc (args->count, sizeof (args->ptr[0])); //分配
    if (!args->ptr)
    {
      if (fmt_check)
      return 0;

      args->ptr = args->prealloc;
      args->count = ARRAY_SIZE (args->prealloc);
    }
  }

  grub_memset (args->ptr, 0, args->count * sizeof (args->ptr[0]));

  fmt = fmt0;
  n = 0;
  while ((c = *fmt++) != 0)
  {
    int longfmt = 0;
    grub_size_t curn;
    const char *p;

    if (c != '%')
      continue;

    curn = n++;

    if (*fmt =='-')
      fmt++;

    p = fmt;

    while (grub_isdigit (*fmt))
      fmt++;

    if (*fmt == '$')
    {
//	  curn = grub_strtoull (p, 0, 10) - 1;
      safe_parse_maxint ((char**)&p, &hex);
      curn = hex - 1;
      fmt++;
    }

    if (*fmt =='-')
      fmt++;

    while (grub_isdigit (*fmt))
      fmt++;

    if (*fmt =='.')
      fmt++;

    while (grub_isdigit (*fmt))
      fmt++;

    if (*fmt == '*')
    {
      fmt++;
    args->ptr[curn].type = INT;
    curn = n++;
    }

    c = *fmt++;
    if (c == '%')
    {
      n--;
      continue;
    }
    if (c == 'l')
    {
      c = *fmt++;
      longfmt = 1;
    }
    if (c == 'l')
    {
      c = *fmt++;
      longfmt = 2;
    }
    if (curn >= args->count)
      continue;
    switch (c)
    {
      case 'x':
      case 'X':
      case 'u':
        args->ptr[curn].type = UNSIGNED_INT + longfmt;
        break;
      case 'd':
        args->ptr[curn].type = INT + longfmt;
        break;
      case 'p':
        if (sizeof (void *) == sizeof (long long))
          args->ptr[curn].type = UNSIGNED_LONGLONG;
        else
          args->ptr[curn].type = UNSIGNED_INT;
        break;
      case 's':
        args->ptr[curn].type = STRING;
        break;
      case 'C':
      case 'c':
        args->ptr[curn].type = INT;
        break;
    }
  }

  return GRUB_ERR_NONE;
}

static void
parse_printf_args (const char *fmt0, struct printf_args *args, va_list args_in)
{
  grub_size_t n;

  parse_printf_arg_fmt (fmt0, args, 0, 0);

  for (n = 0; n < args->count; n++)
    switch (args->ptr[n].type)
    {
      case INT:
        args->ptr[n].ll = va_arg (args_in, int);
        break;
      case LONG:
        args->ptr[n].ll = va_arg (args_in, long);
        break;
      case UNSIGNED_INT:
        args->ptr[n].ll = va_arg (args_in, unsigned int);
        break;
      case UNSIGNED_LONG:
        args->ptr[n].ll = va_arg (args_in, unsigned long);
        break;
      case LONGLONG:
      case UNSIGNED_LONGLONG:
        args->ptr[n].ll = va_arg (args_in, long long);
        break;
      case STRING:
        if (sizeof (void *) == sizeof (long long))
          args->ptr[n].ll = va_arg (args_in, long long);
        else
          args->ptr[n].ll = va_arg (args_in, unsigned int);
        break;
    }
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//net/efi/net.c

char *grub_strdup (const char *s);
char *
grub_strdup (const char *s)
{
  grub_size_t len;
  char *p;

  if (!s)
    return grub_zalloc (1);

  len = grub_strlen (s) + 1;
  p = (char *) grub_malloc (len);
  if (! p)
    return 0;

  return grub_memcpy (p, s, len);
}


char *grub_strndup (const char *s, grub_size_t n);
char *
grub_strndup (const char *s, grub_size_t n)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s);
  if (len > n)
    len = n;
  p = (char *) grub_malloc (len + 1);
  if (! p)
    return 0;

  grub_memcpy (p, s, len);
  p[len] = '\0';
  return p;
}


static void grub_efi_net_config_real (grub_efi_handle_t hnd, char **device, char **path);
static void
grub_efi_net_config_real (grub_efi_handle_t hnd, char **device,
			  char **path)  //网络配置实例
{
  grub_efi_handle_t config_hnd;
  struct grub_efi_net_device *netdev;
  grub_efi_net_interface_t *inf;

  config_hnd = grub_efi_locate_device_path (&ip4_config_guid, grub_efi_get_device_path (hnd), NULL); //定位ip4设备路径
  if (!config_hnd)  //失败
    return;

  for (netdev = net_devices; netdev; netdev = netdev->next)
    if (netdev->handle == config_hnd)
      break;

  if (!netdev)
    return;

  if (!(inf = grub_efi_net_config_from_handle (hnd, netdev, device, path)))  //从句柄配置网络
    return;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//net->efi->net.c

char card_name[10];
static void grub_efi_net_find_cards (void);
static void
grub_efi_net_find_cards (void)  //网络查找卡 ok
{
  grub_efi_uintn_t num_handles;
  grub_efi_handle_t *handles;
  grub_efi_handle_t *handle;
  int id;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &ip4_config_guid,
				    0, &num_handles);	//定位ip4句柄
  if (!handles)
    return;

  for (id = 0, handle = handles; num_handles--; handle++, id++)
  {
    grub_efi_device_path_t *dp;
    grub_efi_ip4_config2_protocol_t *ip4_config;
    grub_efi_ip6_config_protocol_t *ip6_config;
    grub_efi_handle_t http_handle;
    grub_efi_http_t *http;
    grub_efi_handle_t dhcp4_handle;
    grub_efi_dhcp4_protocol_t *dhcp4;
    grub_efi_handle_t dhcp6_handle;
    grub_efi_dhcp6_protocol_t *dhcp6;
    struct grub_efi_net_device *d;

    dp = grub_efi_get_device_path (*handle);  //获得设备路径
    if (!dp)
      continue;

    ip4_config = grub_efi_open_protocol (*handle, &ip4_config_guid,
				    GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL); //打开ip4协议     
    if (!ip4_config)  //不支持ip4
      continue;

    ip6_config = grub_efi_open_protocol (*handle, &ip6_config_guid,
				    GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL); //打开ip6协议
    http_handle = grub_efi_service_binding (*handle, &http_service_binding_guid); //http服务绑定
    http = (http_handle) 
          ? grub_efi_open_protocol (http_handle, &http_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL) //http服务绑定成功,打开http协议
          : NULL;
    dhcp4_handle = grub_efi_service_binding (*handle, &dhcp4_service_binding_guid); //dhcp4服务绑定
    dhcp4 = (dhcp4_handle)
          ? grub_efi_open_protocol (dhcp4_handle, &dhcp4_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL) //dhcp4服务绑定成功,打开dhcp4协议
          : NULL;
    dhcp6_handle = grub_efi_service_binding (*handle, &dhcp6_service_binding_guid); //dhcp6服务绑定
    dhcp6 = (dhcp6_handle)
          ? grub_efi_open_protocol (dhcp6_handle, &dhcp6_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL) //dhcp6服务绑定成功,打开dhcp6协议
          : NULL;

    d = grub_malloc (sizeof (*d));  //分配内存
    if (!d) //如果失败
    {
      grub_free (handles);  //释放
      while (net_devices)
	    {
	      d = net_devices->next;
	      grub_free (net_devices);
	      net_devices = d;
	    }
      return;
    }
    //创建网络设备
    d->handle = *handle;              //句柄        e5983a0
    d->ip4_config = ip4_config;       //ip4配置     f54f578
    d->ip6_config = ip6_config;       //ip6配置     f533f70
    d->http_handle = http_handle;     //http句柄    f4fbd18
    d->http = http;                   //http入口    f4f2020
    d->dhcp4_handle = dhcp4_handle;   //dhcp4句柄   f4f6e18
    d->dhcp4 = dhcp4;                 //dhcp4入口   f4f5420
    d->dhcp6_handle = dhcp6_handle;   //dhcp6句柄   f50f798
    d->dhcp6 = dhcp6;                 //dhcp6入口   f4f5d40
    d->next = net_devices;            //下一个      0
    grub_sprintf (card_name,"efinet%d", id);
    d->card_name = card_name;         //网卡名称    efinet0
    d->net_interfaces = NULL;         //网络接口
    net_devices = d;                  //网络设备入口  e5982a0
  }

  grub_efi_net_add_pxebc_to_cards (); //将pxebc添加到卡中
  grub_free (handles);
  set_ip_policy_to_static (); //将ip策略设置为静态
}

static void
grub_efi_net_add_pxebc_to_cards (void)  //将pxebc添加到卡中  ok
{
  grub_efi_uintn_t num_handles;
  grub_efi_handle_t *handles;
  grub_efi_handle_t *handle;
  int is_ip6_x;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &pxe_io_guid,
				    0, &num_handles); //定位pxe句柄
  if (!handles) //失败
    return;

  for (handle = handles; num_handles--; handle++)
  {
    grub_efi_device_path_t *dp, *ddp, *ldp;
    struct grub_efi_net_device *d;


    dp = grub_efi_get_device_path (*handle);  //获得设备路径
    if (!dp)  //失败继续
      continue;

    ddp = grub_efi_duplicate_device_path (dp);  //重复设备路径
    ldp = grub_efi_find_last_device_path (ddp); //查找设备最后路径

    if (ldp->type == GRUB_EFI_MESSAGING_DEVICE_PATH_TYPE            //消息传递设备路径类型 3
            && ldp->subtype == GRUB_EFI_IPV4_DEVICE_PATH_SUBTYPE)   //IPV4设备路径子类型   12
    {
      is_ip6_x = 0;   //不是ip6
      ldp->type = GRUB_EFI_END_DEVICE_PATH_TYPE;
      ldp->subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
      ldp->length = sizeof (*ldp);
    }
    else if (ldp->type == GRUB_EFI_MESSAGING_DEVICE_PATH_TYPE       //消息传递设备路径类型 3
            && ldp->subtype == GRUB_EFI_IPV6_DEVICE_PATH_SUBTYPE)   //IPV6设备路径子类型   13
    {
      is_ip6_x = 1;   //是ip6
      ldp->type = GRUB_EFI_END_DEVICE_PATH_TYPE;
      ldp->subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
      ldp->length = sizeof (*ldp);
    }

    for (d = net_devices; d; d = d->next)
      if (grub_efi_compare_device_paths (ddp, grub_efi_get_device_path (d->handle)) == 0) //比较设备路径,相等退出
        break;

    if (!d) //失败
    {
      grub_free (ddp);
      continue;
    }

    pxe_entry = 0;
    pxe_entry = grub_efi_open_protocol (*handle, &pxe_io_guid,
          GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);   //打开pxe协议
    if (!pxe_entry) //失败
    {
      grub_free (ddp);
      continue;
    }
    
    struct grub_efi_pxe_mode *pxe_mode;
    pxe_mode = pxe_entry->mode;	//模式
		discover_reply = (BOOTPLAYER *)((char *)&pxe_mode->dhcp_ack.dhcpv4);	//引导播放器	

		pxe_sip = discover_reply->sip;	//服务器IP

    if (is_ip6_x) //是ip6
    {
      d->ip6_pxe_handle = *handle;  //ip6_pxe句柄
      d->ip6_pxe = pxe_entry;       //pxe入口
    }
    else
    {
      d->ip4_pxe_handle = *handle;  //ip4_pxe句柄
      d->ip4_pxe = pxe_entry;       //pxe入口
    }

    grub_free (ddp);
  }

  grub_free (handles);
}

static void
set_ip_policy_to_static (void) //将ip策略设置为静态   ok
{
  struct grub_efi_net_device *dev;

  for (dev = net_devices; dev; dev = dev->next)
  {
    grub_efi_ip4_config2_policy_t ip4_policy = GRUB_EFI_IP4_CONFIG2_POLICY_STATIC;  //静态

    if (efi_call_4 (dev->ip4_config->set_data, dev->ip4_config,
            GRUB_EFI_IP4_CONFIG2_DATA_TYPE_POLICY,                                  //策略
            sizeof (ip4_policy), &ip4_policy) != GRUB_EFI_SUCCESS)
      printf_debug ("could not set GRUB_EFI_IP4_CONFIG2_POLICY_STATIC on dev `%s'\n", dev->card_name);  //无法在dev上设置GRUBEFI_IP4_CONFIG2_POLICY_STATIC

    if (dev->ip6_config)
    {
      grub_efi_ip6_config_policy_t ip6_policy = GRUB_EFI_IP6_CONFIG_POLICY_MANUAL;

      if (efi_call_4 (dev->ip6_config->set_data, dev->ip6_config,
              GRUB_EFI_IP6_CONFIG_DATA_TYPE_POLICY,
              sizeof (ip6_policy), &ip6_policy) != GRUB_EFI_SUCCESS)
        printf_debug ("could not set GRUB_EFI_IP6_CONFIG_POLICY_MANUAL on dev `%s'\n", dev->card_name); //无法在dev上设置GRUB_EFI_IP6_CONFIG_POLICY_MANUAL
    }
  }
}

static grub_efi_handle_t
grub_efi_service_binding (grub_efi_handle_t dev, grub_efi_guid_t *service_binding_guid) //dev服务绑定
{
  grub_efi_service_binding_t *service;
  grub_efi_status_t status;
  grub_efi_handle_t child_dev = NULL;

  service = grub_efi_open_protocol (dev, service_binding_guid, GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);  //打开服务绑定协议
  if (!service) //失败
  {
    printf_errinfo ("couldn't open efi service binding protocol\n"); //无法打开efi服务绑定协议
    return NULL;
  }

  status = efi_call_2 (service->create_child, service, &child_dev); //服务->创建子项
  if (status != GRUB_EFI_SUCCESS) //失败
  {
    printf_errinfo ("Failed to create child device of http service\n"); //无法创建http服务的子设备
    return NULL;
  }

  return child_dev; //子设备
}

static int
grub_efi_net_parse_address (const char *address,
    grub_efi_ip4_config2_manual_address_t *ip4,
    grub_efi_ip6_config_manual_address_t *ip6,
    int *has_cidr)  //网络解析地址
{
  const char *rest;

  if (grub_efi_string_to_ip4_address (address, &ip4->address, &rest)) //字符串到ip4地址
  {
    is_ip6 = 0;   
    if (*rest == '/')
    {
      grub_uint32_t subnet_mask_size;

//      subnet_mask_size = grub_strtoul (rest + 1, &rest, 0);
      safe_parse_maxint ((char**)&rest + 1, &hex);
      subnet_mask_size = hex;

      if (!errnum && subnet_mask_size <= 32 && *rest == 0)
	    {
	      grub_uint32_t subnet_mask;

	      subnet_mask = grub_cpu_to_be32 ((0xffffffffU << (32 - subnet_mask_size)));        
	      grub_memcpy (ip4->subnet_mask, &subnet_mask, sizeof (ip4->subnet_mask));
	      if (has_cidr)
          *has_cidr = 1;
	      return 0;
	    }
    }
    else if (*rest == 0)
    {
      grub_uint32_t subnet_mask = 0xffffffffU;
      grub_memcpy (ip4->subnet_mask, &subnet_mask, sizeof (ip4->subnet_mask));

      if (has_cidr)
        *has_cidr = 0;
      return 0;
    }
  }
  else if (grub_efi_string_to_ip6_address (address, &ip6->address, &rest))
  {
    is_ip6 = 1;  
    if (*rest == '/')
    {
      grub_efi_uint8_t prefix_length;

//      prefix_length = grub_strtoul (rest + 1, &rest, 0);
      safe_parse_maxint ((char**)&rest + 1, &hex);
      prefix_length = hex;
      if (!errnum && prefix_length <= 128 && *rest == 0)
	    {
	      ip6->prefix_length = prefix_length;
	      ip6->is_anycast = 0;
	      if (has_cidr)
          *has_cidr = 1;
	      return 0;
	    }
    }
    else if (*rest == 0)
    {
      ip6->prefix_length = 128;
      ip6->is_anycast = 0;
      if (has_cidr)
        *has_cidr = 0;
      return 1;
    }
  }

  printf_errinfo ("unrecognised network address %s\n", address);
  return 1;
}

static grub_efi_net_interface_t *
match_route (const char *server)  //匹配路线
{
  grub_err_t err;
  grub_efi_ip4_config2_manual_address_t ip4;
  grub_efi_ip6_config_manual_address_t ip6;
  grub_efi_net_interface_t *inf;

  err = grub_efi_net_parse_address (server, &ip4, &ip6, 0);
  if (err)
    return NULL;

  if (is_ip6)
  {
    struct grub_efi_net_device *dev;
    grub_efi_net_ip_address_t addr;

    grub_memcpy (addr.ip6, ip6.address, sizeof(ip6.address));

    for (dev = net_devices; dev; dev = dev->next)
      if ((inf = efi_net_ip6_config->best_interface (dev, &addr)))
//      if ((inf = grub_efi_ip6_interface_match (dev, &addr)))
        return inf;
  }
  else
  {
    struct grub_efi_net_device *dev;
    grub_efi_net_ip_address_t addr;

    grub_memcpy (addr.ip4, ip4.address, sizeof(ip4.address));
    for (dev = net_devices; dev; dev = dev->next)
    {
      if ((inf = efi_net_ip4_config->best_interface (dev, &addr))) //ip4接口匹配
      {
        return inf;
      }
    }
  }

  return 0;
}

static grub_efi_handle_t
grub_efi_locate_device_path (grub_efi_guid_t *protocol, grub_efi_device_path_t *device_path,
			    grub_efi_device_path_t **r_device_path) //定位设备路径  ok
{
  grub_efi_handle_t handle;
  grub_efi_status_t status;

  status = efi_call_3 (grub_efi_system_table->boot_services->locate_device_path,
		      protocol, &device_path, &handle);

  if (status != GRUB_EFI_SUCCESS)
    return 0;

  if (r_device_path)
    *r_device_path = device_path;

  return handle;
}

static void pxe_get_boot_location (const struct grub_net_bootp_packet *bp, char **device, char **path, int is_default);
static void
pxe_get_boot_location (const struct grub_net_bootp_packet *bp,
		  char **device,
		  char **path,
		  int is_default) //pxe获得引导位置  ok
{
//  char *server = grub_xasprintf ("%d.%d.%d.%d",   //????
  char server[24];
  grub_sprintf (server,  "%d.%d.%d.%d",
	     ((grub_uint8_t *) &bp->server_ip)[0],
	     ((grub_uint8_t *) &bp->server_ip)[1],
	     ((grub_uint8_t *) &bp->server_ip)[2],
	     ((grub_uint8_t *) &bp->server_ip)[3]);

//  *device = grub_xasprintf ("tftp,%s", server);
  char str[24];
  grub_sprintf (str, "tftp,%s", server);
  *device = str;
  *path = grub_strndup (bp->boot_file, sizeof (bp->boot_file));
  if (*path)
  {
    char *slash;
    slash = grub_strrchr (*path, '/');
    if (slash)
      *slash = 0;
    else
      **path = 0;
  }

  if (is_default)
    default_server = server;
  else
    grub_free (server);
}

grub_efi_net_interface_t * grub_efi_net_create_interface (struct grub_efi_net_device *dev, const char *interface_name, grub_efi_net_ip_manual_address_t *net_ip, int has_subnet);
grub_efi_net_interface_t *
grub_efi_net_create_interface (struct grub_efi_net_device *dev,
		const char *interface_name,
		grub_efi_net_ip_manual_address_t *net_ip,
		int has_subnet) //网络创建接口  ok
{
  grub_efi_net_interface_t *inf;

  for (inf = dev->net_interfaces; inf; inf = inf->next)
  {
    if (inf->prefer_ip6 == net_ip->is_ip6)
      break;
  }

  if (!inf)
  {
    inf = grub_malloc (sizeof(*inf));
    inf->name = grub_strdup (interface_name);
    inf->prefer_ip6 = net_ip->is_ip6;
    inf->dev = dev;
    inf->next = dev->net_interfaces;
    inf->ip_config = (net_ip->is_ip6) ? efi_net_ip6_config : efi_net_ip4_config ;
    dev->net_interfaces = inf;
  }
  else
  {
    grub_free (inf->name);
    inf->name = grub_strdup (interface_name);
  }

  if (!efi_net_interface_set_address (inf, net_ip, has_subnet))
  {
    printf_errinfo ("Set Address Failed\n");
    return NULL;
  }

  return inf;
}

struct grub_net_dhcp6_packet
 {
  grub_uint32_t message_type:8;
  grub_uint32_t transaction_id:24;
  grub_uint8_t dhcp_options[0];
 } GRUB_PACKED;
 
struct grub_net_dhcp6_option {
  grub_uint16_t code;
  grub_uint16_t len;
  grub_uint8_t data[0];
} GRUB_PACKED;

enum
  {
    GRUB_NET_DHCP6_OPTION_CLIENTID = 1,
    GRUB_NET_DHCP6_OPTION_SERVERID = 2,
    GRUB_NET_DHCP6_OPTION_IA_NA = 3,
    GRUB_NET_DHCP6_OPTION_IAADDR = 5,
    GRUB_NET_DHCP6_OPTION_ORO = 6,
    GRUB_NET_DHCP6_OPTION_ELAPSED_TIME = 8,
    GRUB_NET_DHCP6_OPTION_DNS_SERVERS = 23,
    GRUB_NET_DHCP6_OPTION_BOOTFILE_URL = 59
  };

static int
url_parse_fields (const char *url, char **proto, char **host, char **path)  //url解析字段
{
  const char *p, *ps;
  grub_size_t l;

  *proto = *host = *path = NULL;
  ps = p = url;

  while ((p = grub_strchr (p, ':')))
    {
      if (grub_strlen (p) < sizeof ("://") - 1)
	break;
      if (grub_memcmp (p, "://", sizeof ("://") - 1) == 0)
	{
	  l = p - ps;
	  *proto = grub_malloc (l + 1);
	  if (!*proto)
      return 0;

	  grub_memcpy (*proto, ps, l);
	  (*proto)[l] = '\0';
	  p +=  sizeof ("://") - 1;
	  break;
	}
      ++p;
    }

  if (!*proto)
    {
      printf_errinfo ("url: %s is not valid, protocol not found\n", url);
      return 0;
    }

  ps = p;
  p = grub_strchr (p, '/');

  if (!p)
    {
      printf_errinfo ("url: %s is not valid, host/path not found\n", url);
      grub_free (*proto);
      *proto = NULL;
      return 0;
    }

  l = p - ps;

  if (l > 2 && ps[0] == '[' && ps[l - 1] == ']')
    {
      *host = grub_malloc (l - 1);
      if (!*host)
	{
	  grub_free (*proto);
	  *proto = NULL;
	  return 0;
	}
      grub_memcpy (*host, ps + 1, l - 2);
      (*host)[l - 2] = 0;
    }
  else
    {
      *host = grub_malloc (l + 1);
      if (!*host)
	{
	  grub_free (*proto);
	  *proto = NULL;
	  return 0;
	}
      grub_memcpy (*host, ps, l);
      (*host)[l] = 0;
    }

  *path = grub_strdup (p);
  if (!*path)
    {
      grub_free (*host);
      grub_free (*proto);
      *host = NULL;
      *proto = NULL;
      return 0;
    }
  return 1;
}

static void
url_get_boot_location (const char *url, char **device, char **path, int is_default) //url获得引导位置
{
  char *protocol, *server, *file;
  char *slash;

  if (!url_parse_fields (url, &protocol, &server, &file))
    return;

  if ((slash = grub_strrchr (file, '/')))
    *slash = 0;
  else
    *file = 0;

//  *device = grub_xasprintf ("%s,%s", protocol, server);
  char str[24];
  grub_sprintf (str, "%s,%s", protocol, server);
  *device = str;
  *path = grub_strdup(file);

  if (is_default)
    default_server = server;
  else
    grub_free (server);

  grub_free (protocol);
  grub_free (file);
}

static void
pxe_get_boot_location_v6 (const struct grub_net_dhcp6_packet *dp,
		  grub_size_t dhcp_size,
		  char **device,
		  char **path) //pxe获得引导位置v6
{

  struct grub_net_dhcp6_option *dhcp_opt;
  grub_size_t dhcp_remain_size;
  *device = *path = 0;

  if (dhcp_size < sizeof (*dp))
  {
    printf_errinfo ("DHCPv6 packet size too small\n");
    return;
  }

  dhcp_remain_size = dhcp_size - sizeof (*dp);
  dhcp_opt = (struct grub_net_dhcp6_option *)dp->dhcp_options;

  while (dhcp_remain_size)
  {
    grub_uint16_t code = grub_be_to_cpu16 (dhcp_opt->code);
    grub_uint16_t len = grub_be_to_cpu16 (dhcp_opt->len);
    grub_uint16_t option_size = sizeof (*dhcp_opt) + len;

    if (dhcp_remain_size < option_size || code == 0)
      break;

    if (code == GRUB_NET_DHCP6_OPTION_BOOTFILE_URL)
    {
      char *url = grub_malloc (len + 1);

      grub_memcpy (url, dhcp_opt->data, len);
      url[len] = 0;

      url_get_boot_location ((const char *)url, device, path, 1); //url获得引导位置
      grub_free (url);
      break;
    }

    dhcp_remain_size -= option_size;
    dhcp_opt = (struct grub_net_dhcp6_option *)((grub_uint8_t *)dhcp_opt + option_size);
  }
}


static grub_efi_net_interface_t *
grub_efi_net_config_from_handle (grub_efi_handle_t *hnd,
		  struct grub_efi_net_device *netdev,
		  char **device,
		  char **path)  //从句柄配置网络  ok
{
  if (hnd == netdev->ip4_pxe_handle)
    pxe_entry = netdev->ip4_pxe;
  else if (hnd == netdev->ip6_pxe_handle)
    pxe_entry = netdev->ip6_pxe;

  if (pxe_entry->mode->using_ipv6)
  {
    grub_efi_net_ip_manual_address_t net_ip;

    pxe_get_boot_location_v6 ((const struct grub_net_dhcp6_packet *) &pxe_entry->mode->dhcp_ack, sizeof (pxe_entry->mode->dhcp_ack), device, path); //pxe获得引导位置v6

    grub_memcpy (net_ip.ip6.address, pxe_entry->mode->station_ip.v6, sizeof(net_ip.ip6.address));
    net_ip.ip6.prefix_length = GRUB_EFI_IP6_PREFIX_LENGTH;
    net_ip.ip6.is_anycast = 0;
    net_ip.is_ip6 = 1;
    return (grub_efi_net_create_interface (netdev, netdev->card_name, &net_ip, 1));
  }
  else
  {
    grub_efi_net_ip_manual_address_t net_ip;

    pxe_get_boot_location ((const struct grub_net_bootp_packet *) &pxe_entry->mode->dhcp_ack, device, path, 1); //pxe获得引导位置 ok

    grub_memcpy (net_ip.ip4.address, pxe_entry->mode->station_ip.v4, sizeof (net_ip.ip4.address));
    grub_memcpy (net_ip.ip4.subnet_mask, pxe_entry->mode->subnet_mask.v4, sizeof (net_ip.ip4.subnet_mask));
    net_ip.is_ip6 = 0;

    return (grub_efi_net_create_interface (netdev,netdev->card_name, &net_ip, 1)); //网络创建接口  ok
  }
  return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//net/efi/ip4_config.c
char *
grub_efi_hw_address_to_string (grub_efi_uint32_t hw_address_size, grub_efi_mac_address_t hw_address)  //硬件地址到字符串
{
  char *hw_addr, *p;
  grub_size_t sz, s, i;

  if (grub_mul (hw_address_size, sizeof ("XX:") - 1, &sz) ||
      grub_add (sz, 1, &sz))
    return NULL;

  hw_addr = grub_malloc (sz);
  if (!hw_addr)
    return NULL;

  p = hw_addr;
  s = sz;
  for (i = 0; i < hw_address_size; i++)
  {
    grub_snprintf (p, sz, "%02x:", hw_address[i]);
    p +=  sizeof ("XX:") - 1;
    s -=  sizeof ("XX:") - 1;
  }

  hw_addr[sz - 2] = '\0';
  return hw_addr;
}

char *
grub_efi_ip4_address_to_string (grub_efi_ipv4_address_t *address) //ip4地址到字符串
{
  char *addr;

  addr = grub_malloc (sizeof ("XXX.XXX.XXX.XXX"));
  if (!addr)
      return NULL;

  /* FIXME: Use grub_xasprintf ? */
  grub_snprintf (addr,
	  sizeof ("XXX.XXX.XXX.XXX"),
	  "%u.%u.%u.%u",
	  (*address)[0],
	  (*address)[1],
	  (*address)[2],
	  (*address)[3]);

  return addr;
}

int
grub_efi_string_to_ip4_address (const char *val, grub_efi_ipv4_address_t *address, const char **rest) //字符串到ip4地址
{
  grub_uint32_t newip = 0;
  int i;
  const char *ptr = val;

  for (i = 0; i < 4; i++)
  {
    unsigned long t;
//    t = grub_strtoul (ptr, &ptr, 0);
    safe_parse_maxint ((char**)&ptr, &hex);
    t = hex;

    if (errnum)
    {
      errnum = GRUB_ERR_NONE;
      return 0;
    }
    if (*ptr != '.' && i == 0)
    {
      /* XXX: t is in host byte order */
      newip = t;
      break;
    }
    if (t & ~0xff)
      return 0;
    newip <<= 8;
    newip |= t;
    if (i != 3 && *ptr != '.')
      return 0;
    ptr++;
  }

  newip =  grub_cpu_to_be32 (newip);
  grub_memcpy (address, &newip, sizeof(*address));
  if (rest)
    *rest = (ptr - 1);
  return 1;
}

//被grub_efi_ip4_interface_name，grub_efi_ip4_interface_hw_address，grub_efi_ip4_interface_route_table，grub_efi_ip4_interface_match调用
static grub_efi_ip4_config2_interface_info_t *
efi_ip4_config_interface_info (grub_efi_ip4_config2_protocol_t *ip4_config) //ip4配置接口信息
{
  grub_efi_uintn_t sz;
  grub_efi_status_t status;
  grub_efi_ip4_config2_interface_info_t *interface_info;

  sz = sizeof (*interface_info) + sizeof (*interface_info->route_table);
  interface_info = grub_malloc (sz);
  if (!interface_info)
    return NULL;

  status = efi_call_4 (ip4_config->get_data, ip4_config,
        GRUB_EFI_IP4_CONFIG2_DATA_TYPE_INTERFACEINFO,
        &sz, interface_info);

  if (status == GRUB_EFI_BUFFER_TOO_SMALL)
  {
    grub_free (interface_info);
    interface_info = grub_malloc (sz);
    status = efi_call_4 (ip4_config->get_data, ip4_config,
		    GRUB_EFI_IP4_CONFIG2_DATA_TYPE_INTERFACEINFO,
		    &sz, interface_info);
  }

  if (status != GRUB_EFI_SUCCESS)
  {
    grub_free (interface_info);
    return NULL;
  }

  return interface_info;
}

static grub_efi_ip4_config2_manual_address_t *
efi_ip4_config_manual_address (grub_efi_ip4_config2_protocol_t *ip4_config) //ip4配置手动地址
{
  grub_efi_uintn_t sz;
  grub_efi_status_t status;
  grub_efi_ip4_config2_manual_address_t *manual_address;

  sz = sizeof (*manual_address);
  manual_address = grub_malloc (sz);
  if (!manual_address)
    return NULL;

  status = efi_call_4 (ip4_config->get_data, ip4_config,
		    GRUB_EFI_IP4_CONFIG2_DATA_TYPE_MANUAL_ADDRESS,
		    &sz, manual_address);

  if (status != GRUB_EFI_SUCCESS)
  {
    grub_free (manual_address);
    return NULL;
  }

  return manual_address;
}

char *
grub_efi_ip4_interface_name (struct grub_efi_net_device *dev) //ip4接口名称
{
  grub_efi_ip4_config2_interface_info_t *interface_info;
  char *name;

  interface_info = efi_ip4_config_interface_info (dev->ip4_config); //ip4配置接口信息

  if (!interface_info)
    return NULL;

  name = grub_malloc (GRUB_EFI_IP4_CONFIG2_INTERFACE_INFO_NAME_SIZE
		      * GRUB_MAX_UTF8_PER_UTF16 + 1);
  *grub_utf16_to_utf8 ((grub_uint8_t *)name, interface_info->name,
		      GRUB_EFI_IP4_CONFIG2_INTERFACE_INFO_NAME_SIZE) = 0;
  grub_free (interface_info);
  return name;
}

static char *
grub_efi_ip4_interface_hw_address (struct grub_efi_net_device *dev) //ip4接口硬件地址
{
  grub_efi_ip4_config2_interface_info_t *interface_info;
  char *hw_addr;

  interface_info = efi_ip4_config_interface_info (dev->ip4_config); //ip4配置接口信息

  if (!interface_info)
    return NULL;

  hw_addr = grub_efi_hw_address_to_string (interface_info->hw_address_size, interface_info->hw_address);  //硬件地址到字符串
  grub_free (interface_info);

  return hw_addr;
}

static char *
grub_efi_ip4_interface_address (struct grub_efi_net_device *dev)  //ip4接口地址
{
  grub_efi_ip4_config2_manual_address_t *manual_address;
  char *addr;

  manual_address = efi_ip4_config_manual_address (dev->ip4_config); //ip4配置手动地址

  if (!manual_address)
    return NULL;

  addr = grub_efi_ip4_address_to_string (&manual_address->address); //ip4地址到字符串
  grub_free (manual_address);
  return addr;
}

static int
address_mask_size (grub_efi_ipv4_address_t *address)  //地址掩码尺寸
{
  grub_uint8_t i;
  grub_uint32_t u32_addr = grub_be_to_cpu32 (grub_get_unaligned32 (address));

  if (u32_addr == 0)
    return 0;

  for (i = 0; i < 32 ; ++i)
  {
    if (u32_addr == ((0xffffffff >> i) << i))
      return (32 - i);
  }

  return -1;
}

static char **
grub_efi_ip4_interface_route_table (struct grub_efi_net_device *dev)  //ip4接口路由表
{
  grub_efi_ip4_config2_interface_info_t *interface_info;
  char **ret;
  int id;
  grub_size_t i, nmemb;

  interface_info = efi_ip4_config_interface_info (dev->ip4_config); //ip4配置接口信息
  if (!interface_info)
    return NULL;

  if (grub_add (interface_info->route_table_size, 1, &nmemb))
  {
    errnum = GRUB_ERR_OUT_OF_RANGE;
    return NULL;
  }

  ret = grub_calloc (nmemb, sizeof (*ret));
  if (!ret)
  {
    grub_free (interface_info);
    return NULL;
  }

  id = 0;
  for (i = 0; i < interface_info->route_table_size; i++)
  {
    char *subnet, *gateway, *mask;
    grub_uint32_t u32_subnet, u32_gateway;
    int mask_size;
    grub_efi_ip4_route_table_t *route_table = interface_info->route_table + i;
    grub_efi_net_interface_t *inf;
    char *interface_name = NULL;

    for (inf = dev->net_interfaces; inf; inf = inf->next)
      if (!inf->prefer_ip6)
        interface_name = inf->name;

    u32_gateway = grub_get_unaligned32 (&route_table->gateway_address);
    gateway = grub_efi_ip4_address_to_string (&route_table->gateway_address); //ip4地址到字符串
    u32_subnet = grub_get_unaligned32 (&route_table->subnet_address);
    subnet = grub_efi_ip4_address_to_string (&route_table->subnet_address); //ip4地址到字符串
    mask_size = address_mask_size (&route_table->subnet_mask);  //地址掩码尺寸
    mask = grub_efi_ip4_address_to_string (&route_table->subnet_mask); //ip4地址到字符串
    if (u32_subnet && !u32_gateway && interface_name)
//	ret[id++] = grub_xasprintf ("%s:local %s/%d %s", dev->card_name, subnet, mask_size, interface_name);
        grub_sprintf (ret[id++], "%s:local %s/%d %s", dev->card_name, subnet, mask_size, interface_name);
    else if (u32_subnet && u32_gateway)
//	ret[id++] = grub_xasprintf ("%s:gw %s/%d gw %s", dev->card_name, subnet, mask_size, gateway);
      grub_sprintf (ret[id++], "%s:gw %s/%d gw %s", dev->card_name, subnet, mask_size, gateway);
    else if (!u32_subnet && u32_gateway)
//	ret[id++] = grub_xasprintf ("%s:default %s/%d gw %s", dev->card_name, subnet, mask_size, gateway);
    grub_sprintf (ret[id++], "%s:default %s/%d gw %s", dev->card_name, subnet, mask_size, gateway);
    grub_free (subnet);
    grub_free (gateway);
    grub_free (mask);
  }

  ret[id] = NULL;
  grub_free (interface_info);
  return ret;
}

static grub_efi_net_interface_t *
grub_efi_ip4_interface_match (struct grub_efi_net_device *dev, grub_efi_net_ip_address_t *ip_address) //ip4接口匹配
{
  grub_efi_ip4_config2_interface_info_t *interface_info;
  grub_efi_net_interface_t *inf;
  int i;
  grub_efi_ipv4_address_t *address = &ip_address->ip4;

  interface_info = efi_ip4_config_interface_info (dev->ip4_config); //ip4配置接口信息
  if (!interface_info)
    return NULL;

  for (i = 0; i < (int)interface_info->route_table_size; i++)
  {
    grub_efi_ip4_route_table_t *route_table = interface_info->route_table + i;
    grub_uint32_t u32_address, u32_mask, u32_subnet;

    u32_address = grub_get_unaligned32 (address);
    u32_subnet = grub_get_unaligned32 (route_table->subnet_address);
    u32_mask = grub_get_unaligned32 (route_table->subnet_mask);
    /* SKIP Default GATEWAY */
    if (!u32_subnet && !u32_mask)
      continue;

    if ((u32_address & u32_mask) == u32_subnet)
    {
      for (inf = dev->net_interfaces; inf; inf = inf->next)
        if (!inf->prefer_ip6)
	      {
          grub_free (interface_info);
          return inf;
	      }
    }
  }

  grub_free (interface_info);
  return NULL;
}

static int
grub_efi_ip4_interface_set_manual_address (struct grub_efi_net_device *dev,
	    grub_efi_net_ip_manual_address_t *net_ip,
	    int with_subnet)  //接口设置手动地址
{
  grub_efi_status_t status;
  grub_efi_ip4_config2_manual_address_t *address = &net_ip->ip4;

  if (!with_subnet)
  {
    grub_efi_ip4_config2_manual_address_t *manual_address =
    efi_ip4_config_manual_address (dev->ip4_config); //ip4配置手动地址

    if (manual_address)
    {
      grub_memcpy (address->subnet_mask, manual_address->subnet_mask, sizeof(address->subnet_mask));
      grub_free (manual_address);
    }
    else
    {
      /* XXX: */
      address->subnet_mask[0] = 0xff;
      address->subnet_mask[1] = 0xff;
      address->subnet_mask[2] = 0xff;
      address->subnet_mask[3] = 0;
    }
  }

  status = efi_call_4 (dev->ip4_config->set_data, dev->ip4_config,
		    GRUB_EFI_IP4_CONFIG2_DATA_TYPE_MANUAL_ADDRESS,
		    sizeof(*address), address);
  if (status != GRUB_EFI_SUCCESS)
    return 0;

  return 1;
}

static int
grub_efi_ip4_interface_set_gateway (struct grub_efi_net_device *dev,
	      grub_efi_net_ip_address_t *address) //ip4接口设置网关
{
  grub_efi_status_t status;

  status = efi_call_4 (dev->ip4_config->set_data, dev->ip4_config,
      GRUB_EFI_IP4_CONFIG2_DATA_TYPE_GATEWAY,
      sizeof (address->ip4), &address->ip4);

  if (status != GRUB_EFI_SUCCESS)
    return 0;
  return 1;
}

/* FIXME: Multiple DNS */
static int
grub_efi_ip4_interface_set_dns (struct grub_efi_net_device *dev,
	      grub_efi_net_ip_address_t *address) //ip4接口设置dns
{
  grub_efi_status_t status;

  status = efi_call_4 (dev->ip4_config->set_data, dev->ip4_config,
		GRUB_EFI_IP4_CONFIG2_DATA_TYPE_DNSSERVER,
		sizeof (address->ip4), &address->ip4);

  if (status != GRUB_EFI_SUCCESS)
    return 0;
  return 1;
}

grub_efi_net_ip_config_t *efi_net_ip4_config = &(grub_efi_net_ip_config_t)
  {
    .get_hw_address = grub_efi_ip4_interface_hw_address,        //获得_ip4接口硬件地址
    .get_address = grub_efi_ip4_interface_address,              //获得_ip4接口地址
    .get_route_table = grub_efi_ip4_interface_route_table,      //获得_ip4路由表
    .best_interface = grub_efi_ip4_interface_match,             //最佳接口_ip4接口匹配
    .set_address = grub_efi_ip4_interface_set_manual_address,   //设置_地址
    .set_gateway = grub_efi_ip4_interface_set_gateway,          //设置_网关
    .set_dns = grub_efi_ip4_interface_set_dns                   //设置_dns
  };


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//net/efi/ip6_config.c
char *
grub_efi_ip6_address_to_string (grub_efi_pxe_ipv6_address_t *address) //ip6地址到字符串
{
  char *str = grub_malloc (sizeof ("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX"));
  char *p;
  int i;
  int squash;

  if (!str)
    return NULL;

  p = str;
  squash = 0;
  for (i = 0; i < 8; ++i)
  {
    grub_uint16_t addr;

    if (i == 7)
      squash = 2;

    addr = grub_get_unaligned16 (address->addr + i * 2);
    if (grub_be_to_cpu16 (addr))
    {
      char buf[sizeof ("XXXX")];
      if (i > 0)
        *p++ = ':';
      grub_snprintf (buf, sizeof (buf), "%x", grub_be_to_cpu16 (addr));
      grub_strcpy (p, buf);
      p += grub_strlen (buf);

      if (squash == 1)
        squash = 2;
    }
    else
    {
      if (squash == 0)
	    {
	      *p++ = ':';
	      squash = 1;
	    }
      else if (squash == 2)
	    {
	      *p++ = ':';
	      *p++ = '0';
	    }
    }
  }
  *p = '\0';

  return str;
}

int
grub_efi_string_to_ip6_address (const char *val, grub_efi_ipv6_address_t *address, const char **rest) //字符串到ip6地址
{
  grub_uint16_t newip[8];
  const char *ptr = val;
  int word, quaddot = -1;
  int bracketed = 0;

  if (ptr[0] == '[')
  {
    bracketed = 1;
    ptr++;
  }

  if (ptr[0] == ':' && ptr[1] != ':')
    return 0;
  if (ptr[0] == ':')
    ptr++;

  for (word = 0; word < 8; word++)
  {
    unsigned long t;
    if (*ptr == ':')
    {
      quaddot = word;
      word--;
      ptr++;
      continue;
    }
//    t = grub_strtoul (ptr, &ptr, 16);
    safe_parse_maxint ((char**)&ptr, &hex);
    t = hex;
    if (t & ~0xffff)
      return 0;
    newip[word] = grub_cpu_to_be16 (t);

    if (*ptr != ':')
      break;
    ptr++;
  }

  if (quaddot == -1 && word < 7)
    return 0;
  if (quaddot != -1)
  {
    grub_memmove (&newip[quaddot + 7 - word], &newip[quaddot],
		    (word - quaddot + 1) * sizeof (newip[0]));
    grub_memset (&newip[quaddot], 0, (7 - word) * sizeof (newip[0]));
  }
  grub_memcpy (address, newip, 16);
  if (bracketed && *ptr == ']')
  {
    ptr++;
  }
  if (rest)
    *rest = ptr;

  return 1;
}

static grub_efi_ip6_config_interface_info_t *
efi_ip6_config_interface_info (grub_efi_ip6_config_protocol_t *ip6_config)  //ip6配置接口信息
{
  grub_efi_uintn_t sz;
  grub_efi_status_t status;
  grub_efi_ip6_config_interface_info_t *interface_info;

  sz = sizeof (*interface_info) + sizeof (*interface_info->route_table);
  interface_info = grub_malloc (sz);

  status = efi_call_4 (ip6_config->get_data, ip6_config,
      GRUB_EFI_IP6_CONFIG_DATA_TYPE_INTERFACEINFO,
      &sz, interface_info);

  if (status == GRUB_EFI_BUFFER_TOO_SMALL)
  {
    grub_free (interface_info);
    interface_info = grub_malloc (sz);
    status = efi_call_4 (ip6_config->get_data, ip6_config,
		    GRUB_EFI_IP6_CONFIG_DATA_TYPE_INTERFACEINFO,
		    &sz, interface_info);
  }

  if (status != GRUB_EFI_SUCCESS)
  {
    grub_free (interface_info);
    return NULL;
  }

  return interface_info;
}

static grub_efi_ip6_config_manual_address_t *
efi_ip6_config_manual_address (grub_efi_ip6_config_protocol_t *ip6_config)  //ip6配置手动地址
{
  grub_efi_uintn_t sz;
  grub_efi_status_t status;
  grub_efi_ip6_config_manual_address_t *manual_address;

  sz = sizeof (*manual_address);
  manual_address = grub_malloc (sz);
  if (!manual_address)
    return NULL;

  status = efi_call_4 (ip6_config->get_data, ip6_config,
		    GRUB_EFI_IP6_CONFIG_DATA_TYPE_MANUAL_ADDRESS,
		    &sz, manual_address);

  if (status != GRUB_EFI_SUCCESS)
  {
    grub_free (manual_address);
    return NULL;
  }

  return manual_address;
}

char *
grub_efi_ip6_interface_name (struct grub_efi_net_device *dev) //ip6接口名称
{
  grub_efi_ip6_config_interface_info_t *interface_info;
  char *name;

  interface_info = efi_ip6_config_interface_info (dev->ip6_config);  //ip6配置接口信息

  if (!interface_info)
    return NULL;

  name = grub_malloc (GRUB_EFI_IP4_CONFIG2_INTERFACE_INFO_NAME_SIZE
		      * GRUB_MAX_UTF8_PER_UTF16 + 1);
  *grub_utf16_to_utf8 ((grub_uint8_t *)name, interface_info->name,
		      GRUB_EFI_IP4_CONFIG2_INTERFACE_INFO_NAME_SIZE) = 0;
  grub_free (interface_info);
  return name;
}

static char *
grub_efi_ip6_interface_hw_address (struct grub_efi_net_device *dev) //ip6接口硬件地址
{
  grub_efi_ip6_config_interface_info_t *interface_info;
  char *hw_addr;

  interface_info = efi_ip6_config_interface_info (dev->ip6_config);  //ip6配置接口信息

  if (!interface_info)
    return NULL;

  hw_addr = grub_efi_hw_address_to_string (interface_info->hw_address_size, interface_info->hw_address);
  grub_free (interface_info);

  return hw_addr;
}

static char *
grub_efi_ip6_interface_address (struct grub_efi_net_device *dev)  //ip6接口地址
{
  grub_efi_ip6_config_manual_address_t *manual_address;
  char *addr;

  manual_address = efi_ip6_config_manual_address (dev->ip6_config);  //ip6配置手动地址

  if (!manual_address)
    return NULL;

  addr = grub_efi_ip6_address_to_string ((grub_efi_pxe_ipv6_address_t *)&manual_address->address); //ip6地址到字符串
  grub_free (manual_address);
  return addr;
}

static char **
grub_efi_ip6_interface_route_table (struct grub_efi_net_device *dev)  //ip6接口路由表
{
  grub_efi_ip6_config_interface_info_t *interface_info;
  char **ret;
  int id;
  grub_size_t i, nmemb;

  interface_info = efi_ip6_config_interface_info (dev->ip6_config);  //ip6配置接口信息
  if (!interface_info)
    return NULL;

  if (grub_add (interface_info->route_count, 1, &nmemb))
  {
    errnum = GRUB_ERR_OUT_OF_RANGE;
    return NULL;
  }

  ret = grub_calloc (nmemb, sizeof (*ret));
  if (!ret)
  {
    grub_free (interface_info);
    return NULL;
  }

  id = 0;
  for (i = 0; i < interface_info->route_count ; i++)
  {
    char *gateway, *destination;
    grub_uint64_t u64_gateway[2];
    grub_uint64_t u64_destination[2];
    grub_efi_ip6_route_table_t *route_table = interface_info->route_table + i;
    grub_efi_net_interface_t *inf;
    char *interface_name = NULL;

    gateway = grub_efi_ip6_address_to_string (&route_table->gateway); //ip6地址到字符串
    destination = grub_efi_ip6_address_to_string (&route_table->destination); //ip6地址到字符串

    u64_gateway[0] = grub_get_unaligned64 (route_table->gateway.addr);
    u64_gateway[1] = grub_get_unaligned64 (route_table->gateway.addr + 8);
    u64_destination[0] = grub_get_unaligned64 (route_table->destination.addr);
    u64_destination[1] = grub_get_unaligned64 (route_table->destination.addr + 8);

    for (inf = dev->net_interfaces; inf; inf = inf->next)
      if (inf->prefer_ip6)
        interface_name = inf->name;

    if ((!u64_gateway[0] && !u64_gateway[1])
          && (u64_destination[0] || u64_destination[1]))
    {
      if (interface_name)
	    {
	      if ((grub_be_to_cpu64 (u64_destination[0]) == 0xfe80000000000000ULL)
              && (!u64_destination[1])
              && (route_table->prefix_length == 64))
//		ret[id++] = grub_xasprintf ("%s:link %s/%d %s", dev->card_name, destination, route_table->prefix_length, interface_name);
          grub_sprintf (ret[id++], "%s:link %s/%d %s", dev->card_name, destination, route_table->prefix_length, interface_name);
	      else
//		ret[id++] = grub_xasprintf ("%s:local %s/%d %s", dev->card_name, destination, route_table->prefix_length, interface_name);
          grub_sprintf (ret[id++], "%s:local %s/%d %s", dev->card_name, destination, route_table->prefix_length, interface_name);
	    }
    }
    else if ((u64_gateway[0] || u64_gateway[1])
          && (u64_destination[0] || u64_destination[1]))
//	ret[id++] = grub_xasprintf ("%s:gw %s/%d gw %s", dev->card_name, destination, route_table->prefix_length, gateway);
      grub_sprintf (ret[id++], "%s:gw %s/%d gw %s", dev->card_name, destination, route_table->prefix_length, gateway);
    else if ((u64_gateway[0] || u64_gateway[1])
          && (!u64_destination[0] && !u64_destination[1]))
//	ret[id++] = grub_xasprintf ("%s:default %s/%d gw %s", dev->card_name, destination, route_table->prefix_length, gateway);
      grub_sprintf (ret[id++], "%s:default %s/%d gw %s", dev->card_name, destination, route_table->prefix_length, gateway);

    grub_free (gateway);
    grub_free (destination);
  }

  ret[id] = NULL;
  grub_free (interface_info);
  return ret;
}

static grub_efi_net_interface_t *
grub_efi_ip6_interface_match (struct grub_efi_net_device *dev, grub_efi_net_ip_address_t *ip_address) //ip6接口匹配
{
  grub_efi_ip6_config_interface_info_t *interface_info;
  grub_efi_net_interface_t *inf;
  int i;
  grub_efi_ipv6_address_t *address = &ip_address->ip6;

  interface_info = efi_ip6_config_interface_info (dev->ip6_config);  //ip6配置接口信息

  if (!interface_info)
    return NULL;

  for (i = 0; i < (int)interface_info->route_count ; i++)
  {
    grub_uint64_t u64_addr[2];
    grub_uint64_t u64_subnet[2];
    grub_uint64_t u64_mask[2];

    grub_efi_ip6_route_table_t *route_table = interface_info->route_table + i;

    /* SKIP Default GATEWAY */
    if (route_table->prefix_length == 0)
      continue;

    u64_addr[0] = grub_get_unaligned64 (address);
    u64_addr[1] = grub_get_unaligned64 (address + 4);
    u64_subnet[0] = grub_get_unaligned64 (route_table->destination.addr);
    u64_subnet[1] = grub_get_unaligned64 (route_table->destination.addr + 8);
    u64_mask[0] = (route_table->prefix_length <= 64) ?
          0xffffffffffffffffULL << (64 - route_table->prefix_length) :
          0xffffffffffffffffULL;
    u64_mask[1] = (route_table->prefix_length <= 64) ?
          0 :
          0xffffffffffffffffULL << (128 - route_table->prefix_length);

    if (((u64_addr[0] & u64_mask[0]) == u64_subnet[0])
          && ((u64_addr[1] & u64_mask[1]) == u64_subnet[1]))
    {
      for (inf = dev->net_interfaces; inf; inf = inf->next)
        if (inf->prefer_ip6)
	      {
          grub_free (interface_info);
          return inf;
	      }
    }
  }

  grub_free (interface_info);
  return NULL;
}

static int
grub_efi_ip6_interface_set_manual_address (struct grub_efi_net_device *dev,
	    grub_efi_net_ip_manual_address_t *net_ip,
	    int with_subnet)  //ip6接口设置手动地址
{
  grub_efi_status_t status;
  grub_efi_ip6_config_manual_address_t *address = &net_ip->ip6;

  if (!with_subnet)
  {
    grub_efi_ip6_config_manual_address_t *manual_address =
    efi_ip6_config_manual_address (dev->ip6_config);  //ip6配置手动地址

    if (manual_address)
    {
      address->prefix_length = manual_address->prefix_length;
      grub_free (manual_address);
    }
    else
    {
      /* XXX: */
      address->prefix_length = 64;
    }
  }

  status = efi_call_4 (dev->ip6_config->set_data, dev->ip6_config,
		    GRUB_EFI_IP6_CONFIG_DATA_TYPE_MANUAL_ADDRESS,
		    sizeof(*address), address);

  if (status != GRUB_EFI_SUCCESS)
    return 0;

  return 1;
}

static int
grub_efi_ip6_interface_set_gateway (struct grub_efi_net_device *dev,
	      grub_efi_net_ip_address_t *address) //ip6接口设置网关
{
  grub_efi_status_t status;

  status = efi_call_4 (dev->ip6_config->set_data, dev->ip6_config,
		GRUB_EFI_IP6_CONFIG_DATA_TYPE_GATEWAY,
		sizeof (address->ip6), &address->ip6);

  if (status != GRUB_EFI_SUCCESS)
    return 0;
  return 1;
}

static int
grub_efi_ip6_interface_set_dns (struct grub_efi_net_device *dev,
	      grub_efi_net_ip_address_t *address) //ip6接口设置dns
{

  grub_efi_status_t status;

  status = efi_call_4 (dev->ip6_config->set_data, dev->ip6_config,
		GRUB_EFI_IP6_CONFIG_DATA_TYPE_DNSSERVER,
		sizeof (address->ip6), &address->ip6);

  if (status != GRUB_EFI_SUCCESS)
    return 0;
  return 1;
}

grub_efi_net_ip_config_t *efi_net_ip6_config = &(grub_efi_net_ip_config_t)
  {
    .get_hw_address = grub_efi_ip6_interface_hw_address,      //ip6接口硬件地址
    .get_address = grub_efi_ip6_interface_address,            //ip6接口地址
    .get_route_table = grub_efi_ip6_interface_route_table,    //ip6接口路由表
    .best_interface = grub_efi_ip6_interface_match,           //ip6接口匹配
    .set_address = grub_efi_ip6_interface_set_manual_address, //ip6接口设置手动地址
    .set_gateway = grub_efi_ip6_interface_set_gateway,        //ip6接口设置网关
    .set_dns = grub_efi_ip6_interface_set_dns                 //ip6接口设置dns
  };

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void pxe_init (void);
void
pxe_init (void)
{
//  debug = 3;
  char *device = 0;
  char *path = 0;

  grub_efi_net_find_cards (); //ok
	grub_efi_net_config_real (image->device_handle, &device, &path);	//实际网络配置  net/efi/net.c 
}

#endif	//ifdef FSYS_PXE
