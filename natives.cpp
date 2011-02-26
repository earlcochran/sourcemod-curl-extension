
#include "extension.h"
#include "curlmanager.h"
#include <curl/curl.h>

#define SETUP_CURL_HANDLE()\
	cURLHandle *handle;\
	HandleError err;\
	HandleSecurity sec(pContext->GetIdentity(), myself_Identity);\
	if((err = handlesys->ReadHandle(params[1], g_cURLHandle, &sec, (void **)&handle)) != HandleError_None)\
	{\
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", params[1], err);\
	}

#define SETUP_CURL_WEBFORM()\
	WebForm *handle;\
	HandleError err;\
	HandleSecurity sec(pContext->GetIdentity(), myself_Identity);\
	if((err = handlesys->ReadHandle(params[1], g_WebForm, &sec, (void **)&handle)) != HandleError_None)\
	{\
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", params[1], err);\
	}

#define SETUP_CURL_SLIST()\
	cURL_slist_pack *handle;\
	HandleError err;\
	HandleSecurity sec(pContext->GetIdentity(), myself_Identity);\
	if((err = handlesys->ReadHandle(params[1], g_cURLSlist, &sec, (void **)&handle)) != HandleError_None)\
	{\
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", params[1], err);\
	}


static cell_t sm_curl_easy_init(IPluginContext *pContext, const cell_t *params)
{
	CURL *curl = curl_easy_init();
	if(curl == NULL)
	{
		return BAD_HANDLE;
	}

	cURLHandle *handle = new cURLHandle();
	handle->curl = curl;

	Handle_t hndl = handlesys->CreateHandle(g_cURLHandle, handle, pContext->GetIdentity(), myself_Identity, NULL);
	if(!hndl)
	{
		curl_easy_cleanup(handle->curl);
		delete handle;
		return BAD_HANDLE;
	}

	handle->hndl = hndl;
	return hndl;
}

static cell_t sm_curl_easy_setopt_string(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *buffer;
	pContext->LocalToString(params[3], &buffer);

	return g_cURLManager.AddcURLOptionString(handle, (CURLoption)params[2], buffer);
}

static cell_t sm_curl_easy_setopt_int(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	return g_cURLManager.AddcURLOptionInt(handle, (CURLoption)params[2], params[3]);
}

static cell_t sm_curl_easy_setopt_int_array(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	cell_t *array;
	cell_t array_size = params[3];
	pContext->LocalToPhysAddr(params[2], &array);

	bool valid = true;
	for(int i=0; i<array_size; i++)
	{
		cell_t c1_addr = params[2] + (i * sizeof(cell_t)) + array[i];
		cell_t *c1_r;
		pContext->LocalToPhysAddr(c1_addr, &c1_r);

		bool ret = g_cURLManager.AddcURLOptionInt(handle, (CURLoption)c1_r[0], c1_r[1]);
		if(!ret)
		{
			valid = false;
		}
	}
	return valid;
}

static cell_t sm_curl_easy_setopt_int64(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *buffer;
	pContext->LocalToString(params[3], &buffer);

	long long value = _atoi64(buffer);
	return g_cURLManager.AddcURLOptionInt64(handle, (CURLoption)params[2], value);
}

static cell_t sm_curl_easy_setopt_handle(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	return g_cURLManager.AddcURLOptionHandle(pContext, handle, &sec, (CURLoption)params[2], params[3]);
}

static cell_t sm_curl_easy_perform_thread(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	IPluginFunction *pFunction = pContext->GetFunctionById(params[2]);
	if(!pFunction)
	{
		return pContext->ThrowNativeError("Invalid function %x", params[2]);
	}
	
	handle->callback_Function = pFunction;
	cURLThread *thread = new cURLThread(handle);
	threader->MakeThread(thread);
	return 1;
}

static cell_t sm_curl_easy_perform(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	handle->running = true;
	return curl_easy_perform(handle->curl);
}

static cell_t sm_curl_easy_getinfo_string(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	int type = CURLINFO_TYPEMASK & (int)params[2];

	CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;
	switch(type)
	{
		case CURLINFO_STRING:
			char *string_buffer;
			code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &string_buffer);
			if(code == CURLE_OK)
			{
				pContext->StringToLocalUTF8(params[3], params[4], string_buffer, NULL);
			}
			break;
		case CURLINFO_SLIST:
			curl_slist engines; 
			code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &engines);
			if(code == CURLE_OK)
			{
				int i = 0;
			}
			break;
	}

	return code;
}

static cell_t sm_curl_easy_getinfo(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	int type = CURLINFO_TYPEMASK & (int)params[2];
	cell_t *addr;
	pContext->LocalToPhysAddr(params[3], &addr);
	CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;
	switch(type)
	{
		case CURLINFO_LONG:
			long long_buffer;
			code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &long_buffer);
			if(code == CURLE_OK)
			{
				*addr = (cell_t)long_buffer;
			}
			break;
		case CURLINFO_DOUBLE:
			double double_buffer;
			code = curl_easy_getinfo(handle->curl, (CURLINFO)params[2], &double_buffer);
			if(code == CURLE_OK)
			{
				*addr = sp_ftoc((float)double_buffer);
			}
			break;
	}
	return code;
}

static cell_t sm_curl_load_opt(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	g_cURLManager.LoadcURLOption(handle);
	return handle->lasterror;
}

static cell_t sm_curl_get_error_buffer(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();
	
	pContext->StringToLocalUTF8(params[2], params[3], handle->errorBuffer, NULL);
	return 1;
}

static cell_t sm_curl_easy_escape(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *url;
	pContext->LocalToString(params[2], &url);

	char *buffer = curl_easy_escape(handle->curl, url, strlen(url));
	if(buffer == NULL)
		return 0;

	pContext->StringToLocalUTF8(params[3], params[4], buffer, NULL);
	curl_free(buffer);
	return 1;
}

static cell_t sm_curl_easy_unescape(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_HANDLE();

	char *url;
	pContext->LocalToString(params[2], &url);

	int outlen;
	char *buffer = curl_easy_unescape(handle->curl, url, strlen(url), &outlen);
	if(buffer == NULL)
		return 0;

	pContext->StringToLocalUTF8(params[3], params[4], buffer, NULL);
	curl_free(buffer);
	return outlen;
}

static cell_t sm_curl_easy_strerror(IPluginContext *pContext, const cell_t *params)
{
	const char *error_code = curl_easy_strerror((CURLcode)params[1]);
	pContext->StringToLocalUTF8(params[2], params[3], error_code, NULL);
	return 1;
}

static cell_t sm_curl_version(IPluginContext *pContext, const cell_t *params)
{
	pContext->StringToLocalUTF8(params[1], params[2], curl_version(), NULL);
	return 1;
}

static cell_t sm_curl_features(IPluginContext *pContext, const cell_t *params)
{
	curl_version_info_data *vinfo = curl_version_info(CURLVERSION_NOW);
	return vinfo->features;
}

static cell_t sm_curl_OpenFile(IPluginContext *pContext, const cell_t *params)
{
	char *name, *mode;
	int err;
	if ((err=pContext->LocalToString(params[1], &name)) != SP_ERROR_NONE)
	{
		pContext->ThrowNativeErrorEx(err, NULL);
		return 0;
	}
	if ((err=pContext->LocalToString(params[2], &mode)) != SP_ERROR_NONE)
	{
		pContext->ThrowNativeErrorEx(err, NULL);
		return 0;
	}

	char realpath[PLATFORM_MAX_PATH];
	g_pSM->BuildPath(Path_Game, realpath, sizeof(realpath), "%s", name);

	FILE *pFile = fopen(realpath, mode);
	if(!pFile)
		return 0;
	

	return handlesys->CreateHandle(g_cURLFile, pFile, pContext->GetIdentity(), myself_Identity, NULL);
}

static cell_t sm_curl_httppost(IPluginContext *pContext, const cell_t *params)
{
	WebForm *handle = new WebForm();
	Handle_t hndl = handlesys->CreateHandle(g_WebForm, handle, pContext->GetIdentity(), myself_Identity, NULL);
	if(!hndl)
	{
		delete handle;
		return BAD_HANDLE;
	}
	return hndl;
}

/*
static cell_t sm_curl_formadd_string(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_WEBFORM();

	CURLformoption form_opt_1 = (CURLformoption)params[2];
	CURLformoption form_opt_2 = (CURLformoption)params[4];

	char *name;
	pContext->LocalToString(params[3], &name);

	char *data;
	pContext->LocalToString(params[5], &data);

	cell_t *addr;
	pContext->LocalToPhysAddr(params[6], &addr);

	CURLFORMcode lastError = CURL_FORMADD_OK;

	bool supported = handle->AddString(form_opt_1, name, form_opt_2, data, &lastError);

	*addr = (cell_t)lastError;

	return supported;
}
*/



static cell_t sm_curl_formadd(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_WEBFORM();

	return (cell_t)g_cURLManager.cURLFormAdd(pContext, params, handle);
}

static cell_t sm_curl_slist_append(IPluginContext *pContext, const cell_t *params)
{
	SETUP_CURL_SLIST();
	
	char *data;
	pContext->LocalToString(params[2], &data);

	handle->chunk = curl_slist_append(handle->chunk, data);
	return 1;
}

static cell_t sm_curl_slist(IPluginContext *pContext, const cell_t *params)
{
	cURL_slist_pack *handle = new cURL_slist_pack();
	Handle_t hndl = handlesys->CreateHandle(g_cURLSlist, handle, pContext->GetIdentity(), myself_Identity, NULL);
	if(!hndl)
	{
		delete handle;
		return BAD_HANDLE;
	}
	return hndl;
}

sp_nativeinfo_t g_cURLNatives[] = 
{ 
	{"curl_easy_init",				sm_curl_easy_init},
	{"curl_easy_setopt_string",		sm_curl_easy_setopt_string},
	{"curl_easy_setopt_int",		sm_curl_easy_setopt_int},
	{"curl_easy_setopt_int_array",	sm_curl_easy_setopt_int_array},
	{"curl_easy_setopt_int64",		sm_curl_easy_setopt_int64},
	{"curl_easy_setopt_handle",		sm_curl_easy_setopt_handle},
	{"curl_easy_perform_thread",	sm_curl_easy_perform_thread},
	{"curl_easy_perform",			sm_curl_easy_perform},
	{"curl_easy_getinfo_string",	sm_curl_easy_getinfo_string},
	{"curl_easy_getinfo",			sm_curl_easy_getinfo},
	{"curl_load_opt",				sm_curl_load_opt},
	{"curl_easy_escape",			sm_curl_easy_escape},
	{"curl_easy_unescape",			sm_curl_easy_unescape},
	{"curl_easy_strerror",			sm_curl_easy_strerror},
	{"curl_get_error_buffer",		sm_curl_get_error_buffer},
	{"curl_version",				sm_curl_version},
	{"curl_features",				sm_curl_features},
	{"curl_OpenFile",				sm_curl_OpenFile},

	{"curl_httppost",				sm_curl_httppost},
	{"curl_formadd",				sm_curl_formadd},

	{"curl_slist_append",			sm_curl_slist_append},
	{"curl_slist",					sm_curl_slist},
	{NULL,							NULL}
};