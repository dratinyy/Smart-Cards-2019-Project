#undef CAC 
#include "CDCUtil.h"
#include "ASKCSC.h"
#include <windows.h>
#include <setupapi.h>
#include "wincsc.h"
#include <devguid.h>
#include <regstr.h>
#include "csc_def.h"    // CSC definition file
#include <tchar.h>

extern int		gCOMOpen;						// COM Opened ? TRUE:Yes  FALSE:No
extern BOOL PreserveCPUUsage;	// preserve CPU usage on host communication. Suitable for most operation. Unrecommended on some test suites

  typedef HKEY (__stdcall SETUPDIOPENDEVREGKEY)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, DWORD, DWORD, REGSAM);
  typedef BOOL (__stdcall SETUPDICLASSGUIDSFROMNAME)(LPCTSTR, LPGUID, DWORD, PDWORD);
  typedef BOOL (__stdcall SETUPDIDESTROYDEVICEINFOLIST)(HDEVINFO);
  typedef BOOL (__stdcall SETUPDIENUMDEVICEINFO)(HDEVINFO, DWORD, PSP_DEVINFO_DATA);
  typedef HDEVINFO (__stdcall SETUPDIGETCLASSDEVS)(LPGUID, LPCTSTR, HWND, DWORD);
  typedef BOOL (__stdcall SETUPDIGETDEVICEREGISTRYPROPERTY)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);


/****************************************************************/
BOOL WINAPI InternalUsePortNameIsPresent(LPSTR ComName, BOOL AskForAll)
/*****************************************************************
INPUTS
  ComName           Communication port Name (ex: "COM1", "LPT1" or "USB1") 

RETURNS
  TRUE              Function success
  FALSE             Function fail
*****************************************************************/
{
  BOOL bSuccess = FALSE;
  BOOL bMoreItems;
  int nIndex;
  SP_DEVINFO_DATA devInfo;
  HDEVINFO hDevInfoSet;

  if (AskForAll)
  {
	//Now create a "device information set" which is required to enumerate all the ports
	hDevInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_PORTS, NULL, NULL, DIGCF_PRESENT);
  }
  else
  {
	//Now create a "device information set" which is required to enumerate all the ports
	hDevInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_PORTS, "USB", NULL, DIGCF_PRESENT);
  }
  if (hDevInfoSet == INVALID_HANDLE_VALUE)
  {
    return FALSE;
  }

  //Finally do the enumeration
  bMoreItems = TRUE;
  nIndex = 0;
  while (bMoreItems)
  {
    //Enumerate the current device
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    bMoreItems = SetupDiEnumDeviceInfo(hDevInfoSet, nIndex, &devInfo);
    if (bMoreItems)
    {
      //Get the registry key which stores the ports settings
      HKEY hDeviceKey = SetupDiOpenDevRegKey (hDevInfoSet, &devInfo, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE);
      if (hDeviceKey)
      {
        //Read in the name of the port
        TCHAR pszPortName[256];
        DWORD dwSize = sizeof(pszPortName);
        DWORD dwType = 0;
  	    if ((RegQueryValueEx(hDeviceKey, _T("PortName"), NULL, &dwType, (LPBYTE)(pszPortName), &dwSize) == ERROR_SUCCESS) && (dwType == REG_SZ))
        {
          //If it looks like "COMX" then
          //add it to the array which will be returned
          size_t nLen = _tcslen(pszPortName);
          if (nLen > 3)
          {
            if (_tcsicmp(pszPortName, ComName+4) == 0)
            {
			  bSuccess=TRUE;
			  break;
            }
          }
        }
        //Close the key now that we are finished with it
        RegCloseKey(hDeviceKey);
      }
    }
    ++nIndex;
  }

  //Free up the "device information set" now that we are finished with it
  SetupDiDestroyDeviceInfoList(hDevInfoSet);

  //Return the success indicator
  return bSuccess;
}

/****************************************************************/
BOOL WINAPI CDCUtilPortNameIsPresent(LPSTR ComName)
/*****************************************************************
INPUTS
  ComName           Communication port Name (ex: "COM1", "LPT1" or "USB1") 

RETURNS
  TRUE              Function success
  FALSE             Function fail
*****************************************************************/
{
	return (InternalUsePortNameIsPresent(ComName, FALSE));
}

/****************************************************************/
BOOL WINAPI CDCUtilPortIsCDC(LPSTR ComName)
/*****************************************************************
INPUTS

RETURNS
  TRUE              Port is CDC driver based
  FALSE             Port is not CDC driver based
*****************************************************************/
{
	HDEVINFO hDevInfoSet;
	BOOL bMoreItems = TRUE;
	int nIndex = 0;
	SP_DEVINFO_DATA devInfo;
	BOOL bRetVal=FALSE;

	// retrieves a device information set that contains all devices of a specified class
	hDevInfoSet = SetupDiGetClassDevs(&GUID_DEVCLASS_PORTS, "USB", NULL, DIGCF_PRESENT);
	if (hDevInfoSet == INVALID_HANDLE_VALUE)
	{
		return (bRetVal);
	}

  while (bMoreItems)
  {
    //Enumerate the current device
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    bMoreItems = SetupDiEnumDeviceInfo(hDevInfoSet, nIndex, &devInfo);
    if (bMoreItems)
    {
      //Did we find a serial port for this device
      BOOL bAdded = FALSE;

      //Get the registry key which stores the ports settings
      HKEY hDeviceKey = SetupDiOpenDevRegKey(hDevInfoSet, &devInfo, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_QUERY_VALUE);
      if (hDeviceKey)
      {
        //Read in the name of the port
        TCHAR pszPortName[256];
        DWORD dwSize = sizeof(pszPortName);
        DWORD dwType = 0;
  	    if ((RegQueryValueEx(hDeviceKey, _T("PortName"), NULL, &dwType, (LPBYTE)(pszPortName), &dwSize) == ERROR_SUCCESS) && (dwType == REG_SZ))
        {
          //If it looks like "COMX" then
          //add it to the array which will be returned
          size_t nLen = _tcslen(pszPortName);
          if (nLen > 3)
          {
			if (_tcsicmp(pszPortName, ComName+4) == 0)
				bAdded = TRUE;
          }
        }
        //Close the key now that we are finished with it
        RegCloseKey(hDeviceKey);
      }

      //If the port was a serial port, then also try to get its friendly name
      if (bAdded)
      {
        TCHAR pszHardwareID[256];
        DWORD dwSize = sizeof(pszHardwareID);
        DWORD dwType = 0;

		memset (pszHardwareID, 0, 256);
		SetupDiGetDeviceRegistryProperty(hDevInfoSet, &devInfo, SPDRP_HARDWAREID,
		&dwType, (PBYTE)(pszHardwareID), 256, &dwSize);
		_strlwr_s (pszHardwareID,sizeof (pszHardwareID));
        if (strstr(pszHardwareID,"vid_1fd3") != NULL) 
		{
			bRetVal = TRUE;
			break;
		}
      }
    }
    ++nIndex;
  }

  //Free up the "device information set" now that we are finished with it
  SetupDiDestroyDeviceInfoList(hDevInfoSet);
  return (bRetVal);
}
/*****************************************************************
INPUTS

RETURNS
  TRUE              CDC Port is re-opened
  FALSE             CDC port is not re-opened
*****************************************************************/
BOOL WINAPI CDCUtilRecoverCDCPort (LPSTR ComName,DWORD dwDisconnectTimeout, DWORD dwReconnectTimeout)
{
	DWORD StartValue;
	DWORD TimeOut,vDt,vTo;

	// close COM port immediately
	CSC_Close();

	// wait for port disconnection on USB CDC device
	TimeOut=dwDisconnectTimeout;
	vDt=wCSC_GetTimer(0); // begin timer
	do
	{
		
		vTo=wCSC_GetTimer(vDt);

		StartValue = wCSC_GetTimer(0);
		while (wCSC_GetTimer(StartValue)<20)
		{
			if (PreserveCPUUsage)
				Sleep (1);
			wCSC_IdleLoop();
		}

		if (CDCUtilPortNameIsPresent(ComName)==FALSE)
			break;

		if (PreserveCPUUsage)
			Sleep (2);
	}
	while (vTo <= TimeOut);

	// wait for port re-connection on USB CDC device
	TimeOut=dwReconnectTimeout;
	vDt=wCSC_GetTimer(0); // begin timer
	do
	{
		vTo=wCSC_GetTimer(vDt);

		StartValue = wCSC_GetTimer(0);
		while (wCSC_GetTimer(StartValue)<20)
		{
			if (PreserveCPUUsage)
				Sleep (1);
			wCSC_IdleLoop();
		}

		if (PreserveCPUUsage)
			Sleep (1);
		
		if (CDCUtilPortNameIsPresent(ComName)==TRUE)
		{
			StartValue = wCSC_GetTimer(0);
			while (wCSC_GetTimer(StartValue)<200)
			{
				if (PreserveCPUUsage)
					Sleep (1);
				wCSC_IdleLoop();
			}
			break;
		}
	}
	while (vTo <= TimeOut);

	if (vTo <= TimeOut)
	{
		if (wCSC_OpenCOM(ComName) == TRUE)
		{
			StartValue = wCSC_GetTimer(0);
			while (wCSC_GetTimer(StartValue)<1500)
			{
				if (PreserveCPUUsage)
					Sleep (1);
				wCSC_IdleLoop();
			}

			if (PreserveCPUUsage)
				Sleep (1);

			gCOMOpen=TRUE;
			return (TRUE);
		}
	}
	return (FALSE);
}
