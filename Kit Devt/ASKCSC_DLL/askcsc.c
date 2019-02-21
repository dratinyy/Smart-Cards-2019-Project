/*****************************************************************
  DLL Main File CSC Functions  ( ASKCSC.C )

  WIN32 plateform for WINDOWS 95 & WINDOWS NT4

  Copyright (C)2002-1999 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Thierry J. - ASK
		   Jean-Luc M. - ASK
		   Serge M. -ASK
*****************************************************************/


/*****************************************************************
  HISTORY :
$Log:   W:/Lecteurs/DLL Askcsc/Sources/archives/askcsc.c-arc  $
 * 
 *    Rev 1.24   28 Sep 2005 18:09:18   gbrand
 * version change
 * 
 *    Rev 1.23   13 Jun 2005 15:21:10   gbrand
 * version change
 * 
 *    Rev 1.22   13 Jun 2005 15:04:06   gbrand
 * CSC CRC enable/disable
 * 
 *    Rev 1.21   13 Jun 2005 11:18:12   ccoure
 * MAJ
 * 
 *    Rev 1.20   07 Jun 2005 11:51:46   ccoure
 * MAJ CSC_DesactiveCRC()
 * 
 *    Rev 1.19   06 Jun 2005 14:59:42   ccoure
 * MAJ gestion ou non du CRC
 * 
 *    Rev 1.18   11 Feb 2005 11:49:20   gbrand
 * 691200 kb/s
 * 
 *    Rev 1.16   04 Jan 2005 11:28:20   gbrand
 * _
 * 
 *    Rev 1.15   Jan 28 2004 14:43:16   cjeann
 * * Ajout de la gestion des trames longues.
 * * Ajout de la classe CTx512x.
 * * Ajout de la commande 00_06_WriteSAMNumber.
 * 
 *    Rev 1.14   Oct 03 2002 11:43:28   blepin
 * voir change history
 * 
 *    Rev 1.13   Sep 16 2002 15:45:44   blepin
 * Mise à jour de la datation de la DLL
 * 
 *    Rev 1.12   Sep 16 2002 15:11:26   blepin
 * Voir liste des modification
 * 
 *    Rev 1.11   Feb 28 2002 17:25:36   smanig
 * modif ChgDLLSpeed
 * 
 *    Rev 1.10   Feb 08 2002 15:19:36   smanig
 * Tous fichiers modifiés pour ajout de la classe MIFARE
 * 
 *    Rev 1.8   May 11 2001 15:56:46   smanig
 * Changement du numéro de version
 * Initialisation de la vitesse de communication série par défaut
 * Fonction de changement de vitesse de communication
 * 
 *    Rev 1.7   Mar 30 2001 16:02:38   ccoure
 * Maj pour harmonisation du nom des commandes ticket
 * 
 *    Rev 1.6   Mar 28 2001 18:14:36   ccoure
 * 1- homogeneisation des noms des commandes tickets CTx_XXX()
 * 2- calcul et verif du certificat en classe générique

Ver 4.05.03.253		 03-09-10  BL   Add long frames management
Ver 4.05.03.218	Beta 03-08-06  BL   Add mono search mode
									Add CTx512x class
									Add CSC_WriteSAMNumber command
									Add CSC_TransparentCommand and CSC_TransparentCommandConfig
Ver 4.04.03.022		 03-01-22  BL
Ver 4.04.02.333 Beta 02-11-19  BL	Pass RFU param to CSC in iCTX_512B_List
Ver 4.04.02.332 Alpha02-11-18  BL   Wait delay=25ms in CSC_ResetCSC()
									Add global variables for CSC_SendReseive timeout param
									Add CSC_SetTimings modifying those variables
Ver 4.03.00.275		 02-10-02  BL	Correct CSC_SearchCardExt in askcsc.def
Ver 4.02.00.246		 02-09-04  BL	Add ISOCommandContact()
									Add sCARD_SearchExt
									Add CSC_SearchCardExt() using sCARD_SearchExt + search_mask
									Change VerifyPIN() for clear mode PIN presentation
									Add PINStatus()
									Add MIFARE_Select()
Ver 4.01.00.133	Beta 02-08-21  BL	Add first CTx512B functions : list, select, read, update, halt
Ver 4.00.02.036		 02-02-05  SM   Correction Warning Reset SAM et longueur min des réponses CTx 
Ver 3.11.01.260		 01-09-17  SM   Ajout des commandes de la classe MIFARE, RS485 et ChgSpeed
Ver 3.10.01.087		 01-03-28  CCV  harmonisation des commandes CTS (prevision CTM)
Ver 3.10.01.064		 01-03-05  CCV  Add CTS functions and modify CSC_SearchCard()
Ver 3.01.00.329	Beta 00-11-24  JLM  Add GEN 3XX Managment functions
Ver	2.01.00.132		 00-05-11  JLM  Check the reader version for GTML 
									compatibility
Ver	2.01.00.126		 00-05-05  JLM  Remove GTML_ChangeKey function
Ver 2.01.00.116      00-04-25  THJ  Add GTML class
Ver 1.93.00.061      00-03-01  THJ  Error CSC_ResetSAM ( vBuf[6] )
Ver 1.92.00.032      00-02-01  THJ  Error CSC_ISOCommand ( vBuf[4] )
Ver 1.91.99.322      99-11-12  THJ  Send ATR from ISSUER coupler
Ver 1.90.99.301      99-10-22  THJ  Correct Increase and Decrease Bug
Ver 1.80.99.257      99-09-09  THJ	Modify CSC_CardStopSearch
Ver 1.60.99.242      99-08-25  THJ	Special search
Ver 1.50.99.227      99-08-10  THJ	Parallel communication
Ver 1.07.99.142      99-05-18  THJ  First Commercial Version
Ver 1.06.99.130      99-05-06  THJ  Add the DEBUG LOG
Ver 1.05.99.102      99-04-09  THJ  Add CD97 function
Ver 1.01.99.087      99-03-25  THJ  Created
*****************************************************************/

/* Includes for constants, external variables and structures ****/
#include <windows.h>
#include <stdio.h>
#include <string.h>


#include "csc_def.h"    // CSC definition file

#include "wincsc.h"
#include "csc_ord.h"
#include <tchar.h>

#define __ASKCSC_IN__

#include "askcsc.h"
#include "CDCUtil.h"
#include "FTD2XX.H"
// PC/SC header files
#include <winscard.h>
#include <scarderr.h>

/* Internals Constants ******************************************/

#define CSC_VER				0x0407
#define CSC_LPVER			"ASK CSC Module Library Version 4.8.17.29"
#define MAX_BAUDRATE		691200

/* Internals Globals Variables **********************************/

int		gCOMOpen;						// COM Opened ? TRUE:Yes  FALSE:No
BOOL	bDirectIO;						// 1 : direct , 0 via driver
DWORD	gPlatform;						// Windows Version
BYTE	SearchMem;						// Search type save
DWORD	TimeoutSearch;					// Searching timeout
DWORD	TimerLAP;						// Timer Memory for TimeoutSearch
SCARDCONTEXT    hSC;
BYTE	bNbASKPCSCReader;
char	ASKPCSCReader[10][MAX_PATH];	// ASK PCSC readers names
char	swDEBUG;						// if =1 : Debug log actived
char	tdeb[2048];						// Log line ( DEBUG Version )
char	tdeb2[2048];					// Log line ( DEBUG Version )

char sExtendedComName[MAX_PATH];

extern BOOL	SlowFrame;	// temporary for slow CSC rx at high baud rate
extern BOOL	SoftReset;	// use soft reset, useful for GEN5XX USB CDC (avoid hard reset, loosing virtual com port)
extern BOOL PreserveCPUUsage;	// preserve CPU usage on host communication. Suitable for most operation. Unrecommended on some test suites
extern BOOL NoRetryOnHostTimeout;	// no retry on timeout host

extern char m_INIFileName[MAX_PATH];
extern BYTE bIOChannel;					// SERIAL, PARLLEL, USB or PCSC

/* Prototypes ***************************************************/
__declspec( dllexport ) void WINAPI CSC_Close(void);
__declspec( dllexport ) DWORD WINAPI CSC_SendReceive(DWORD Timeout,BYTE* BufIN,
													 DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT);
__declspec( dllexport ) BOOL WINAPI PortNameIsPresent(LPSTR ComName, BOOL All);

/****************************************************************/
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
/*****************************************************************
Main Entry Point of the Library ( CALLBACK Function )

INPUTS
  hinstDLL,		// handle to DLL module
  fdwReason,    // reason for calling function
  lpvReserved   // reserved.
*****************************************************************/
{
unsigned char path[256];
char Key[256]={"SOFTWARE\\ASK\\ASKCSC.DLL\\SETUP"};
HKEY hKey=NULL;
DWORD l=256;
long ln;
	// split frame : temporary for slow CSC serial rx
	char	Path[ MAX_PATH ];
	DWORD	PathLen;
	char	Dir[ _MAX_DIR ];
	char	Drive [ _MAX_DRIVE ];

// Global Data Initialization
	ComSpeed = (ulong) 115200;
	giCSCMode485 = FALSE;
	giCSCNumber485 = 0;
	giCRCNeeded = TRUE;
	gSAM_Prot[4] = SAM_PROT_HSP_INNOVATRON;				
	gCurrentSAM = SAM_SLOT_1;
	FuncTimeout = 2000;
	SearchTimeout = 3000;


	PathLen = _MAX_PATH;
	GetModuleFileName ((GetModuleHandle (NULL)),Path,PathLen);
	_splitpath_s( Path, Drive,sizeof(Drive), Dir,sizeof(Dir), NULL,0, NULL,0 );
	strcpy_s(m_INIFileName,sizeof(m_INIFileName),Drive);
	strcat_s(m_INIFileName,sizeof(m_INIFileName),Dir);
	strcat_s(m_INIFileName,sizeof(m_INIFileName),"AskCsc.ini");
	SlowFrame = GetPrivateProfileInt ("Configuration","SlowFrame",0,m_INIFileName);
	SoftReset = GetPrivateProfileInt ("Configuration","SoftReset",0,m_INIFileName);
	PreserveCPUUsage = GetPrivateProfileInt ("Configuration","PreserveCPUUsage",0,m_INIFileName);
	NoRetryOnHostTimeout = GetPrivateProfileInt ("Configuration","NoRetryOnHostTimeout",0,m_INIFileName);

switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		gCOMOpen=FALSE;            // COM Close
		// Find the windows version
		gPlatform=wCSC_GetWinVersion();
		// if the windows version is not WIN95 or WINNT4 -> STOP DLL
		if(gPlatform==wCSC_VER_ERROR)return FALSE;
		if (gPlatform == wCSC_VER_WIN95)
			bDirectIO = 1;

		// read DEBUG switch in Registry Key database
		path[0]=0;
		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,Key,0,KEY_READ,&hKey)==ERROR_SUCCESS)
			{
			ln=RegQueryValueEx(hKey,"DEBUG Log",NULL,NULL,(LPBYTE)path,&l);
			RegCloseKey(hKey);
			if(ln!=ERROR_SUCCESS)break;
			}
		swDEBUG= *(char *)path;

		// write DEBUG switch in Registry Key database
		ln=swDEBUG;
		if(RegCreateKey(HKEY_LOCAL_MACHINE,Key,&hKey)!=ERROR_SUCCESS)break;
		RegSetValueEx(hKey,"DEBUG Log",0,REG_DWORD,(LPBYTE)&ln,4);
		RegCloseKey(hKey);

		if(swDEBUG==1){ /* DEBUG */
		GetModuleFileName(NULL,path,sizeof(path));
		sprintf_s(tdeb,sizeof(tdeb),"New Application - %s -----",path);
		wCSC_DebugLog(tdeb,0);
		} /* LOG DEBUG */
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		if(gCOMOpen)CSC_Close();
		break;
	case DLL_THREAD_DETACH:
		break;
	}
return TRUE;
}

/****************************************************************/
__declspec( dllexport ) DWORD CSC_GetUSBNumDevices (DWORD *NumDevices)
/****************************************************************
Get number of CSC USB devices
*****************************************************************/
{
	if (FT_CreateDeviceInfoList (NumDevices) == FT_OK)
		return (RCSC_Ok);
	else
		return (RCSC_Fail);
};

/****************************************************************/
__declspec( dllexport ) DWORD CSC_GetPCSCNumDevices (DWORD *NumDevices)
/****************************************************************
Get number of CSC PCSC devices
*****************************************************************/
{
	DWORD           cch = SCARD_AUTOALLOCATE;
	LONG            lReturn;
	LPTSTR          pmszReaders = NULL;
	LPTSTR          pReader;

	bNbASKPCSCReader=0;

	// Establish the context.
	if (hSC == (SCARDCONTEXT )NULL)
	{
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL,&hSC);
		if ( SCARD_S_SUCCESS != lReturn )
			return (RCSC_Fail);
	}

	// Retrieve the list the readers.
	lReturn = SCardListReaders(hSC,	NULL,(LPTSTR)&pmszReaders,&cch );
	if ( SCARD_S_SUCCESS != lReturn )
		return (RCSC_Fail);
	
	// A double-null terminates the list of values.
	pReader = pmszReaders;
	while ( '\0' != *pReader )
	{
		if (strstr (pReader,"ASK"))
			strcpy_s (ASKPCSCReader[bNbASKPCSCReader++],sizeof(ASKPCSCReader[bNbASKPCSCReader++]),pReader);
		pReader = pReader + strlen(pReader) + 1;
	}

	// Free the memory.
	lReturn = SCardFreeMemory( hSC,	pmszReaders );
	if ( SCARD_S_SUCCESS != lReturn )
		return (RCSC_Fail);

	*NumDevices = bNbASKPCSCReader;
	return (RCSC_Ok);
};

/****************************************************************/
__declspec( dllexport ) DWORD CSC_GetPCSCDeviceName (DWORD DeviceNumber,char *sName)
/****************************************************************
Get the name of DeviceNumber PCSC ASK reader
*****************************************************************/
{
	if ((DeviceNumber<=bNbASKPCSCReader) && (DeviceNumber)) 
	{
		strcpy_s (sName,MAX_PATH, ASKPCSCReader[DeviceNumber-1]);
		return (RCSC_Ok);
	}
	else
		return (RCSC_Fail);
}


/****************************************************************/
__declspec( dllexport ) void WINAPI CSC_Close(void)
/*****************************************************************
Close the PC communication port
*****************************************************************/
{
// Close the PC communication port
wCSC_CloseCOM();
gCOMOpen=FALSE;

if(swDEBUG==1){ /* DEBUG */
wCSC_DebugLog("CSC_Close( )",RCSC_Ok);
} /* LOG DEBUG */
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_Open(LPSTR ComName)
/*****************************************************************
Open the PC communication port

INPUTS
  ComName   : Communication port Name (ex: "COM1", "LPT1" or "USB1") 

RETURNS
	RCSC_Ok
	RCSC_OpenCOMError
*****************************************************************/
{
if ((strstr (ComName,"COM"))  || strstr (ComName,"LPT"))
	sprintf_s (sExtendedComName,MAX_PATH,"\\\\.\\%s",ComName);
else
	strcpy_s (sExtendedComName,MAX_PATH,ComName);

	
if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_Open( )");
} /* LOG DEBUG */

if(gCOMOpen)CSC_Close();

if(ComName==NULL)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_Open(%s)",ComName);
} /* LOG DEBUG */


if(wCSC_OpenCOM(sExtendedComName)==FALSE)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

gCOMOpen=TRUE;
return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_VersionDLL(LPSTR Version)
/*****************************************************************
Return the DLL version

OUTPUTS
  Version	: The text DLL version

RETURNS
  The DLL version : release
*****************************************************************/
{
// copy the value to the external buffer ( zero terminal string )
if(Version!=NULL)
	strcpy_s(Version,sizeof(CSC_LPVER),CSC_LPVER);
return CSC_VER;
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_DesactiveCRC(BYTE Type, LPSTR Version)
/*****************************************************************
Desactive the Compute and Set of the CRC 

INPUTS
	Type     : 0xFF (desactive)/ else (activate)

OUTPUTS
	Version	: The text CSC version

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];					// local temp buffer
DWORD vLen;						// The answer frame size
unsigned char IndicCRC;

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_DesactiveCRC");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// old value
IndicCRC=giCRCNeeded ;

if(Type==0xFF){
	// CRC is not needed
	giCRCNeeded = FALSE;
}
else
	giCRCNeeded = TRUE;

// prepares the command buffer for a SoftwareVersion command
iCSC_SoftwareVersion();
/*
if (IndicCRC == TRUE){
	// Compute and Set the CRC at the end of the buffer
	giCSCTrame[giCSCTrameLn]=0x00;
	giCSCTrameLn++;
	icsc_SetCRC();
}
*/

// Send a command frame to the CSC, and waits for the answer
vRet=CSC_SendReceive(1000,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the external buffer ( zero terminal string )
if(Version!=NULL)
	{
		vBuf[vLen]=0x00;
		strcpy_s(Version,sizeof(vBuf),&vBuf[4]);

		if(swDEBUG==1) // DEBUG 
		{
			sprintf_s(tdeb,sizeof(tdeb),"CSC_DesactiveCRC( %s )",Version);
		} // LOG DEBUG 

	}

return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_VersionCSC(LPSTR Version)
/*****************************************************************
Return the CSC version

OUTPUTS
	Version	: The text CSC version

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size
BYTE CSCName [8] = {0x43,0x53,0x43,0x2D,0x41,0x53,0x4B,0x00};
BYTE StrCSCName[8];
int IntVersion=0,IntRelease=0;

StrCSCName[7]=0;// String CSC Name


if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_VersionCSC");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a SoftwareVersion command
iCSC_SoftwareVersion();

// Send a command frame to the CSC, and waits for the answer
vRet=CSC_SendReceive(1000,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);



// copy the local buffer to the external buffer ( zero terminal string )
if(Version!=NULL)
	{
		strcpy_s(Version,sizeof(vBuf),&vBuf[4]);

		if(swDEBUG==1) /* DEBUG */
		{
			sprintf_s(tdeb,sizeof(tdeb),"CSC_VersionCSC( %s )",Version);
		} /* LOG DEBUG */

	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

 
/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ResetCSC(void)
/*****************************************************************
Initialize the CSC module

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_DataWrong
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
int vLoop;
BYTE vBuf[255];
DWORD ptRepLen[1];
DWORD vRet;
 
if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ResetCSC");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

if (bIOChannel == STUB)
{
	// send the command RESET .
	giCSCTrame[0]=CSC_CMD_EXEC;				// EXEC Command
	giCSCTrame[1]=0x02;				        // Length
	giCSCTrame[2]=CSC_CLA_SYSTEM;           // System class
	giCSCTrame[3]=0x00;						// CSC_CMD_RES;
	giCSCTrame[4]=0x00;                     // End of Command
	giCSCTrameLn=5; 
	// Compute and Set the CRC at the end of the buffer
	icsc_SetCRC();
	giCSCStatus=iCSC_OK;
	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(1000,giCSCTrame,giCSCTrameLn,vBuf,ptRepLen);
	return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
}
if (bIOChannel == PCSC)
{
	SetPCSCCommandTimeout (3000);
	giCSCTrame[0]=CSC_CMD_RES;
	if ((wCSC_RxTxPCSC (giCSCTrame,1,vBuf,&vRet)) && (vBuf[0]==CSC_STA_RES))
		return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
	else
		return wCSC_DebugLog(tdeb,RCSC_Ok);
}
else if (bIOChannel == CCID)
{
	DWORD vDt;
//	SetPCSCCommandTimeout (3000);
	giCSCTrame[0]=CSC_CMD_EXEC;
	giCSCTrame[1]=0x02;
	giCSCTrame[2]=CSC_CLA_SYSTEM;
	giCSCTrame[3]=CSC_SYS_RESET;
	giCSCTrame[4]=0;

	giCSCTrameLn=5; 
// Compute and Set the CRC at the end of the buffer
	icsc_SetCRC();
	giCSCStatus=iCSC_OK;
	
	wCSC_RxTxCCID (giCSCTrame,giCSCTrameLn,vBuf,&vRet);
	// CCID reader is lost whatever the response is
	wCSC_CloseCOM();

	// Let minimum time for the reader to get up again
	vDt=wCSC_GetTimer(0);
	while (wCSC_GetTimer(vDt)<=3500)
	{
		wCSC_IdleLoop ();
	}
	
	if (wCSC_OpenCOM(sExtendedComName)==TRUE)
		return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
	else
		return wCSC_DebugLog(tdeb,RCSC_Ok);
}

// discard all characters from the output or input buffer.
wCSC_FlushCOM();


giCRCNeeded = TRUE;

	if (giCSCMode485 == TRUE)
	{
		// send the command CSC_CMD_RES.
		giCSCTrame[0]=CSC_CMD_EXEC;				// EXEC Command
		giCSCTrame[1]=0x02;				        // Length
		giCSCTrame[2]=CSC_CLA_SYSTEM;           // System class
		giCSCTrame[3]=0x00;						// CSC_CMD_RES;
		giCSCTrame[4]=0x00;                     // End of Command
		giCSCTrameLn=5; 
		// Compute and Set the CRC at the end of the buffer
		icsc_SetCRC();
		giCSCStatus=iCSC_OK;

		// Send a command frame to the CSC, and waits 2 seconds for the answer
		vRet=CSC_SendReceive(5000,giCSCTrame,giCSCTrameLn,vBuf,ptRepLen);
	
		if(vRet==RCSC_Ok) 	return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
	}
	else
	{
		if (CDCUtilPortIsCDC (sExtendedComName))
		{
			if (SoftReset)
			{
				CSC_VersionCSC(NULL); // first command allowed
				// send the command soft RESET				
				giCSCTrame[0]=CSC_CMD_EXEC;				// EXEC Command
				giCSCTrame[1]=0x02;				        // Length
				giCSCTrame[2]=CSC_CLA_DOWNLOAD;         // System class
				giCSCTrame[3]=0x0B;						// Soft Reset
				giCSCTrame[4]=0x00;                     // End of Command
				giCSCTrameLn=5; 
				// Compute and Set the CRC at the end of the buffer
				icsc_SetCRC();
				giCSCStatus=iCSC_OK;
				// Send a command frame to the CSC, and waits 2 seconds for the answer
				vRet=CSC_SendReceive(2000,giCSCTrame,giCSCTrameLn,vBuf,ptRepLen);
				return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
			}
			else
			{
				// send the command CSC_CMD_RES.
				giCSCTrame[0]=CSC_CMD_RES;
				wCSC_SendCOM(giCSCTrame,1);
				
				if (CDCUtilRecoverCDCPort (sExtendedComName,2000,3000) == TRUE)
				{
					if((wCSC_ReceiveCOM(5000,1,vBuf)==1) && (vBuf[0] == CSC_STA_RES))
						return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
				}
			}
		} 
		else	// port is not CDC based
		{
			// do it twice, in case the first reset fails
			for(vLoop=0;vLoop<2;vLoop++)
			{
				// send the command CSC_CMD_RES.
				giCSCTrame[0]=CSC_CMD_RES;
				if(wCSC_SendCOM(giCSCTrame,1)==FALSE)continue;

				// receive 1 character from CSC
				while (1)
				{
					if(wCSC_ReceiveCOM(3000,1,vBuf)!=1)
						break;
					if (vBuf[0] == CSC_STA_RES)
						break;
				}
		
				// result data check
				if(vBuf[0]!=CSC_STA_RES)
						return wCSC_DebugLog(tdeb,RCSC_DataWrong);
				return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
			}
		}
	}

return wCSC_DebugLog(tdeb,RCSC_Fail);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_DownloadStartCSC(void)
/*****************************************************************
Initialize the CSC Download transfert

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_DataWrong
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
BYTE vBuf[255];
DWORD vRet;
 
if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_DownloadStartCSC");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)
	return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

giCRCNeeded = TRUE;

// send the command DOwnload.
giCSCTrame[0]=CSC_CMD_EXEC;
giCSCTrame[1]=0x02;				        // Length
giCSCTrame[2]=CSC_CLA_DOWNLOAD;         // Download class
giCSCTrame[3]=CSC_DOW_START_DOWNLOAD;	// CSC_CMD_Erase;
giCSCTrame[4]=0x00;                     // End of Command
giCSCTrameLn=5; 
// Compute and Set the CRC at the end of the buffer
icsc_SetCRC();
giCSCStatus=iCSC_OK;

if (bIOChannel == PCSC)
{
	SetPCSCCommandTimeout (10000);
	if ((wCSC_RxTxPCSC (giCSCTrame,giCSCTrameLn,vBuf,&vRet)== -1) || (vBuf[4]!=0))
		return wCSC_DebugLog(tdeb,RCSC_Fail);
	else
		return wCSC_DebugLog(tdeb,RCSC_Ok);
} 
else if (bIOChannel == CCID)
{
	//The Download Start is not acceptable in CCID mode has the bootloader is not ccid compliant
	//SetPCSCCommandTimeout (10000);
	//if ((wCSC_RxTxCCID (giCSCTrame,giCSCTrameLn,vBuf,&vRet)== -1) || (vBuf[4]!=0))
		return wCSC_DebugLog(tdeb,RCSC_Fail);
	//else
	//	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

if (CDCUtilPortIsCDC (sExtendedComName))
{		
	wCSC_SendCOM(giCSCTrame,giCSCTrameLn);
	if (CDCUtilRecoverCDCPort (sExtendedComName,3000,3000)== TRUE)
	{
		if ((wCSC_ReceiveCOM(10000,5,vBuf) == -1) || (vBuf[4] !=0))
			return wCSC_DebugLog(tdeb,RCSC_Fail);
	}
}
else
{
	wCSC_SendCOM(giCSCTrame,giCSCTrameLn);
	// receive response from CSC
	if ((wCSC_ReceiveCOM(10000,5,vBuf) == -1) || (vBuf[4] !=0))
		return wCSC_DebugLog(tdeb,RCSC_Fail);
}
Sleep (2);
// discard all characters from the output or input buffer.
wCSC_FlushCOM();

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_DownloadStopCSC(void)
/*****************************************************************
Conclude the CSC download transfert

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_DataWrong
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
BYTE vBuf[255];
DWORD vRet;
 
if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_DownloadStopCSC");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)
	return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

giCRCNeeded = TRUE;

// send the command DOwnload.
giCSCTrame[0]=CSC_CMD_EXEC;
giCSCTrame[1]=0x02;				        // Length
giCSCTrame[2]=CSC_CLA_DOWNLOAD;         // Download class
giCSCTrame[3]=CSC_DOW_STOP_DOWNLOAD;	// CSC_CMD_STOP;
giCSCTrame[4]=0x00;                     // End of Command
giCSCTrameLn=5; 
// Compute and Set the CRC at the end of the buffer
icsc_SetCRC();
giCSCStatus=iCSC_OK;

if (bIOChannel == PCSC)
{
	SetPCSCCommandTimeout (3000);
	if ((wCSC_RxTxPCSC (giCSCTrame,giCSCTrameLn,vBuf,&vRet)== -1) || (vBuf[4]!=0))
		return wCSC_DebugLog(tdeb,RCSC_Fail);
	else
		return wCSC_DebugLog(tdeb,RCSC_Ok);
}
else if (bIOChannel == CCID)
{
	//SetPCSCCommandTimeout (3000);
	if ((wCSC_RxTxCCID (giCSCTrame,giCSCTrameLn,vBuf,&vRet)== -1) || (vBuf[4]!=0))
		return wCSC_DebugLog(tdeb,RCSC_Fail);
	else
		return wCSC_DebugLog(tdeb,RCSC_Ok);
}


// discard all characters from the output or input buffer.
wCSC_FlushCOM();

if (CDCUtilPortIsCDC (sExtendedComName))
{		
	wCSC_SendCOM(giCSCTrame,giCSCTrameLn);
	if (CDCUtilRecoverCDCPort (sExtendedComName,2000,3000)== TRUE)
	{
		// on ne récupère pas la réponse de DownloadStop car on attend la déconnexion, donc
		// on pert cette trame
		if((wCSC_ReceiveCOM(5000,1,vBuf)== -1) || (vBuf[0] != CSC_STA_RES))
			return wCSC_DebugLog(tdeb,RCSC_Fail);
	}
}
else
{
	wCSC_SendCOM(giCSCTrame,giCSCTrameLn);
	// receive response from CSC
	if ((wCSC_ReceiveCOM(3000,5,vBuf) == -1) ||(vBuf[4]!=0))
		return wCSC_DebugLog(tdeb,RCSC_Fail);
}
return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SearchCSC(void)
/*****************************************************************
Search the CSC module, Open the PC communication port and the
CSC is reseted.

RETURNS
	RCSC_Ok
	RCSC_CSCNotFound
*****************************************************************/
{
int i;
BYTE tx[25];

unsigned char path[256];
char Key[256]={"SOFTWARE\\ASK\\ASKCSC.DLL\\SETUP"};
HKEY hKey=NULL;
DWORD l=256;
long ln;
DWORD NumUSBDevices=0;
DWORD NumPCSCDevices=0;

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCSC");
} /* LOG DEBUG */

CSC_GetPCSCNumDevices (&NumPCSCDevices);

// read the last connected port in Registry Key database
path[0]=0;
tx[0]=0;
if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,Key,0,KEY_READ,&hKey)==ERROR_SUCCESS)
	{
	ln=RegQueryValueEx(hKey,"PORT",NULL,NULL,(LPBYTE)path,&l);
	RegCloseKey(hKey);
	if(ln==ERROR_SUCCESS)	memcpy(tx,path,25);
	}

if(tx[0])
	{
	wCSC_IdleLoop();
	if(CSC_Open(tx)==RCSC_Ok)
		{
		// if Open comm port OK -> try to reset the CSC
		wCSC_IdleLoop();
		if(CSC_ResetCSC()==RCSC_Ok)
			{
			if(swDEBUG==1){ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCSC -> %s",tx);
			} /* LOG DEBUG */
			return wCSC_DebugLog(tdeb,RCSC_Ok);
			}
		else CSC_Close();
		}
	}

	if (CSC_GetUSBNumDevices (&NumUSBDevices) != RCSC_Ok)
		NumUSBDevices = 0;

	if (CSC_GetPCSCNumDevices (&NumPCSCDevices) != RCSC_Ok)
		NumPCSCDevices = 0;

	// try on PC/SC
	for(i=1;i<=(signed)NumPCSCDevices;i++)  
	{
		wsprintf(tx,ASKPCSCReader[i-1]);
		wCSC_IdleLoop();
		if(CSC_Open(tx)==RCSC_Ok)
		{
			// if Open comm port OK -> try to reset the CSC
			wCSC_IdleLoop();
			if(CSC_ResetCSC()==RCSC_Ok)
			{
				if(swDEBUG==1)
					sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCSC -> %s",tx);

				// write the conneted port in Registry Key database
				if(RegCreateKey(HKEY_LOCAL_MACHINE,Key,&hKey)==ERROR_SUCCESS)
				{
					RegSetValueEx(hKey,"PORT",0,REG_SZ,(LPBYTE)tx,(DWORD)strlen(tx)+1);
					RegCloseKey(hKey);
				}
				return wCSC_DebugLog(tdeb,RCSC_Ok);
			}
			// the CSC is not on this port -> close and continue
			// with another port
			CSC_Close();
		}
	}

	// try on USB
	for(i=1;i<=(signed)NumUSBDevices;i++)
	{
		wsprintf(tx,"USB%d",i);
		wCSC_IdleLoop();
		if(CSC_Open(tx)==RCSC_Ok)
		{
			// if Open comm port OK -> try to reset the CSC
			wCSC_IdleLoop();
			if(CSC_ResetCSC()==RCSC_Ok)
			{
				if(swDEBUG==1)
					sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCSC -> %s",tx);

				// write the conneted port in Registry Key database
				if(RegCreateKey(HKEY_LOCAL_MACHINE,Key,&hKey)==ERROR_SUCCESS)
				{
					RegSetValueEx(hKey,"PORT",0,REG_SZ,(LPBYTE)tx,(DWORD)strlen(tx)+1);
					RegCloseKey(hKey);
				}
				return wCSC_DebugLog(tdeb,RCSC_Ok);
			}
			// the CSC is not on this port -> close and continue
			// with another port
			CSC_Close();
		}
	}

	// try on serial
	for(i=1;i<=32;i++)
	{
		wsprintf(tx,"COM%d",i);
		if (!PortNameIsPresent (tx,TRUE))
			continue;
		wCSC_IdleLoop();
		if(CSC_Open(tx)==RCSC_Ok)
		{
			// if Open comm port OK -> try to reset the CSC
			wCSC_IdleLoop();
			if(CSC_ResetCSC()==RCSC_Ok)
			{
				if(swDEBUG==1)
					sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCSC -> %s",tx);

				// write the conneted port in Registry Key database
				if(RegCreateKey(HKEY_LOCAL_MACHINE,Key,&hKey)==ERROR_SUCCESS)
				{
					RegSetValueEx(hKey,"PORT",0,REG_SZ,(LPBYTE)tx,(DWORD)strlen(tx)+1);
					RegCloseKey(hKey);
				}
				return wCSC_DebugLog(tdeb,RCSC_Ok);
			}

			// the CSC is not on this port -> close and continue
			// with another port
			CSC_Close();
		}
	}

	// try on parallel
	for(i=1;i<=3;i++)
	{
		wsprintf(tx,"LPT%d",i); // Parallel mode
		wCSC_IdleLoop();
		if(CSC_Open(tx)==RCSC_Ok)
		{
			// if Open comm port OK -> try to reset the CSC
			wCSC_IdleLoop();
			if(CSC_ResetCSC()==RCSC_Ok)
			{
				if(swDEBUG==1)
					sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCSC -> %s",tx);

				// write the conneted port in Registry Key database
				if(RegCreateKey(HKEY_LOCAL_MACHINE,Key,&hKey)==ERROR_SUCCESS)
				{
					RegSetValueEx(hKey,"PORT",0,REG_SZ,(LPBYTE)tx,(DWORD)strlen(tx)+1);
					RegCloseKey(hKey);
				}
				return wCSC_DebugLog(tdeb,RCSC_Ok);
			}
			// the CSC is not on this port -> close and continue
			// with another port
			CSC_Close();
		}
	}

	return wCSC_DebugLog(tdeb,RCSC_CSCNotFound);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SendReceive
		(DWORD Timeout,BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT)
/*****************************************************************
Send a command frame to the CSC, and waits for the answer

INPUTS
	Timeout	: The command timeout value in milliseconds
	BufIN	: Command frame to send to the CSC
			  The frame is : <CMD><LEN><CLASS><IDENT><DATA><CRC>
	LnIN	: The frame size
	

OUTPUT
	BufOUT	: Contains the CSC answer frame
			  The frame is :<STA><LEN><CLASS><IDENT><DATA><CRC>
	LnOUT	: The answer frame size

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_DataWrong
	RCSC_CheckSum
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from wCSC_ReceiveCOM
//BYTE vBuf[255];			// local temp buffer
BYTE vBuf[600];			// local temp buffer (increased for long frames)
INT NbTry=1;

// CSC_Open no executed
if(!gCOMOpen)return RCSC_OpenCOMError;

if(BufIN==NULL)return RCSC_Fail;
if(BufOUT==NULL)return RCSC_Fail;
if(LnOUT==NULL)return RCSC_Fail;

if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb2,sizeof(tdeb2),"CSC_SendReceive(%s , %d...)",wCSC_BTS(BufIN,LnIN),LnIN);
} /* LOG DEBUG */


if (bIOChannel == STUB)
{
	unsigned char status;
	unsigned short int DataOutLength=0; 

	// If the function address is valid, call the function.
    if (NULL != ProcCallAppliFunc) 
    {
		status = (ProcCallAppliFunc) (BufIN[2], BufIN[3], &BufIN[4], &BufOUT[4], &DataOutLength, BufIN[1]);
	}

	*LnOUT = (DataOutLength)+5;
	BufOUT[0]= 0x01;
	BufOUT[1]= DataOutLength+5;
	BufOUT[2]= BufIN[2];
	BufOUT[3]= BufIN[3];
	vRet=RCSC_Ok;			    	
	return RCSC_Ok;
}

while (NbTry <= 2)	// 2 try to get THE ANSWER (no re-send): needed for serial communication due to UART overrun
					// if PC is busy by high priority process (like USB device plugin)
{
if (bIOChannel == PCSC)
{
	SetPCSCCommandTimeout (Timeout);
	vRet = wCSC_RxTxPCSC (BufIN,LnIN,vBuf,LnOUT);
}
else if (bIOChannel == CCID)
{
//	SetPCSCCommandTimeout (Timeout);
	vRet = wCSC_RxTxCCID (BufIN,LnIN,vBuf,LnOUT);
}
else
{
	// discard all characters from the output or input buffer. Disabled because it slows down
	//wCSC_FlushCOM();
	if (NbTry == 2)
	{
		if (giCRCNeeded)
		{
			if(wCSC_SendCOM("\x80\x02\x55\xAA\x00\x85\x94",7)==FALSE)return RCSC_TXError;
		}
		else
		{
			if(wCSC_SendCOM("\x80\x02\x55\xAA",4)==FALSE)return RCSC_TXError;
		}
	}
	else
	{
		if(wCSC_SendCOM(BufIN,LnIN)==FALSE)return RCSC_TXError;
	}

	// Desactive the CRC
	if ((BufIN[2] == 0x01) && (BufIN[3] == 0x01) && (BufIN[4] == 0xFF))	giCRCNeeded=0;
	// Active the CRC
	if ((BufIN[2] == 0x01) && (BufIN[3] == 0x01) && (BufIN[4] == 0x00))	giCRCNeeded=1;

	// wait 'timeout' milliseconds the answer
	vRet=wCSC_ReceiveCOM(Timeout,600,vBuf);	// 255->270->600 for long frames
	if(!vRet)return RCSC_NoAnswer;
	if(vRet==-1)
	{		
		if (NoRetryOnHostTimeout == 0)
		{
			if ((NbTry == 1) && (bIOChannel == SERIAL))
			{	
				NbTry++;
				continue;
			}
			else
				return RCSC_Timeout;
		}
		else
		{
			NbTry=3;
			return RCSC_Timeout;
		}
	}
}

if(vRet!=1)
{
		if (giCSCMode485 == TRUE)
		{
			/*$$$$$$$$$$$$$$$$$$$$$$$$$$$*/
			// error protocol test
			if(vBuf[1]&~(CSC_STA_STOP|CSC_STA_RES|CSC_STA_ANS))
									return RCSC_DataWrong;
			if((BufIN[2]!=0xFF)&&((BufIN[1]&0x40)== 0))
			{
				if((vBuf[2]!=0xFF)&&((vBuf[2]&0x40)== 0))
				{
					if((vBuf[3]!=BufIN[3])||(vBuf[4]!=BufIN[4]))
									return RCSC_DataWrong;
				}
				else
					if((vBuf[4]!=BufIN[3])||(vBuf[5]!=BufIN[4]))
									return RCSC_DataWrong;
			}
			else
			{
				if((vBuf[2]!=0xFF) && ((vBuf[1]&0x40)== 0))
				{
					if((vBuf[3]!=BufIN[4])||(vBuf[4]!=BufIN[5]))
									return RCSC_DataWrong;
				}
				else
					if((vBuf[4]!=BufIN[4])||(vBuf[5]!=BufIN[5]))
									return RCSC_DataWrong;
			}
		}
		else
		{

			/*$$$$$$$$$$$$$$$$$$$$$$$*/
			// error protocol test
		//	if(vBuf[0]&~(CSC_STA_STOP|CSC_STA_RES|CSC_STA_ANS))
		//							return RCSC_DataWrong;
			if((BufIN[1]!=0xFF) && ((BufIN[0]&0x40)== 0))
			{
				if((vBuf[1]!=0xFF) && ((vBuf[0]&0x40)== 0))
				{
					if((vBuf[2]!=BufIN[2])||(vBuf[3]!=BufIN[3]))
									return RCSC_DataWrong;
				}
				else
					if((vBuf[3]!=BufIN[2])||(vBuf[4]!=BufIN[3]))
									return RCSC_DataWrong;
			}
			else
			{
				if((vBuf[1]!=0xFF) && ((vBuf[0]&0x40)== 0))
				{
					if((vBuf[2]!=BufIN[3])||(vBuf[3]!=BufIN[4]))
									return RCSC_DataWrong;
				}
				else
					if((vBuf[3]!=BufIN[3])||(vBuf[4]!=BufIN[4]))
									return RCSC_DataWrong;
			}
		/*$$$$$$$$$$$$$$$$$$$$$$$$*/
		}
	// CHECKSUM test
	giCSCTrameLn=vRet;
	CopyMemory(giCSCTrame,vBuf,giCSCTrameLn);
	if (giCRCNeeded==TRUE){
			if(iCSC_TestCRC()!=iCSC_OK)
			{
				if ((NbTry == 1) && (bIOChannel == SERIAL))
				{	
					NbTry++;
					continue;
				}
				else
					return RCSC_CheckSum;
			}
		}
	}

	if (giCSCMode485 == TRUE)
	{
		CopyMemory(vBuf,&giCSCTrame[1],giCSCTrameLn);
	}
	NbTry=3;
} // (NbTry <= 2)

// Unknown Clas or Command
if(vBuf[0]==CSC_STA_ERROR)return RCSC_UnknownClassCommand;

// copy the local buffer to the external buffer
*LnOUT=vRet;
CopyMemory(BufOUT,vBuf,*LnOUT);

if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb)," %s CSC_SendReceive(... %s , %d)",tdeb2, wCSC_BTS(BufOUT,*LnOUT),*LnOUT);
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_AddCRC(BYTE* Buf,LPDWORD Len)
/*****************************************************************
Compute and Set the CRC at the end of the buffer and change the
Len value

INPUTS
	Buf 	: Buffer without CRC
	Len 	: The buffer size
	
OUTPUT
	Len 	: The new buffer size

RETURNS
	RCSC_Overflow
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{

if (giCRCNeeded == TRUE)
{
	if(Len==NULL)return RCSC_Fail;
	if(Buf==NULL)return RCSC_Fail;
	if(*Len>(kiCSCMaxTrame-2))return RCSC_Overflow;

	CopyMemory(giCSCTrame,Buf,*Len);
	giCSCTrameLn=*Len;

	// Compute and Set the CRC at the end of the buffer
	icsc_SetCRC();

	// copy the local buffer to the external buffer
	*Len=(DWORD)giCSCTrameLn;
	CopyMemory(Buf,giCSCTrame,*Len);
}
return RCSC_Ok;
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_CardConfig(BYTE SearchType)
/*****************************************************************
Configure the CSC in PSCL or contactless card mode

INPUTS
	SearchType	:	- PSCL mode : CSC_SEARCH_PSCL					
					- Contact less Card : CSC_SEARCH_CLESSCARD		

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

SearchMem=0;

if(!gCOMOpen)return RCSC_OpenCOMError;		// CSC_Open no executed

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a SetAntennaTransparentMode command
if((SearchType!=CSC_SEARCH_PSCL)
		&&(SearchType!=CSC_SEARCH_CLESSCARD))return RCSC_Fail;
iCSC_SetAntennaTransparentMode(CSC_SYS_ANTENNA_1,SearchType,
		CSC_SYS_MODE_TRANSPARENT_1);

// Send a command frame to the CSC, and waits for the answer
vRet=CSC_SendReceive(1000,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return vRet;

// save SearchType for the CSC_CardStartSearch function
SearchMem=SearchType;


return RCSC_Ok;
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SearchCardExt(sCARD_SearchExt* search,DWORD search_mask,
													BYTE Forget,BYTE TimeOut,
													LPBYTE COM,LPDWORD lpcbATR,BYTE* lpATR)
/*****************************************************************
Starts the search for a card. This function must be called once
to set the CSC module in a search mode.
The mask specifies the relevant information stored in the sCARD_SearchExt structure

INPUTS
	Search		: Contain the type of tag to be found.
					- CONT : Contact Mode
					- ISOB : ISO B Protocol Mode
					- ISOA : ISO A Protocol Mode
					- TICK : Ticket Mode
					- INNO : Innovatron Protocol Mode
					- MIFARE : Mifare Mode
					- MV4k : MV4k protocol mode
					- MV5k : MV5k protocol mode
					- MONO : mono-search mode
	search_mask	: mask sepcifying the types of cards searched
 	Forget		: Parameter to forget the last tag serial number.
	TimeOut		: Time Out of the command (x10ms).

OUTPUTS
	COM			: type of tag to be found
	lpcbATR		: is its length
	lpATR		: is the ISO ATR sent by the card

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_DataWrong
	RCSC_CheckSum
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	BYTE	searchCONT;
	BYTE	searchISOB;
	BYTE	searchISOA;
	BYTE	searchTICK;
	BYTE	searchINNO;
	BYTE	searchMIFARE;
	BYTE	searchMV4k;
	BYTE	searchMV5k;
	BYTE	searchMono;
	BYTE	searchSRx;

	// SRX
	if ((search_mask & SEARCH_MASK_SRX) == SEARCH_MASK_SRX)
	{
		searchSRx=search->SRX;
		if (searchSRx>0x03) searchSRx=0x03;
	}
	else
	{
		searchSRx=0x00;
	}
	// CONT
	if ((search_mask & SEARCH_MASK_CONT) == SEARCH_MASK_CONT)
	{
		searchCONT=search->CONT;
		if (searchCONT>0x03) searchCONT=0x03;
	}
	else
	{
		searchCONT=0x00;
	}
	// ISOB
	if ((search_mask & SEARCH_MASK_ISOB) == SEARCH_MASK_ISOB)
	{
		searchISOB=search->ISOB;
		if (searchISOB>0x03) searchISOB=0x03;
	}
	else
	{
		searchISOB=0x00;
	}
	// ISOA
	if ((search_mask & SEARCH_MASK_ISOA) == SEARCH_MASK_ISOA)
	{
		searchISOA=search->ISOA;
		if (searchISOA>0x03) searchISOA=0x03;
	}
	else
	{
		searchISOA=0x00;
	}
	// TICK
	if ((search_mask & SEARCH_MASK_TICK) == SEARCH_MASK_TICK)
	{
		searchTICK=search->TICK;
		if (searchTICK>0x03) searchTICK=0x03;
	}
	else
	{
		searchTICK=0x00;
	}
	// INNO
	if ((search_mask & SEARCH_MASK_INNO) == SEARCH_MASK_INNO)
	{
		searchINNO=search->INNO;
		if (searchINNO>0x03) searchINNO=0x03;
	}
	else
	{
		searchINNO=0x00;
	}
	// MIFARE
	if ((search_mask & SEARCH_MASK_MIFARE) == SEARCH_MASK_MIFARE)
	{
		searchMIFARE=search->MIFARE;
		if (searchMIFARE>0x03) searchMIFARE=0x03;
	}
	else
	{
		searchMIFARE=0x00;
	}
	// MV4k
	if ((search_mask & SEARCH_MASK_MV4K) == SEARCH_MASK_MV4K)
	{
		searchMV4k=search->MV4k;
		if (searchMV4k>0x03) searchMV4k=0x03;
	}
	else
	{
		searchMV4k=0x00;
	}
	// MV5k
	if ((search_mask & SEARCH_MASK_MV5K) == SEARCH_MASK_MV5K)
	{
		searchMV5k=search->MV5k;
		if (searchMV5k>0x03) searchMV5k=0x03;
	}
	else
	{
		searchMV5k=0x00;
	}
	// MONO
	if ((search_mask & SEARCH_MASK_MONO) == SEARCH_MASK_MONO)
	{
		searchMono=search->MONO;
		if (searchMono>0x01) searchMono=0x01;
	}
	else
	{
		searchMono=0x00;
	}

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardExt(MASK:%04X-SRX:%02X-CONT:%02X-MV5k:%02X-MV4k:%02X-ISOB:%02X-ISOA:%02X-MIFARE:%02X-TICK:%02X-INNO:%02X-MONO:%02X-Forget:%02X-Timeout:%02X)",
		search_mask,search->SRX,search->CONT,search->MV5k,search->MV4k,search->ISOB,search->ISOA,search->MIFARE,search->TICK,search->INNO,search->MONO,Forget,TimeOut);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(lpcbATR==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCSC_EnterHuntPhase5(CSC_SYS_ANTENNA_1,searchMono,searchSRx, searchCONT,searchISOA,searchMIFARE,
										   searchISOB, searchTICK,searchINNO,searchMV4k,searchMV5k,
										   Forget,TimeOut);

	// Send a command frame to the CSC, and waits 3 seconds for the answer
	vRet=CSC_SendReceive(SearchTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]<4)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	ZeroMemory(lpATR,sizeof(lpATR));
	*COM=vBuf[5];
	if (*COM!=0x6F)
	{
		if (*COM==0x03)	// protocole RMT
		{		
			*lpcbATR=vBuf[6]-6;
			CopyMemory(lpATR,&vBuf[7+6],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardExt(MASK:%04X-CONT:%02X-MV5k:%02X-MV4k:%02X-ISOB:%02X-ISOA:%02X-MIFARE:%02X-TICK:%02X-INNO:%02X-MONO:%02X-Forget:%02X-Timeout:%02X / COM:%02X-ATRln:%d-ATR:%s)",
					search_mask,search->CONT,search->MV5k,search->MV4k,search->ISOB,search->ISOA,search->MIFARE,
					search->TICK,search->INNO,search->MONO,Forget,TimeOut,*COM,*lpcbATR,
					wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
		else 	// other protocols
		{
			*lpcbATR=vBuf[6];
			CopyMemory(lpATR,&vBuf[7],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardExt(MASK:%04X-CONT:%02X-MV5k:%02X-MV4k:%02X-ISOB:%02X-ISOA:%02X-MIFARE:%02X-TICK:%02X-INNO:%02X-MONO:%02X-Forget:%02X-Timeout:%02X / COM:%02X-ATRln:%d-ATR:%s)",
					search_mask,search->CONT,search->MV5k,search->MV4k,search->ISOB,search->ISOA,search->MIFARE,
					search->TICK,search->INNO,search->MONO,Forget,TimeOut,*COM,*lpcbATR,
					wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
	}
	else
	{
		*lpcbATR=0;
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardExt(MASK:%04X-CONT:%02X-MV5k:%02X-MV4k:%02X-ISOB:%02X-ISOA:%02X-MIFARE:%02X-TICK:%02X-INNO:%02X-MONO:%02X-Forget:%02X-Timeout:%02X / COM:%02X-ATRln:%d-ATR:%s)",
					search_mask,search->CONT,search->MV5k,search->MV4k,search->ISOB,search->ISOA,search->MIFARE,
					search->TICK,search->INNO,search->MONO,Forget,TimeOut,*COM,*lpcbATR,
					wCSC_BTS(lpATR,*lpcbATR));
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SearchCard(sCARD_Search Search,
													BYTE Forget,BYTE TimeOut,
													LPBYTE COM,LPDWORD lpcbATR,BYTE* lpATR)
/*****************************************************************
Starts the search for a card. This function must be called once
to set the CSC module in a search mode;

INPUTS
	Search		: Contain the type of tag to be find.
					- CONT : Contact Mode
					- ISOB : ISO B Protocol Mode
					- ISOA : ISO A Protocol Mode
					- TICK : Ticket Mode
					- INNO : Innovatron Protocol Mode
	Forget		: Parameter to forget the last tag serial number.
	TimeOut		: Time Out of the command (x10ms).

OUTPUTS
	COM			: type of tag to be found
	lpcbATR		: is its length
	lpATR		: is the ISO ATR sent by the card

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_DataWrong
	RCSC_CheckSum
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size


	if (Search.CONT>0x0F) Search.CONT=0x0F;
	if (Search.ISOB>0x0F) Search.ISOB=0x0F;
	if (Search.ISOA>0x0F) Search.ISOA=0x0F;
	if (Search.TICK>0x0F) Search.TICK=0x0F;
	if (Search.INNO>0x0F) Search.INNO=0x0F;

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCard(CONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %02X, %02X)",
		Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(lpcbATR==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCSC_EnterHuntPhase2(CSC_SYS_ANTENNA_1,Search.CONT,Search.ISOA,Search.ISOB,
										   Search.TICK,Search.INNO,Forget,TimeOut);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(SearchTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]<4)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	ZeroMemory(lpATR,sizeof(lpATR));
	*COM=vBuf[5];
	if (*COM!=0x6F)	{
		if (*COM==0x03){		// protocole RMT
			*lpcbATR=vBuf[6]-6;
			CopyMemory(lpATR,&vBuf[7+6],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardCONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %d, %02X, %d, %s)",
					Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut,
					*lpcbATR,wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
		else if (*COM==0x04){	// protocole ISO B
			*lpcbATR=vBuf[6];
			CopyMemory(lpATR,&vBuf[7],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardCONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %d, %02X, %d, %s)",
					Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut,
					*lpcbATR,wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
		else if (*COM==0x05){	// protocole ISO A
			*lpcbATR=vBuf[6];
			CopyMemory(lpATR,&vBuf[7],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardCONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %d, %02X, %d, %s)",
					Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut,
					*lpcbATR,wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
		else if (*COM==0x06){	// protocole CTS
			*lpcbATR=vBuf[6];
			CopyMemory(lpATR,&vBuf[7],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardCONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %d, %02X, %d, %s)",
					Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut,
					*lpcbATR,wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
		else if (*COM==0x07){	// protocole CONTACT
			*lpcbATR=vBuf[6];
			CopyMemory(lpATR,&vBuf[7],*lpcbATR);
			if(swDEBUG==1)
			{ /* DEBUG */
				sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardCONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %d, %02X, %d, %s)",
					Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut,
					*lpcbATR,wCSC_BTS(lpATR,*lpcbATR));
			} /* LOG DEBUG */
		}
	}
	else
	{
		*lpcbATR=0;
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"CSC_SearchCardCONT:%02X-ISOB:%02X-ISOA:%02X-TICK:%02X-INNO:%02X, %d, %02X, %d, %s)",
				Search.CONT,Search.ISOB,Search.ISOA,Search.TICK,Search.INNO,Forget,TimeOut,
				*lpcbATR,wCSC_BTS(lpATR,*lpcbATR));
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_CardStartSearch(void)
/*****************************************************************
Starts the search for a card. This function must be called once
to set the CSC module in a search mode;
Then the CSC_CardFound may be called repeatedly to see if a card
was detected.

CSC_CardConfig function must be called before.

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_DataWrong
	RCSC_CheckSum
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_CardStartSearch");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a EnterHuntPhase command
iCSC_EnterHuntPhase(CSC_SYS_ANTENNA_1,SearchMem);

// Send a command frame to the CSC, and waits for the answer
vRet=CSC_SendReceive(0,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if((vRet!=RCSC_Ok)&&(vRet!=RCSC_Timeout))
										return wCSC_DebugLog(tdeb,vRet);

// Start the timer
TimerLAP=wCSC_GetTimer(0);
TimeoutSearch=3000;  // 3 seconds

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_CardStopSearch(void)
/*****************************************************************
Stops the search for a card
This function must be called to stop a search running, when no
card has been found


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
BYTE vBuf[255];			// local temp buffer
DWORD ptRepLen[1];
DWORD vRet;

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_CardStopSearch");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// not avalilable in PCSC mode
if (bIOChannel == PCSC)
	wCSC_DebugLog(tdeb,RCSC_InputDataWrong);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

	if (giCSCMode485 == TRUE)
	{

		// prepares the command buffer for a StopSearchCommand
		iCSC_SearchStop(DEFINITIVELY);

		// Send a command frame to the CSC, and waits 2 seconds for the answer
		vRet=CSC_SendReceive(2000,giCSCTrame,giCSCTrameLn,vBuf,ptRepLen);
	
		if(vRet!=RCSC_Ok)  	
			return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	}
	else
	{
		// prepares the command buffer for a SetAntennaTransparentMode command
		giCSCTrame[0]=CSC_CMD_STOP;

		// send the command CSC_CMD_STOP.
		if(wCSC_SendCOM(giCSCTrame,1)==FALSE)return wCSC_DebugLog(tdeb,RCSC_TXError);

		// receive 1 character from CSC
		if(wCSC_ReceiveCOM(2000,1,vBuf)!=1)return wCSC_DebugLog(tdeb,CSC_VersionCSC(NULL));
	
		// result data check
		if(vBuf[0]!=CSC_STA_STOP)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_CardFound(BYTE* lpATR,
												   LPDWORD lpcbATR)
/*****************************************************************
Look if a card was found.
The function CSC_CardStartSearch must have been called previously
to start the search


OUTPUTS
	lpATR	: is the ISO ATR sent by the card
	lpcbATR	: is its length


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value
DWORD ptRepLen[1];
BYTE vBuf[255];				// local temp buffer

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_CardFound");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// not avalilable in PCSC mode
if (bIOChannel == PCSC)
	wCSC_DebugLog(tdeb,RCSC_InputDataWrong);

	if (giCSCMode485 == TRUE)
	{

		// prepares the command buffer for a StopSearchCommand
		iCSC_SearchStop(INTERROGATION);

		// Send a command frame to the CSC, and waits 2 seconds for the answer
		vRet=CSC_SendReceive(2000,giCSCTrame,giCSCTrameLn,vBuf,ptRepLen);
	
		if((vRet!=RCSC_Ok) || (vBuf[3] != 0x02)) 	
			return wCSC_DebugLog(tdeb,RCSC_DataWrong);

		if(vBuf[5] == 0x7F )
			return RCSC_CardNotFound;

		*lpcbATR=vBuf[6];
		CopyMemory(lpATR,&vBuf[7],*lpcbATR);

	}
	else	// not 485
	{
		// Receive the ATR from the CSC ( only if a card was found )
		if(wCSC_ReceiveCOM(0,255,vBuf)<=0) 
		{
			if(wCSC_GetTimer(TimerLAP)>TimeoutSearch)
			{
				// Restart the timer
				TimerLAP=wCSC_GetTimer(0);
				// The card is not found yet -> restart the search
				if((vRet=CSC_CardStopSearch())!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet); 
				if((vRet=CSC_CardStartSearch())!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet); 
			}

			return RCSC_CardNotFound;
		}
	
		// return the ATR in the lpATR buffer
		//  <STA><LEN><CLASS><ID><ANT><MODE><LEN REPGEN><SER0><SER1><SER2>
		//  <SER3><VERLOG><CONFIG><ATR...><CRC>
		if((vBuf[1]>11) && ((vBuf[11]/*VERLOG*/&0x80)!=0)	&& ((vBuf[12]/*CONFIG*/ & 0x40)!=0))
		{
		// copy the ATR to the external buffer
			if((lpcbATR!=NULL)&&(lpATR!=NULL))
			{
				*lpcbATR=vBuf[1]-12/*PosATR*/+1;
				CopyMemory(lpATR,&vBuf[1]+12/*PosATR*/,*lpcbATR);
	
				if(swDEBUG==1){ /* DEBUG */
					sprintf_s(tdeb,sizeof(tdeb),"CSC_CardFound(%s , %d)",wCSC_BTS(lpATR,*lpcbATR),*lpcbATR);
				} /* LOG DEBUG */
			}
		}
		else
		{
		// copy the ATR to the external buffer
			if((lpcbATR!=NULL)&&(lpATR!=NULL))
			{
				*lpcbATR=vBuf[1];
				CopyMemory(lpATR,&vBuf[2],*lpcbATR);

				if(swDEBUG==1){ /* DEBUG */
					sprintf_s(tdeb,sizeof(tdeb),"CSC_CardFound(%s , %d)",wCSC_BTS(lpATR,*lpcbATR),*lpcbATR);
				} /* LOG DEBUG */
			}
			// No correct ATR
			return wCSC_DebugLog(tdeb,RCSC_BadATR);
		}
	}// end choice RS485 / other format
return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_CardEnd(void)
/*****************************************************************
End the communication with the card


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_DataWrong
	RCSC_CheckSum
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size
sprintf_s(tdeb,sizeof(tdeb),"CSC_CardEnd");

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a EndTagCommunication command
iCSC_EndTagCommunication(CSC_SYS_DISC_REQ);

// Send a command frame to the CSC, and waits for the answer
return wCSC_DebugLog(tdeb,CSC_SendReceive(500,giCSCTrame,giCSCTrameLn,vBuf,&vLen));
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_AntennaOFF(void)
/*****************************************************************
Stop the antenna


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_DataWrong
	RCSC_CheckSum
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_AntennaOFF");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a SwitchOffAntenna command
iCSC_SwitchOffAntenna(0); // antenna 1

// Send a command frame to the CSC, and waits for the answer
return wCSC_DebugLog(tdeb,CSC_SendReceive(500,giCSCTrame,giCSCTrameLn,vBuf,&vLen));
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ISOCommand(BYTE* BufIN,DWORD LnIN,
													BYTE* BufOUT,LPDWORD lpLnOUT)
/*****************************************************************
Sends an ISO command, and returns the answer.


INPUTS
	BufIN	: the ISO Command to send to the card
	LnIN	: ISO command length
	
OUTPUT
	BufOUT	: Contains the answer
	lpLnOUT	: The answer size

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommand( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// check LnIN and BufIN have a good values
if(!LnIN)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(LnIN>=256)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(BufIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommand(%s , %d ,...,...)",wCSC_BTS(BufIN,LnIN),LnIN);
} /* LOG DEBUG */

// prepares the command buffer for a SendToAntenna command
iCSC_SendToAntenna(BufIN,(BYTE)LnIN);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// check Status communication byte
switch(vBuf[4])
	{
	case 0x00:case 0xFC:return wCSC_DebugLog(tdeb,RCSC_Timeout);
	case 0xFF:case 0xFE:return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	case 0xFD:return wCSC_DebugLog(tdeb,RCSC_Overflow);
	case 0xFB:return wCSC_DebugLog(tdeb,RCSC_CheckSum); // CRC error
	}
if(vBuf[4]!=0x01)return wCSC_DebugLog(tdeb,RCSC_Fail);

// copy the local buffer to the external buffer
if((lpLnOUT!=NULL)&&(BufOUT!=NULL))
	{
	*lpLnOUT=vBuf[5];
	if(BufOUT!=NULL)CopyMemory(BufOUT,&vBuf[6],*lpLnOUT);
	
	if(swDEBUG==1){ /* DEBUG */
	strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(BufOUT,*lpLnOUT));
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommand(%s , %d , %s , %d)",wCSC_BTS(BufIN,LnIN),
														LnIN,vBuf,*lpLnOUT);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ISOCommandExt(BYTE LnINLow, BYTE LnINHigh, BYTE* BufIN, 
														BYTE* Status, BYTE* LnOutLow, BYTE* LnOutHigh, BYTE* BufOUT)
/*****************************************************************
Sends an ISO command Extended, and returns the answer.


INPUTS
	LnINLow		: ISO command length Low (1 Byte)
	LnINHigh	: ISO command length High (1 Byte)
	BufIN		: the ISO Command to send to the card (n Bytes)
	
OUTPUT
	Status		: communication status (1 Byte)
					$01 : data received
					$00 (resp $03): no data received in timeout delay in Innovatron or ISOA protocol (resp. ISOB protocol)
					$06 : invalid CID
					$08 : ICC fails to answer correctly
					$FF : data coding error
					$FE : error detected by communication controller
					$FD : reception buffer overflow
					$FC : timeout delay expired before end of reception
					$FB : CRC error 
	LnOutLow	: The answer size Low (1 Byte)
	LnOutHigh	: The answer size High (1 Byte)
	BufOUT		: Contains the answer (n Byte)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandExt( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// check LnIN and BufIN have a good values
	if(!LnINLow)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(BufIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandExt(%s , %02X ,%02X,...)",wCSC_BTS(BufIN,(LnINLow + (256*LnINHigh))), LnINLow, LnINHigh);
	} // LOG DEBUG 

	// prepares the command buffer for a SendToAntenna command
	iCSC_SendToAntennaExt(LnINLow, LnINHigh, BufIN);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// check Status communication byte
	switch(vBuf[5])
	{
		case 0x00:case 0xFC:return wCSC_DebugLog(tdeb,RCSC_Timeout);
		case 0x06:case 0x08:return wCSC_DebugLog(tdeb,RCSC_Fail);
		case 0xFF:case 0xFE:return wCSC_DebugLog(tdeb,RCSC_DataWrong);
		case 0xFD:return wCSC_DebugLog(tdeb,RCSC_Overflow);
		case 0xFB:return wCSC_DebugLog(tdeb,RCSC_CheckSum); // CRC error
	}
	if(vBuf[5]!=0x01)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// copy the local buffer to the external buffer
	if((LnOutLow!=NULL)&&(LnOutHigh!=NULL)&&(BufOUT!=NULL))
	{
		*Status=vBuf[5];
		*LnOutLow=vBuf[6];
		*LnOutHigh=vBuf[7];
		CopyMemory(BufOUT,&vBuf[8],((*LnOutLow) + (256 * (*LnOutHigh))));
		
		if(swDEBUG==1){ // DEBUG 
			strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(BufOUT,((*LnOutLow) + (256*(*LnOutHigh)))));
			sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandExt(%s , %d, %s , %d)", wCSC_BTS(BufIN, (LnINLow + (256*LnINHigh))), (LnINLow + (256 * LnINHigh)), vBuf, ((*LnOutLow) + (256*(*LnOutHigh))));
		} // LOG DEBUG 
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_TransparentCommandConfig(BYTE ISO,
																  BYTE addCRC,
																  BYTE checkCRC,
																  BYTE field,
																  BYTE* configISO,
																  BYTE* configAddCRC,
																  BYTE* configCheckCRC,
																  BYTE* configField)
/*****************************************************************
Configures the settings of "CSC_TransparentCommand"


INPUTS
	ISO :		0x00 : for getting the current config
				0x01 : for selecting ISOB
				0x02 : for selecting ISOA
	addCRC :	0x01 : the CRC will be computed and added to the frame
				else : nothing to add, the frame is sent directly
	checkCRC :	0x01 : the CRC of the frame received needs to be checked
				else : nothing to check
	field :		0x01 : the field will be switched ON when sending the frame
				else : no modification of the field
	
OUTPUT
	configISO :	0x01 : ISOB selected
				0x02 : ISOA selected
				0xFF : wrong protocol asked
	configAddCRC :		current configuration (same values as input)
	configCheckCRC :	current configuration (same values as input)
	configField :		current configuration (same values as input)

  
RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommandConfig( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();


if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommandConfig(ISO:%d,addCRC:%d,checkCRC:%d,field:%d)",
		(int)ISO, (int)addCRC, (int)checkCRC, (int)field);
} /* LOG DEBUG */

// prepares the command buffer for the command
iCSC_TransparentCommandConfig(ISO, addCRC, checkCRC, field);

// Send a command frame to the CSC, and wait "FuncTimeout" for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=configISO
	vBuf[5]=configAddCRC
	vBuf[6]=configCheckCRC
	vBuf[7]=configField
	vBuf[8]=EOF
	vBuf[9]=CRCL
	vBuf[10]=CRCH
*/

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);


// copy the local buffer to the external buffer
*configISO		= vBuf[4];
*configAddCRC	= vBuf[5];
*configCheckCRC	= vBuf[6];
*configField	= vBuf[7];

// check the answer length
if(vBuf[1]!=6)return wCSC_DebugLog(tdeb,RCSC_DataWrong);


if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommandConfig(ISO:%d,addCRC:%d,checkCRC:%d,field:%d/configISO:%d,configAddCRC:%d,configCheckCRC:%d,configField:%d)",
		ISO,addCRC,checkCRC,field,*configISO,*configAddCRC,*configCheckCRC,*configField);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_TransparentCommandConfigExt(BYTE ISO,
																	 BYTE addCRC,
																	 BYTE checkCRC,
																	 BYTE addParity,
																	 BYTE checkParity,
																	 BYTE numBitLastByte,
																	 BYTE byPassISOA,
																	 BYTE field,
																	 WORD timeOut,
																	 BYTE* configISO,
																	 BYTE* configAddCRC,
																	 BYTE* configCheckCRC,
																	 BYTE* configAddParity,
																	 BYTE* configCheckParity,
																	 BYTE* configNumBitLastByte,
																	 BYTE* configByPassISOA,
																	 BYTE* configField,
																	 WORD* configTimeOut)
/*****************************************************************
Configures the settings of "CSC_TransparentCommand"


INPUTS
	ISO				:	0x00 : for getting the current config
						0x01 : for selecting ISOB
						0x02 : for selecting ISOA
						0x03 : for selecting Felica (only Gen5xx)
	addCRC			:	0x01 : the CRC will be computed and added to the frame
						else : nothing to add, the frame is sent directly
	checkCRC		:	0x01 : the CRC of the frame received needs to be checked
						else : nothing to check
	addParity		:	0x01 : the Parity will be computed and added to the frame
						else : nothing to add, the frame is sent directly
	checkParity		:	0x01 : the Parity of the frame received needs to be checked
						else : nothing to check
	numBitLastByte	:	Number of bits of the last byte that shall transmitted 0 to 7 (1 byte)
	byPassISOA		:	0x01 : ByPass ISOA
						else : True ISOA
	field			:	0x01 : the field will be switched ON when sending the frame
						else : no modification of the field
	timeOut			:	TimeOut Allowed for answer 0 to 2000 ms (default 456 ms) (2 bytes) 	
	
OUTPUT
	configISO			:	0x01 : ISOB selected
							0x02 : ISOA selected
							0x03 : Felica selected
							0xFF : wrong protocol asked
	configAddCRC		:	current configuration (same values as input)
	configCheckCRC		:	current configuration (same values as input)
	configAddParity		:	current configuration (same values as input)
	configCheckParity	:	current configuration (same values as input)
	configNumBitLastByte:	current configuration (same values as input)
	configByPassISOA	:	current configuration (same values as input)
	configField			:	current configuration (same values as input)
	configTimeOut		:	current configuration (same values as input)	
  
RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommandConfigExt( )");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// check Input values
	if(ISO > 3)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((addCRC || checkCRC || addParity || checkParity || byPassISOA || field) > 1)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(numBitLastByte > 7)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommandConfigExt(ISO:%d,addCRC:%d,checkCRC:%d,field:%d)",
			ISO,addCRC,checkCRC,field);
	} /* LOG DEBUG */

	// prepares the command buffer for the command
	iCSC_TransparentCommandConfigExt(ISO, addCRC, checkCRC, addParity, checkParity, numBitLastByte, byPassISOA, field, timeOut);

	// Send a command frame to the CSC, and wait "FuncTimeout" for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);


	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);


	// copy the local buffer to the external buffer
	*configISO			= vBuf[4];
	*configAddCRC		= vBuf[5]&0x01;
	*configCheckCRC		= vBuf[6]&0x01;
	*configAddParity	= (vBuf[5]&0x08)>>3;
	*configCheckParity	= (vBuf[6]&0x08)>>3;
	*configNumBitLastByte = (vBuf[5]&0x70)>>4;
	*configByPassISOA	= (vBuf[5]&0x80)>>7;;
	*configField		= vBuf[7];
	*configTimeOut		= (WORD)(vBuf[8] | ((vBuf[9] << 8) & 0xFF00));

	// check the answer length
	if(vBuf[1]!=8)return wCSC_DebugLog(tdeb,RCSC_DataWrong);


	if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommandConfigExt(ISO:%d,addCRC:%d,checkCRC:%d,field:%d/configISO:%d,configAddCRC:%d,configCheckCRC:%d,configField:%d)",
			ISO,addCRC,checkCRC,field,*configISO,*configAddCRC,*configCheckCRC,*configField);
	} /* LOG DEBUG */


	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_TransparentCommand(BYTE* bufIn,
															DWORD lnIn,
															BYTE* status,
															DWORD* lnOut,
															BYTE* bufOut)
/*****************************************************************
sends and receives a transparent command, as previously configured with the
	CSC_TransparentCommandsConfig function



INPUTS
	bufIn	: data to send
	lnIn	: length of the data to send
	
OUTPUT
	bufOut	: data received
	lnOut	: length of the data received
	status	: ISOB and FELICA :	0x01 : CRC checked successfully (if asked)
								0xFF : wrong CRC (if asked to be checked)
								0x00 : CRC not checked
			  ISOA : 0x01 : CRC and Parity checked successfully (if asked)
					 0xFF : wrong CRC (if asked to be checked)
					 0x0F : good CRC (if asked to be checked)
					 0xEE : wrong Parity (if asked to be checked)
					 0x0E : good Parity (if asked to be checked)
					 0x00 : CRC and Parity not checked

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommand( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();


// check lnIn and bufIn have a good values
if(!lnIn)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(lnIn>=256)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(bufIn==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);


if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommand(bufIn:%s,lnIn:%d)",wCSC_BTS(bufIn,lnIn),lnIn);
} /* LOG DEBUG */

// prepares the command buffer for the command
iCSC_TransparentCommand((BYTE)lnIn, bufIn);

// Send a command frame to the CSC, and wait "FuncTimeout" for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=status
	vBuf[5]=lnOut
	vBuf[6]=bufOut[0]
	vBuf[7]=bufOut[1]
	  ...
	vBuf[x]=EOF
	vBuf[x+1]=CRCL
	vBuf[x+2]=CRCH
*/

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);


// copy the local buffer to the external buffer
if((lnOut!=NULL)&&(bufOut!=NULL))
	{
	*status = vBuf[4];
	*lnOut = vBuf[5];
	CopyMemory(bufOut,&vBuf[6],*lnOut);
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_TransparentCommand(bufIn:%s,lnIn:%d / status:%02X,bufOut:%s,lnOut:%d)",
							wCSC_BTS(bufIn,lnIn),lnIn,*status,wCSC_BTS(bufOut,*lnOut),*lnOut);
	} /* LOG DEBUG */
	}


return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_WriteSAMNumber(BYTE	N_SAM,
														BYTE*	status)
/*****************************************************************
writes the default SAM number in EEPROM for memory

INPUTS
	N_SAM : SAM number
	
OUTPUT
	status	: status : 0 = failure / 1 = success

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_WriteSAMNumber( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();


if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_WriteSAMNumber(N_SAM:%d)",N_SAM);
} /* LOG DEBUG */

// prepares the command buffer for the command
iCSC_WriteSAMNumber(N_SAM);

// Send a command frame to the CSC, and wait "FuncTimeout" for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=status
	vBuf[5]=EOF
	vBuf[6]=CRCL
	vBuf[7]=CRCH
*/

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);


// copy the local buffer to the external buffer
*status = vBuf[4];


if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_WriteSAMNumber(N_SAM:%d / status:%d)",
		N_SAM, *status);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_WriteConfigEeprom(BYTE Index, BYTE Value, BYTE *Status)
/*****************************************************************
Writes in the EEPROM configuration

INPUTS
	Index			:	Index (1 byte)
						$01 : Value  =  serial (RS232/TTL/RS485) baud rate divider =1382400 / BAUDRATE                                       
						$02 : Not relevant for GEN5xx : kept for compatibility with other products
						$03 : Not relevant for GEN5xx : kept for compatibility with other products
						$04 : Value  = default SAM Number
						$05 : Field off CTx : turn on the field before CTx command and turn off the field during (Value * 1 ms) after CTx command. 0x00 and 0xFF disable field management on CTx
						$06 : Auto Led management enabled if  Value = 1. Leds are managed by firmware (red = power on, orange = field on, green = reader/card communication.
						$07 : Not significant on GEN5xx
						$08 : Host communication frame padding : module 62 byte padding if Value = 62.
						$09 : ISO14443-4 number of retries.
						$0A : Delay between retries (ms).
						$0B : default RX RF speed at reset (00=106, 01=212, 02=424, 03=847 kb/s).
						$0C : default RX RF speed at reset (00=106, 01=212, 02=424, 03=847 kb/s).
						$0D : SAM reset at coupler reset (0=no reset)
						$0E : AUX Pin signal
						$0F : High baud rate ISO14443-A gain (00=20, 01=24, 02=31, 03=35 dB)
						$10 : Last Slot switch test (1=yes (CAM), other = no (SAM))
						$11 : Strict ISO14443-3B timeout (1=strict check, other = no strict check, same as GEN3XX)
						$12 : Strict ISO14443-4B timeout (1=strict check, other = no strict check, same as GEN3XX)
						$13 : Delay after REQ/Select (0 or FF : no delay, same as GEN3XX, other = delay in ms)
						$14 : Unconditional Mifare selection before authentication (if value=1)
						$15 : Not significant on GEN5XX
						$16 : Custom Frame Waiting Time (Value  * 10 ms, 00 or FF = no custom FWT)
						$17 : ISO14443-4 retries on PICC timeout (if value=1)

	Value			:	Value (1 byte)

OUTPUTS
	Status			:	Status of the operation (1 byte)
						$00 : Failure
						$01 : Success

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_WriteConfigEeprom(Index : %02X)", Index);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_WriteConfigEeprom( Index, Value );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[4];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"CSC_WriteConfigEeprom(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ReadConfigEeprom(BYTE Index, BYTE *Status, BYTE *Value)
/*****************************************************************
Read the value at the Index EEPROM

INPUTS
	Index			:	Index (1 byte)
						$01 : Value  =  serial (RS232/TTL/RS485) baud rate divider =1382400 / BAUDRATE                                       
						$02 : Not relevant for GEN5xx : kept for compatibility with other products
						$03 : Not relevant for GEN5xx : kept for compatibility with other products
						$04 : Value  = default SAM Number
						$05 : Field off CTx : turn on the field before CTx command and turn off the field during (Value * 1 ms) after CTx command. 0x00 and 0xFF disable field management on CTx
						$06 : Auto Led management enabled if  Value = 1. Leds are managed by firmware (red = power on, orange = field on, green = reader/card communication.
						$07 : Not significant on GEN5xx
						$08 : Host communication frame padding : module 62 byte padding if Value = 62.
						$09 : ISO14443-4 number of retries.
						$0A : Delay between retries (ms).
						$0B : default RX RF speed at reset (00=106, 01=212, 02=424, 03=847 kb/s).
						$0C : default RX RF speed at reset (00=106, 01=212, 02=424, 03=847 kb/s).
						$0D : SAM reset at coupler reset (0=no reset)
						$0E : AUX Pin signal
						$0F : High baud rate ISO14443-A gain (00=20, 01=24, 02=31, 03=35 dB)
						$10 : Last Slot switch test (1=yes (CAM), other = no (SAM))
						$11 : Strict ISO14443-3B timeout (1=strict check, other = no strict check, same as GEN3XX)
						$12 : Strict ISO14443-4B timeout (1=strict check, other = no strict check, same as GEN3XX)
						$13 : Delay after REQ/Select (0 or FF : no delay, same as GEN3XX, other = delay in ms)
						$14 : Unconditional Mifare selection before authentication (if value=1)
						$15 : Not significant on GEN5XX
						$16 : Custom Frame Waiting Time (Value  * 10 ms, 00 or FF = no custom FWT)
						$17 : ISO14443-4 retries on PICC timeout (if value=1)


OUTPUTS
	Status			:	Status of the operation (1 byte)
						$00 : Failure
						$01 : Success
	Value			:	Value (1 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_ReadConfigEeprom(Index : %02X)", Index);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_ReadConfigEeprom( Index );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[4];
	*Value = vBuf[5];

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"CSC_ReadConfigEeprom(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ISOCommandContact(BYTE* BufIN,DWORD LnIN,
														   BYTE Case,
													BYTE* BufOUT,DWORD* lpLnOUT)
/*****************************************************************
Sends an ISO command in contact mode, with the choice of the case :
IN, OUT, IN and OUT

INPUTS
	BufIN	: the ISO Command to send to the card
	LnIN	: ISO command length
	Case	: APDU case :	01 : IN
							02 : OUT
							03 : IN and OUT
	
OUTPUT
	BufOUT	: Contains the answer
	lpLnOUT	: The answer size

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandContact( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// check LnIN and BufIN have a good values
if(!LnIN)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(LnIN>=256)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(BufIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandContact(BufIn:%s - LnIn:%d - Case:%d)",wCSC_BTS(BufIN,LnIN),LnIN,Case);
} /* LOG DEBUG */

// prepares the command buffer for a SendToAntenna command
iCSC_ISOCommandContact(BufIN,(BYTE)LnIN,Case);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=status
	vBuf[5]=lng(data) + 1 (length included) 
	vBuf[6]=data
	vBuf[7]=data
	....
	vBuf[x]=data
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// check Status communication byte
if(vBuf[4]!=0x00)return wCSC_DebugLog(tdeb,RCSC_Fail);

// copy the local buffer to the external buffer
*lpLnOUT=vBuf[5]-1;
if(BufOUT!=NULL)CopyMemory(BufOUT,&vBuf[6],*lpLnOUT);

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandContact(BufIn:%s - LnIn:%d - Case:%d / BufOut:%s - LnOut:%d)",
		wCSC_BTS(BufIN,LnIN),LnIN,Case,wCSC_BTS(BufOUT,*lpLnOUT),*lpLnOUT);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_GetCommand(BYTE Command,
													BYTE* BufOUT,LPDWORD LnOUT)
/*****************************************************************
Return the CSC module command frame ( Internal ASK function )

INPUTS
	Command		The command name (CSC_SYS_SOFTWARE_VERSION,...)
	
OUTPUT
	BufOUT 		Command frame
	LnOUT		The bufOUT size

RETURNS
	RCSC_Fail
	RCSC_Ok
*****************************************************************/
{
switch(Command)
	{
	case CSC_SYS_SOFTWARE_VERSION:
		iCSC_SoftwareVersion();
		break;
	case CSC_SYS_ENTER_HUNT_PHASE:
		iCSC_EnterHuntPhase(CSC_SYS_ANTENNA_1,CSC_SEARCH_CLESSCARD);
		break;
	case CSC_SYS_GET_COMMUNICATION_STATUS:
		iCSC_GetCommStatus();
		break;
	case CSC_SYS_SWITCH_OFF_ANTENNA:
		iCSC_SwitchOffAntenna(CSC_SYS_ANTENNA_1);
		break;
	case CSC_SYS_END_TAG_COMMUNICATION:
		iCSC_EndTagCommunication(CSC_SYS_DISC_REQ);
		break;
	default:return RCSC_Fail;
	}

// copy the local buffer to the external buffer
*LnOUT=(DWORD)giCSCTrameLn;
CopyMemory(BufOUT,giCSCTrame,*LnOUT);
return RCSC_Ok;
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SelectSAM(BYTE N_SAM,BYTE Type)
/*****************************************************************
select the specified SAM.


INPUT
	N_SAM				Number of SAM to select.
	Type				Protocole used
RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_SelectSAM(%02X, %02X)",N_SAM, Type);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCSC_SelectSAM(N_SAM,Type);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	if(vBuf[1]<3)return (tdeb,RCSC_DataWrong);
	if(vBuf[4]!=0)return (tdeb,RCSC_SelectSAMError);
	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_SelectSAM(%02X)",N_SAM);
	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ResetSAM(BYTE* lpATR,
												  LPDWORD lpcbATR)
/*****************************************************************
Reset the SAM, and returns the ATR.


OUTPUT
	lpATR								Contains the ATR of the SAM
	lpcbATR								The ATR length

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ResetSAM( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check lpATR and lpcbATR have a good values
if(lpATR==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(lpcbATR==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a ResetSAM command
iCSC_ResetSAM();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// check Status communication byte => take account of warnings = 0x80 to 0x83
if((vBuf[4] & 0x7C )!=0x00)return wCSC_DebugLog(tdeb,RCSC_ErrorSAM);

// copy the local buffer to the external buffer
*lpcbATR=vBuf[5]-1;
CopyMemory(lpATR,&vBuf[6],*lpcbATR);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ResetSAM(%s , %d)",wCSC_BTS(lpATR,*lpcbATR),*lpcbATR);
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ResetSAMExt(BYTE SamNum, BYTE SelectINN, BYTE SelectISO,
													 LPDWORD lpcbATR, BYTE* lpATR)
/*****************************************************************
Reset the SAM, and returns the ATR.

INPUTS
	SamNum		: Selection of SAM (1 byte)
					$00 : SAM usually selected
					$01 : SAM 1
					$02 : SAM 2
					$03 : SAM 3
					$04 : SAM 4
					Others RUF
	SelectINN	: Selection of SAM in Innovatron High Speed protocol  (1 byte)
					$01 : selection of SAM in Innovatron protocol 
					$00 : no SAM selection in this protocol
	SelectISO	: selection of protocol ISO 7816 (1 byte)
					$01 : selection of SAM in ISO7816 T=0 protocol 
					$02 : selection of SAM in ISO7816 T=1 protocol
					$00 : no SAM selection in this protocol

OUTPUT
	lpATR		: Contains the ATR of the SAM (n byte)
	lpcbATR		: The ATR length (1 byte)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ResetSAMExt(%02X, %02X, %02X)", SamNum, SelectINN, SelectISO);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check lpATR and lpcbATR have a good values
	if(lpATR==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(lpcbATR==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer for a ResetSAM command
	iCSC_ResetSAMExt(SamNum, SelectINN, SelectISO);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// check Status communication byte => take account of warnings = 0x80 to 0x83
	if((vBuf[4] & 0x7C )!=0x00)return wCSC_DebugLog(tdeb,RCSC_ErrorSAM);

	// copy the local buffer to the external buffer
	*lpcbATR=vBuf[5]-1;
	CopyMemory(lpATR,&vBuf[6],*lpcbATR);

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ResetSAMExt(%s , %d)",wCSC_BTS(lpATR,*lpcbATR),*lpcbATR);
	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ISOCommandSAM(BYTE* BufIN,
							DWORD LnIN,BYTE* BufOUT,LPDWORD lpLnOUT)
/*****************************************************************
Sends an ISO command to the SAM, and returns the answer.


INPUTS
	BufIN									the ISO Command to send to the SAM
	LnIN									ISO command length
	
OUTPUT
	BufOUT								Contains the answer
	lpLnOUT								The answer size

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandSAM( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check BufIN and LnIN have a good values
if(BufIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandSAM(%s , %d ,...,...)",wCSC_BTS(BufIN,LnIN),LnIN);
} /* LOG DEBUG */

if(LnIN==0)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(LnIN>255)return wCSC_DebugLog(tdeb,RCSC_Fail);


// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a SendToSAM command
iCSC_SendToSAM(BufIN,(BYTE)LnIN);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// check Status communication byte
if(vBuf[4]!=0x00)return wCSC_DebugLog(tdeb,RCSC_ErrorSAM);

// copy the local buffer to the external buffer
if((lpLnOUT!=NULL)&&(BufOUT!=NULL))
	{
	*lpLnOUT=vBuf[5];
	CopyMemory(BufOUT,&vBuf[6],*lpLnOUT);
	
	if(swDEBUG==1){ /* DEBUG */
	strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(BufOUT,*lpLnOUT));
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandSAM(%s , %d , %s , %d)",
			wCSC_BTS(BufIN,LnIN),LnIN,vBuf,*lpLnOUT);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ISOCommandSAMExt(BYTE NumSAM, DWORD LgBufIN, BYTE* BufIN, BYTE Direction,
															LPDWORD LgBufOUT, BYTE* BufOUT)
/*****************************************************************
Sends an ISO command to the SAM, and returns the answer.


INPUTS
	NumSAM								Sam Number 
											$00, $01, $02, $03, $04 as defined in "Reset Sam" cmd
	LgBufIN								ISO command length
	BufIN								the ISO Command to send to the SAM
	Direction							Direction
											$01 : In
											$02 : Out
											$03 : In - Out
	
OUTPUT
	LgBufOUT							The answer size
	BufOUT								Contains the answer

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/
{
	INT vRet;						// return value from CSC_SendReceive
	BYTE vBuf[255];					// local temp buffer
	DWORD vLen;						// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandSAMExt( )");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check BufIN and LnIN have a good values
	if(BufIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandSAMExt(%s , %d ,...,...)",wCSC_BTS(BufIN,LgBufIN),LgBufIN);
	} /* LOG DEBUG */

	if(LgBufIN==0)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(LgBufIN>255)return wCSC_DebugLog(tdeb,RCSC_Fail);


	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer for a SendToSAM command
	iCSC_SendToSAMExt(NumSAM,(BYTE)LgBufIN, BufIN, Direction);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// check Status communication byte
	if(vBuf[4]!=0x00)return wCSC_DebugLog(tdeb,RCSC_ErrorSAM);

	// copy the local buffer to the external buffer
	if((LgBufOUT!=NULL)&&(BufOUT!=NULL))
	{
		*LgBufOUT=vBuf[5];
		CopyMemory(BufOUT,&vBuf[6],*LgBufOUT);
		
		if(swDEBUG==1){ /* DEBUG */
		strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(BufOUT,*LgBufOUT));
		sprintf_s(tdeb,sizeof(tdeb),"CSC_ISOCommandSAMExt(%s , %d , %s , %d)",
				wCSC_BTS(BufIN,LgBufIN),LgBufIN,vBuf,*LgBufOUT);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_Switch_Led_Buz(WORD Param)
/*****************************************************************
Switch ON or OFF LEDs and Buzzer

INPUTS
	Param : 
			- Bit0 :Antanna's LED1 (on if=1)
			- Bit1 :Antenna's LED2 (on if=1)
			- Bit2 :Antenna's Buzzer (on if=1)
			- Bit9 :CPU's LED1 (on if=1)
			- Bit10:CPU's LED2 (on if=1)
			- Bit11:CPU's LED3 (on if=1)
RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_Switch_Led_Buz(%04X)",Param);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCSC_Switch_Led_Buzzer(Param);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
 	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	if(vBuf[1]<3)return (tdeb,RCSC_DataWrong);
	if(vBuf[4]!=0)return (tdeb,RCSC_Fail);
	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_Switch_Led_Buz(%04X)",Param);
	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_AppendRecord(BYTE AccMode,
									BYTE SID,LPBYTE Rec,BYTE RecSize,
												sCARD_Status* Status)
/*****************************************************************
Add a record to a circular EF


INPUTS
	AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		: Short ID Number ( CD97_SID_RT_JOURNAL, ...)
	Rec     : Data to write
	RecSize : The size of data to write

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_AppendRecord(%d , %d)",AccMode,SID);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Rec==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_AppendRecord(%d , %d , %s , %d)",
		AccMode,SID,wCSC_BTS(Rec,RecSize),RecSize);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_AppendRecord(AccMode,SID,Rec,RecSize);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_AppendRecord(%d , %d , %s , %d , %02X%02X%02X)",
			AccMode,SID,wCSC_BTS(Rec,RecSize),RecSize,Status->Code,
			Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_ChangeKey(BYTE KeyIndex,
								BYTE NewVersion,sCARD_Status* Status)
/*****************************************************************
Change the key / Personnalization


INPUTS
	KeyIndex   : Index of the key ( 01 - 03 )
	NewVersion : New version of the key ( <> 0 )

OUTPUT
	Status	   : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangeKey(%d , %d)",KeyIndex,NewVersion);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(KeyIndex>3)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(KeyIndex<1)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(NewVersion==0)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_ChangeKey(KeyIndex,NewVersion);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangeKey(%d , %d , %02X%02X%02X)",
			KeyIndex,NewVersion,Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_ChangeKeyExt(BYTE KeyIndex, BYTE NewKeyVersion, BYTE TypeCmd, 
													   BYTE KeyIndexEncipher, BYTE ALGTag, BYTE ALGSam, 
													   BYTE NewKeyIndex, sCARD_Status* Status)
/*****************************************************************
Change the key / Personnalization


INPUTS
	KeyIndex			: Index of the key ( 01 - 03 ) (1 byte)
	NewKeyVersion		: New version of the key ( <> 0 ) (1 byte)
	TypeCmd				: type Command (1 byte)
							$00 : short cmd
							$01 : long cmd
	KeyIndexEncipher	: Index of the key to encipher the transfer (1 byte)
	ALGTag				: Algo key card to recopy (1 byte)
	ALGSam				: Algo of the Sam used (1 byte)
	NewKeyIndex			: index of the new key in the card in the DF (1 byte)

OUTPUT
	Status				: Contains the card execution return status (3 bytes)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;						// return value from CSC_SendReceive
	BYTE vBuf[255];					// local temp buffer
	DWORD vLen;						// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangeKeyExt(%d , %d)",KeyIndex,NewKeyVersion);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(KeyIndex>3)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(KeyIndex<1)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(NewKeyVersion==0)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((TypeCmd!=0x00) && (TypeCmd!=0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_ChangeKeyExt(KeyIndex, NewKeyVersion, TypeCmd, KeyIndexEncipher, ALGTag, ALGSam, NewKeyIndex);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangeKeyExt(%d , %d , %02X%02X%02X)",
				KeyIndex,NewKeyVersion,Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_ChangePIN(LPBYTE OldPIN,
								LPBYTE NewPIN,sCARD_Status* Status)
/*****************************************************************
Change the PIN code


INPUTS
	OldPIN	: Old PIN Code ( 4 characters )
	NewPIN	: New PIN Code ( 4 characters )

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangePIN()");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(OldPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(NewPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangePIN(%s , %s )",
			wCSC_BTS(OldPIN,4),vBuf);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_ChangePIN(OldPIN,NewPIN);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangePIN(%s , %s , %02X%02X%02X)",
			wCSC_BTS(OldPIN,4),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_ChangePINExt(BYTE KeyNum, LPBYTE OldPIN, LPBYTE NewPIN, BYTE TypeCmd,
													   BYTE KeyNumKIF, BYTE KVC, BYTE ALG, BYTE SamNum, sCARD_Status* Status)
/*****************************************************************
Change the PIN code


INPUTS
	KeyNum		: Key number (1 byte)
					$00 : CD97, GTML and CT2000,
					$04 : GTML2 and CD21, 
					$09 : POPEYE
	OldPIN		: Old PIN Code (4 bytes)
	NewPIN		: New PIN Code (4 bytes)
	TypeCmd		: type Command (1 byte)
					$00 : short cmd
					$01 : long cmd
	KeyNumKIF	: SAM key number to use (1 byte)
				  or KIF of the key
	KVC			: $00 (if NKEY passed in the previous parameter)(1 byte)
				  or KVC of the Key
	ALG			: Algorithm of the SAM used (1 byte) 
	SamNum		: SAM number (1 byte)
					$00 : default SAM,
					$01, $02, $03 or $04 : logical number of the wanted SAM number


OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;						// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangePINExt()");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(OldPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(NewPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((KeyNum!=0x00) && (KeyNum!=0x04) && (KeyNum!=0x09))return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((TypeCmd!=0x00) && (TypeCmd!=0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(SamNum>0x04)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1){ /* DEBUG */
	strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangePINExt(%s , %s )", wCSC_BTS(OldPIN,4), vBuf);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_ChangePINExt(KeyNum, OldPIN, NewPIN, TypeCmd, KeyNumKIF, KVC, ALG, SamNum);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
		{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1){ /* DEBUG */
		strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
		sprintf_s(tdeb,sizeof(tdeb),"CD97_ChangePINExt(%s , %s , %02X%02X%02X)",
				wCSC_BTS(OldPIN,4),vBuf,
				Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
		}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_Decrease(BYTE AccMode,
											BYTE SID,DWORD Value,
							LPDWORD NewValue,sCARD_Status* Status)
/*****************************************************************
Decrease a counter file value

INPUTS
	AccMode	 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Value	 : Value decreased

OUTPUT
	NewValue : Counter new value ( Out of sessions Mode )
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_Decrease(%d , %d , %d )",AccMode,SID,Value);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Decrease(AccMode,SID,Value);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

if(NewValue!=NULL)
	{
	if(vBuf[1]==5)
		*NewValue = 0;
	else
		*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];	
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_Decrease(%d , %d , %d , %d , %02X%02X%02X)",
			AccMode,SID,Value,(NewValue!=NULL)?*NewValue:0,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_Increase(BYTE AccMode,
											BYTE SID,DWORD Value,
							LPDWORD NewValue,sCARD_Status* Status)
/*****************************************************************
Increase a counter file value

INPUTS
	AccMode	 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Value	 : Value increased

OUTPUT
	NewValue : Counter new value ( Out of sessions Mode )
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_Increase(%d , %d , %d )",AccMode,SID,Value);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Increase(AccMode,SID,Value);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(NewValue!=NULL)
	{
	if(vBuf[1]==5)
		*NewValue = 0;
	else
		*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];
	}
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_Increase(%d , %d , %d , %d , %02X%02X%02X)",
			AccMode,SID,Value,(NewValue!=NULL)?*NewValue:0,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}





/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_Invalidate(BYTE AccMode,
												sCARD_Status* Status)
/*****************************************************************
Invalidate the current DF

INPUTS
	AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_Invalidate(%d)",AccMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Invalidate(AccMode);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_Invalidate(%d , %02X%02X%02X)",
			AccMode,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_Rehabilitate(BYTE AccMode,
												sCARD_Status* Status)
/*****************************************************************
Rehabilitate the current DF

INPUTS
	AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_Rehabilitate(%d)",AccMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Rehabilitate(AccMode);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_Rehabilitate(%d , %02X%02X%02X)",
			AccMode,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_ReadRecord(BYTE AccMode,
									BYTE SID,BYTE NuRec,BYTE DataLen,
									LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Read a record from linear or circular file

INPUTS
	AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		: Short ID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec	: Record number
	DataLen : Number of bytes to be read ( record length )

OUTPUT
	Data	: Data read
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_ReadRecord(%d , %d , %d , %d)",
				AccMode,SID,NuRec,DataLen);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_ReadRecord(AccMode,SID,NuRec,DataLen);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

CopyMemory(Data,&vBuf[7],vBuf[1]-5);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_ReadRecord(%d , %d , %d , %d , %s )",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,vBuf[1]-5));
} /* LOG DEBUG */

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ReadRecord(%d , %d , %d , %d , %s , %02X%02X%02X)",
				AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,vBuf[1]-5),
				Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_SelectFile(BYTE SelectMode,
										LPBYTE IdPath,BYTE IdPathLen,
										LPBYTE FCI,sCARD_Status* Status)
/*****************************************************************
EF or DF select file

INPUTS
	SelectMode : Select Mode :
					CD97_SEL_MF	( Select the Master file )
					CD97_SEL_CURENT_EF ( Select the curent EF ID )
					CD97_SEL_PATH ( the path from MF ( exclude ) )

	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

OUTPUT
	FCI		   : File Control Information ( Length = 23 characters )
	Status	   : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_SelectFile(%d)",SelectMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(IdPath==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_SelectFile(%d , %s , %d)",
			SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_SelectFile(SelectMode,IdPath,IdPathLen);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(FCI!=NULL)
	CopyMemory(FCI,&vBuf[7],vBuf[1]-5);

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_SelectFile(%d , %s , %d, ... ,%02X%02X%02X)",
			SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_StatusFile(BYTE SelectMode,
										LPBYTE IdPath,BYTE IdPathLen,
										LPBYTE FCI,sCARD_Status* Status)
/*****************************************************************
Same as iCD97_SelectFile but only give the file status without
select the file

INPUTS
	SelectMode : Select Mode :
					CD97_SEL_MF	( Select the Master file )
					CD97_SEL_CURENT_EF ( Select the curent EF ID )
					CD97_SEL_PATH ( the path from MF ( exclude ) )

	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

OUTPUT
	FCI		   : File Control Information ( Length = 23 characters )
	Status	   : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_StatusFile(%d)",SelectMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(IdPath==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_StatusFile(%d , %s , %d)",
			SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_StatusFile(SelectMode,IdPath,IdPathLen);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(FCI!=NULL)
	CopyMemory(FCI,&vBuf[7],vBuf[1]-5);

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_StatusFile(%d , %s , %d, ... ,%02X%02X%02X)",
			SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_UpdateRecord(BYTE AccMode,
									BYTE SID,BYTE NuRec,BYTE DataLen,
									LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Erase and write a record to a EF

INPUTS
	AccMode	 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		 : SID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec	 : Record number
	Data     : Data to write
	DataLen  : The size of data to write


OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_UpdateRecord(%d , %d , %d , %d )",
			AccMode,SID,NuRec,DataLen);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_UpdateRecord(%d , %d , %d , %d , %s)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_UpdateRecord(AccMode,SID,NuRec,Data,DataLen);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_UpdateRecord(%d , %d , %d , %d , %s , %02X%02X%02X)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_WriteRecord(BYTE AccMode,
									BYTE SID,BYTE NuRec,BYTE DataLen,
									LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Write a record to a EF

INPUTS
	AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		: SID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec	: Record number
	Data    : Data to write
	DataLen : The size of data to write


OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_WriteRecord(%d , %d , %d , %d )",
			AccMode,SID,NuRec,DataLen);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_WriteRecord(%d , %d , %d , %d , %s)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_WriteRecord(AccMode,SID,NuRec,Data,DataLen);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_WriteRecord(%d , %d , %d , %d , %s , %02X%02X%02X)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_VerifyPIN(LPBYTE PIN,
											sCARD_Status* Status)
/*****************************************************************
PIN verification

INPUTS
	PIN		: PIN code ( 4 characters )


OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_VerifyPIN( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(PIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_VerifyPIN( %s )",wCSC_BTS(PIN,4));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_VerifyPIN(PIN);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_VerifyPIN( %s , %02X%02X%02X)",
			wCSC_BTS(PIN,4),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_VerifyPINExt(BYTE Mode, LPBYTE PIN, BYTE TypeCmd, BYTE KeyNumKIF, 
													   BYTE KVC, BYTE SamNum, sCARD_Status* Status)
/*****************************************************************
PIN verification

INPUTS
	Mode		: Mode (1 byte)
					$00 : consultation of counter of number of incorrect presentations		
					$01 : presentation of PIN
					$02 : presentation of PIN in transparent mode for contact communication
	PIN			: PIN code (4 bytes)
	TypeCmd		: Type Cmd (1 byte)
					$00 : short command (compatibility with the former one)
					$01 : long command
	KeyNumKIF	: SAM key number to use Or KIF of the key (1 byte)
	KVC			: $00 if NKEY passed in the previous parameter or KVC of the Key (1 byte)
	SamNum		: SAM number (1 byte) 
					$00 :	default SAM,
					$01, $02, $03 or $04 : logical number of the wanted SAM number

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_VerifyPINExt( )");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(PIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(Mode>0x02)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((TypeCmd!=0x00) && (TypeCmd!=0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(SamNum>0x04)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_VerifyPINExt( %s )",wCSC_BTS(PIN,4));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_VerifyPINExt(Mode, PIN, TypeCmd, KeyNumKIF, KVC, SamNum);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_VerifyPINExt( %s , %02X%02X%02X)",
				wCSC_BTS(PIN,4),
				Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_Purchase(BYTE Type,
					LPBYTE DataLog,LPBYTE Disp,sCARD_Status* Status)
/*****************************************************************
Purchase with the Electronic Purse ( EP )

INPUTS
	Type	 : Purchase Type :
					- Purchase without display ( 0x00 )
					- Purchase with display    ( 0x01 )
	DataLog  : EP Log record ( 7 bytes )
	Disp	 : Display Message


OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_Purchase( %d )",Type);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(DataLog==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if((Disp==NULL)&&(Type==0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_Purchase( %d , %s )",
	Type,wCSC_BTS(DataLog,7));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Purchase(Type,DataLog,Disp);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_Purchase( %d , %s , %02X%02X%02X )",
			Type,wCSC_BTS(DataLog,7),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_GetEPStatus(BYTE Type,
						LPDWORD EP,LPBYTE Log,sCARD_Status* Status)
/*****************************************************************
Purchase with the Electronic Purse ( EP )

INPUTS
	Type	: Transaction Type :
					- Loading Transaction   (0x00)
					- Purchase Transaction  (0x01)
					- Purchase cancellation (0x02)

OUTPUT
	EP		: Electronic Purse Value

	Log     : if Type = Loading Transaction (0x00)
							 Log = Loading Log Record ( 22 characters )
							 if Type = 0x01 or 0x02
							 Log = Payement Log Record ( 19 characters )

	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_GetEPStatus( %d )",Type);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(EP==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_GetEPStatus(Type);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<8)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// Electonic Purse value
*EP = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_GetEPStatus( %d , %d )",Type,*EP);
} /* LOG DEBUG */

// copy the local buffer to the output log
if(Type==0x00) // Loading transaction
	{
	if(vBuf[1]<30)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Log!=NULL)CopyMemory(Log,&vBuf[10],22);
	}
else  // Purchase transaction
	{
	if(vBuf[1]<27)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Log!=NULL)CopyMemory(Log,&vBuf[10],19);
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_GetEPStatus( %d , %d , %02X%02X%02X )",
			Type,*EP,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}





/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_ReloadEP(LPBYTE ChargLog1,
							LPBYTE ChargLog2,sCARD_Status* Status)
/*****************************************************************
Reload Electronic Purse

INPUTS
	ChargLog1 : Loading Log record ( 5 characters )
				 ( Date, Money batch, Equipment type )

	ChargLog2 : Loading Log record, offset [0x08..0x13]
				 ( 5 characters ) ( Amount, Time )

OUTPUT
	Status	  : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_ReloadEP( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(ChargLog1==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(ChargLog2==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(ChargLog2,5));
sprintf_s(tdeb,sizeof(tdeb),"CD97_ReloadEP(%s , %s)",wCSC_BTS(ChargLog1,5),vBuf);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_ReloadEP(ChargLog1,ChargLog2);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(ChargLog2,5));
	sprintf_s(tdeb,sizeof(tdeb),"CD97_ReloadEP(%s , %s , %02X%02X%02X )",
			wCSC_BTS(ChargLog1,5),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_OpenSession(BYTE Type,
											BYTE SID,BYTE NRec,
					sCARD_Session* Session,sCARD_Status* Status)
/*****************************************************************
Open the secured session

INPUTS
	Type	: Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	SID		: SID Number ( CD97_SID_RT_JOURNAL, ...)
	NRec	: Record number

OUTPUT
	Session : Contains the application data return value
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size
DWORD i;

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_OpenSession( %d , %d , %d )",
		Type,SID,NRec);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_OpenSecuredSession(Type,SID,NRec);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Session!=NULL)
	{
	Session->NbApp=vBuf[7];
	for(i=0;i<(DWORD)vBuf[7];i++)
		{
		Session->Path[i]=(vBuf[(i*2)+8]*256)+vBuf[(i*2)+9];
		}
	CopyMemory(Session->Data,&vBuf[(i*2)+8],29);
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_OpenSession( %d , %d , %d , %02X%02X%02X )",
			Type,SID,NRec,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_OpenSessionExt(BYTE Type, sCARD_SecurParam Secur, BYTE RecNum, BYTE TypeCmd, 
														 BYTE Mode, sCARD_Status* Status, sCARD_Session* Session, BYTE* KVC)
/*****************************************************************
Open the secured session

INPUTS
	Type		: Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	Secur		: Contain the parameters for the security
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	RecNum		: Record number
	TypeCmd		: Type Cmd
					$00 : short command (compatibility with the former one for CD97 and GTML)
					$01 : long command
	Mode		: Mode of operation 
					$00 : simple mode 
					$01 : extended mode

OUTPUT
	Session		: Contains the application data return value
					- NbApp
					- Path[128]
					- Data[29]
					- KVC
	Status		: Contains the card execution return status
	KVC			: KVC in extended mode.

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	DWORD i;

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_OpenSessionExt(%02X,SID:%02X-NKEY:%d-KVC:%02X, %d)",
		Type,Secur.SID,Secur.NKEY,Secur.RFU,RecNum);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// check a good values
	if(Mode>0x01)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((TypeCmd!=0x00) && (TypeCmd!=0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((RecNum!=0x00) && (RecNum!=0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);

	// prepares the command buffer
	iCD97_OpenSecuredSessionExt(Type, Secur.SID, RecNum, TypeCmd, Secur.NKEY, Secur.RFU, Mode);
																	
	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Session!=NULL)
	{
		Session->NbApp=vBuf[7];
		for(i=0;i<(DWORD)vBuf[7];i++)
		{
			Session->Path[i]=(vBuf[(i*2)+8]*256)+vBuf[(i*2)+9];
		}
		CopyMemory(Session->Data,&vBuf[(i*2)+8],29);
	}
	*KVC=vBuf[8+29];

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"CD97_OpenSessionExt(%02X,SID:%02X-NKEY:%d-KVC:%02X, %d, %02X , %02X%02X%02X)",
			Type,Secur.SID,Secur.NKEY,Secur.RFU,RecNum,*KVC,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_CloseSession(LPBYTE Result,
								LPDWORD cbResult,sCARD_Status* Status)
/*****************************************************************
Close the secured session


OUTPUT
	Result	 : Order result
	cbResult : The Result length
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_CloseSession( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_CloseSecuredSession();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

if((cbResult!=NULL)&&(Result!=NULL))
	{
	*cbResult=vBuf[1]-5;
	CopyMemory(Result,&vBuf[7],*cbResult);
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_CloseSession( %02X%02X%02X )",
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_CloseSessionExt(BYTE TypeCmd, BYTE TimeOut, sCARD_Status* Status, 
														  LPDWORD LgResult, LPBYTE Result)
/*****************************************************************
Close the secured session

INPUT
	TypeCmd  : Type Cmd (1 byte)
				$00 : session will be ratified at the reception of the following command
				$80 : session is ratified immediately (except for CD97 and GTML)
				$4A : switches OFF the field if the card doesn’t answer
	TimeOut	 : if TYPE=$4A (1 byte)

OUTPUT
	Status	 : Contains the card execution return status
	LgResult : The Result length (1 byte)
	Result	 : Order result (n bytes)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_CloseSessionExt( TypeCmd : %02X)", TypeCmd);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// check a good values
	if((TypeCmd!=0x00) && (TypeCmd!=0x80) && (TypeCmd!=0x4A))return wCSC_DebugLog(tdeb,RCSC_Fail);

	// prepares the command buffer
	iCD97_CloseSecuredSessionExt(TypeCmd, TimeOut);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	if((LgResult!=NULL)&&(Result!=NULL))
	{
		*LgResult=vBuf[1]-5;
		CopyMemory(Result,&vBuf[7],*LgResult);
	}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_CloseSessionExt( %02X%02X%02X )",
				Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_CancelPurchase(BYTE Type,
									LPBYTE DataLog,LPBYTE Disp,sCARD_Status* Status)
/*****************************************************************
Cancel Purchase with the Electronic Purse ( EP )

INPUTS
	Type	: Purchase Type :
					- Purchase without display ( 0x00 )
					- Purchase with display    ( 0x01 )
	DataLog : EP Log record ( 7 bytes )
	Disp	: Display Message


OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_CancelPurchase( %d )",Type);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(DataLog==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if((Disp==NULL)&&(Type==0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CD97_CancelPurchase( %d , %s )",
	Type,wCSC_BTS(DataLog,7));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_CancelPurchase(Type,DataLog,Disp);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_CancelPurchase( %d , %s , %02X%02X%02X )",
			Type,wCSC_BTS(DataLog,7),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_AbortSecuredSession(sCARD_Status* Status)
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-

OUTPUT
	Status	: Contains the card execution return status (3 Bytes)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_AbortSecuredSession");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_AbortSecuredSession();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_AbortSecuredSession( %02X%02X%02X )", Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CD97_SelectISOApplication(BYTE SelectOption, BYTE Lg, LPBYTE Data, 
															   sCARD_Status* Status, LPBYTE FCI)
/*****************************************************************
Select application using Select File ISO command

INPUTS
	SelectOption :	Select Option (1 byte)
					00 : first application or select by name if LNG <> 0.
					01 : select last application (LNG should be 0)
					02 : select next application (LNG should be 0)
					03 : select previoust application (LNG should be 0)

	Lg			 :	length of data "n" (1 byte)
					0 if Select Option <> 0, otherwise <= 16
	Data		 : Application Name (n bytes)

OUTPUT
	Status	: Contains the card execution return status (3 bytes)
	FCI		: FCI (n bytes) 

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255], i;		// local temp buffer
	DWORD vLen;				// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CD97_SelectISOApplication( %02X )", SelectOption);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(SelectOption>3)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(SelectOption==0)
	{	if(Lg>16)return wCSC_DebugLog(tdeb,RCSC_Fail); }
	else
	{	if(Lg!=0)return wCSC_DebugLog(tdeb,RCSC_Fail);	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_SelectISOApplication(SelectOption, Lg, Data);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CD97_SelectISOApplication( %02X%02X%02X )", Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}
	for (i=0;i<25;i++) FCI[i] = vBuf[i+7];	

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


//** GTML ********************************************************

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_AppendRecord(BYTE AccMode,
									BYTE SID,LPBYTE Rec,BYTE RecSize,
												sCARD_Status* Status)
/*****************************************************************
Add a record to a circular EF


INPUTS
	AccMode	: Card Access Mode
	SID		: Short ID Number
	Rec     : Data to write
	RecSize : The size of data to write

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];					// local temp buffer
DWORD vLen;						// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_AppendRecord(%d , %d)",AccMode,SID);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Rec==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_AppendRecord(%d , %d , %s , %d)",
		AccMode,SID,wCSC_BTS(Rec,RecSize),RecSize);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_AppendRecord(AccMode,SID,Rec,RecSize);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_AppendRecord(%d , %d , %s , %d , %02X%02X%02X)",
			AccMode,SID,wCSC_BTS(Rec,RecSize),RecSize,Status->Code,
			Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_ChangePIN(LPBYTE OldPIN,
								LPBYTE NewPIN,sCARD_Status* Status)
/*****************************************************************
Change the PIN code


INPUTS
	OldPIN : Old PIN Code ( 4 characters )
	NewPIN : New PIN Code ( 4 characters )

OUTPUT
	Status : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_ChangePIN()");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(OldPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(NewPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
sprintf_s(tdeb,sizeof(tdeb),"GTML_ChangePIN(%s , %s )",
			wCSC_BTS(OldPIN,4),vBuf);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_ChangePIN(OldPIN,NewPIN);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
	sprintf_s(tdeb,sizeof(tdeb),"GTML_ChangePIN(%s , %s , %02X%02X%02X)",
			wCSC_BTS(OldPIN,4),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_Decrease(BYTE AccMode,
											BYTE SID,DWORD Value,
							LPDWORD NewValue,sCARD_Status* Status)
/*****************************************************************
Decrease a counter file value

INPUTS
	AccMode  : Card Access Mode
	SID	     : Short ID Number
	Value	 : Value decreased

OUTPUT
	NewValue : Counter new value ( Out of sessions Mode )
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_Decrease(%d , %d , %d )",AccMode,SID,Value);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Decrease(AccMode,SID,Value);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

if(NewValue!=NULL)
	{
	if(vBuf[1]==5)
		*NewValue = 0;
	else
		*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];	
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_Decrease(%d , %d , %d , %d , %02X%02X%02X)",
			AccMode,SID,Value,(NewValue!=NULL)?*NewValue:0,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_Increase(BYTE AccMode,
											BYTE SID,DWORD Value,
							LPDWORD NewValue,sCARD_Status* Status)
/*****************************************************************
Increase a counter file value

INPUTS
	AccMode	 : Card Access Mode
	SID		 : Small ID Number
	Value	 : Value increased

OUTPUT
	NewValue : Counter new value ( Out of sessions Mode )
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_Increase(%d , %d , %d )",AccMode,SID,Value);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Increase(AccMode,SID,Value);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(NewValue!=NULL)
	{
	if(vBuf[1]==5)
		*NewValue = 0;
	else
		*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];
	}
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_Increase(%d , %d , %d , %d , %02X%02X%02X)",
			AccMode,SID,Value,(NewValue!=NULL)?*NewValue:0,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}





/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_Invalidate(BYTE AccMode,
												sCARD_Status* Status)
/*****************************************************************
Invalidate the current DF

INPUTS
	AccMode	: Card Access Mode

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_Invalidate(%d)",AccMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Invalidate(AccMode);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_Invalidate(%d , %02X%02X%02X)",
			AccMode,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_Rehabilitate(BYTE AccMode,
												sCARD_Status* Status)
/*****************************************************************
Rehabilitate the current DF

INPUTS
	AccMode	: Card Access Mode

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_Rehabilitate(%d)",AccMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_Rehabilitate(AccMode);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_Rehabilitate(%d , %02X%02X%02X)",
			AccMode,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_ReadRecord(BYTE AccMode,
									BYTE SID,BYTE NuRec,BYTE DataLen,
									LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Read a record from linear or circular file

INPUTS
	AccMode	: Card Access Mode
	SID		: Short ID Number
	NuRec	: Record number
	DataLen : Number of bytes to be read ( record length )

OUTPUT
	Data			 : Data read
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_ReadRecord(%d , %d , %d , %d)",
				AccMode,SID,NuRec,DataLen);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_ReadRecord(AccMode,SID,NuRec,DataLen);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

CopyMemory(Data,&vBuf[7],vBuf[1]-5);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_ReadRecord(%d , %d , %d , %d , %s )",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,vBuf[1]-5));
} /* LOG DEBUG */

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_ReadRecord(%d , %d , %d , %d , %s , %02X%02X%02X)",
				AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,vBuf[1]-5),
				Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_SelectFile(BYTE SelectMode,
										LPBYTE IdPath,BYTE IdPathLen,
									LPBYTE FCI,sCARD_Status* Status)
/*****************************************************************
EF or DF select file

INPUTS
	SelectMode : Select Mode :
	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

OUTPUT
	FCI		   : File Control Information ( Length = 23 characters )
	Status	   : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_SelectFile(%d)",SelectMode);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(IdPath==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_SelectFile(%d , %s , %d)",
			SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen);
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_SelectFile(SelectMode,IdPath,IdPathLen);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(FCI!=NULL)
	CopyMemory(FCI,&vBuf[7],vBuf[1]-5);

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_SelectFile(%d , %s , %d, ... ,%02X%02X%02X)",
			SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_UpdateRecord(BYTE AccMode,
									BYTE SID,BYTE NuRec,BYTE DataLen,
									LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Erase and write a record to a EF

INPUTS
	AccMode	: Card Access Mode
	SID		: SID Number
	NuRec	: Record number
	Data    : Data to write
	DataLen : The size of data to write


OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_UpdateRecord(%d , %d , %d , %d )",
			AccMode,SID,NuRec,DataLen);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_UpdateRecord(%d , %d , %d , %d , %s)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_UpdateRecord(AccMode,SID,NuRec,Data,DataLen);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_UpdateRecord(%d , %d , %d , %d , %s , %02X%02X%02X)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_WriteRecord(BYTE AccMode,
									BYTE SID,BYTE NuRec,BYTE DataLen,
									LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Write a record to a EF

INPUTS
	AccMode	 : Card Access Mode
	SID		 : SID Number
	NuRec	 : Record number
	Data     : Data to write
	DataLen  : The size of data to write


OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_WriteRecord(%d , %d , %d , %d )",
			AccMode,SID,NuRec,DataLen);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_WriteRecord(%d , %d , %d , %d , %s)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_WriteRecord(AccMode,SID,NuRec,Data,DataLen);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_WriteRecord(%d , %d , %d , %d , %s , %02X%02X%02X)",
			AccMode,SID,NuRec,DataLen,wCSC_BTS(Data,DataLen),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_VerifyPIN(LPBYTE PIN,
											sCARD_Status* Status)
/*****************************************************************
PIN verification

INPUTS
	PIN	    : PIN code ( 4 characters )


OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_VerifyPIN( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(PIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_VerifyPIN( %s )",wCSC_BTS(PIN,4));
} /* LOG DEBUG */

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_VerifyPIN(PIN);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_VerifyPIN( %s , %02X%02X%02X)",
			wCSC_BTS(PIN,4),
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_OpenSession(BYTE Type,
												BYTE SID,BYTE NRec,
						sCARD_Session* Session,sCARD_Status* Status)
/*****************************************************************
Open the secured session

INPUTS
	Type    : Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	SID		: SID Number
	NRec	: Record number

OUTPUT
	Session : Contains the application data return value
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size
DWORD i;

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_OpenSession( %d , %d , %d )",
		Type,SID,NRec);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_OpenSecuredSession(Type,SID,NRec);

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the GTML_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
if(Session!=NULL)
	{
	Session->NbApp=vBuf[7];
	for(i=0;i<(DWORD)vBuf[7];i++)
		{
		Session->Path[i]=(vBuf[(i*2)+8]*256)+vBuf[(i*2)+9];
		}
	CopyMemory(Session->Data,&vBuf[(i*2)+8],29);
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_OpenSession( %d , %d , %d , %02X%02X%02X )",
			Type,SID,NRec,
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_CloseSession(LPBYTE Result,
								LPDWORD cbResult,sCARD_Status* Status)
/*****************************************************************
Close the secured session


OUTPUT
	Result	 : Order result
	cbResult : The Result length
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"GTML_CloseSession( )");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCD97_CloseSecuredSession();

// for GTML command
iCD97_ToGTML();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the GTML_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

if((cbResult!=NULL)&&(Result!=NULL))
	{
	*cbResult=vBuf[1]-5;
	CopyMemory(Result,&vBuf[7],*cbResult);
	}

if(Status!=NULL)
	{
	Status->Code=vBuf[4];
	Status->Byte1=vBuf[5];
	Status->Byte2=vBuf[6];
	
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_CloseSession( %02X%02X%02X )",
			Status->Code,Status->Byte1,Status->Byte2);
	} /* LOG DEBUG */
	}

return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GTML_AbortSecuredSession(sCARD_Status* Status)
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-

OUTPUT
	Status	: Contains the card execution return status (3 Bytes)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GTML_AbortSecuredSession");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_AbortSecuredSession();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"GTML_AbortSecuredSession( %02X%02X%02X )", Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


//** Generic *****************************************************

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI AppendRecord(sCARD_SecurParam Secur,
												  LPBYTE Rec,BYTE RecSize,
												  sCARD_Status* Status)
/*****************************************************************
Add a record to a circular EF


INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	  
	Rec			: Data to write
	RecSize		: The size of data to write

OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"AppendRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %s, %d)"
		,Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
		wCSC_BTS(Rec,RecSize),RecSize);

	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(Rec==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"AppendRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %s, %d)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
		wCSC_BTS(Rec,RecSize),RecSize);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_AppendRecord(Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,Rec,RecSize);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"AppendRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %s, %d, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
			wCSC_BTS(Rec,RecSize),RecSize,Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI ChangeKey(BYTE KeyIndex, BYTE KeyIndexEncipher, BYTE NewKeyVersion, BYTE ALGTag,
											   BYTE ALGSam, BYTE NewKeyIndex, sCARD_Status* Status)
/*****************************************************************
Change the key / Personnalization


INPUTS
	KeyIndex			: Index of the key ( 01 - 03 )
	KeyIndexEncipher	: Index of the key to encipher the transfer
	NewKeyVersion		: New version of the key ( <> 0 )
	ALGTag				: Algo key card to recopy
	ALGSam				: Algo of the Sam used
	NewKeyIndex			: index of the new key in the card in the DF

OUTPUT
	Status				: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;						// return value from CSC_SendReceive
	BYTE vBuf[255];					// local temp buffer
	DWORD vLen;						// The answer frame size

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"ChangeKey(%d , %d)",KeyIndex,NewKeyVersion);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(KeyIndex>3)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(KeyIndex<1)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(NewKeyVersion==0)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iChangeKey(KeyIndex, KeyIndexEncipher, NewKeyVersion, ALGTag, ALGSam, NewKeyIndex);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
		{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"ChangeKey(%d , %d , %02X%02X%02X)",
				KeyIndex,NewKeyVersion,Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
		}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI ChangePIN(sCARD_SecurParam Secur,
											   LPBYTE OldPIN,LPBYTE NewPIN,
											   sCARD_Status* Status)
/*****************************************************************
Change the PIN code


INPUTS
	SecurParam	: Contain the parameters for the security
						- NKEY	  : Number of Key which use in the SAM (in future KIF)
						- RUF	  : Reserved for KVC
	OldPIN		: Old PIN Code ( 4 characters )
	NewPIN		: New PIN Code ( 4 characters )

OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));
	
	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"ChangePIN(NKEY:%d-RFU:%02X, %s, %s)",
				Secur.NKEY,Secur.RFU,wCSC_BTS(OldPIN,4),vBuf);

	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(OldPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(NewPIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
		sprintf_s(tdeb,sizeof(tdeb),"ChangePIN(NKEY:%d-RFU:%02X, %s, %s)",
		Secur.NKEY,Secur.RFU,wCSC_BTS(OldPIN,4),vBuf);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_ChangePIN(OldPIN,NewPIN,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1)
		{ /* DEBUG */
			strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewPIN,4));
			sprintf_s(tdeb,sizeof(tdeb),"ChangePIN( NKEY:%d-RFU:%02X, %s ,%s , %02X%02X%02X)",
			Secur.NKEY,Secur.RFU,wCSC_BTS(OldPIN,4),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI VerifyPIN(sCARD_SecurParam Secur,
											   LPBYTE PIN,
											   sCARD_Status* Status)
/*****************************************************************
PIN verification

INPUTS
	SecurParam	: Contain the parameters for the security
						- NKEY	  : Number of Key which use in the SAM (in future KIF)
							if NKEY=0, presentation in clear mode
						- RUF	  : Reserved for KVC
	PIN			: PIN code ( 4 characters )

OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"VerifyPIN(NKEY:%d-RFU:%02X, %s)",Secur.NKEY,Secur.RFU,wCSC_BTS(PIN,4));

	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(PIN==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"VerifyPIN(NKEY:%d-RFU:%02X, %s)",Secur.NKEY,Secur.RFU,wCSC_BTS(PIN,4));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_VerifyPIN(PIN,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"VerifyPIN(NKEY:%d-RFU:%02X-PIN:%s-STATUS:%02X%02X%02X)",
			Secur.NKEY,Secur.RFU,wCSC_BTS(PIN,4),
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI PINStatus(sCARD_Status* Status)
/*****************************************************************
checks the PIN status

INPUTS
	void

OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"PINStatus()");

	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);


	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"PINStatus()");
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_PINStatus();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"PINStatus(status : %02X%02X%02X)",
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI Increase( sCARD_SecurParam Secur,
											   BYTE ICount,DWORD Value,
											   LPDWORD NewValue,sCARD_Status* Status)
/*****************************************************************
Increase a counter file value

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	Icount		: Index of the counter
	Value		: Value increased

OUTPUT
	NewValue	: Counter new value ( Out of sessions Mode )
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Increase(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %06X)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
		ICount,Value);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_Increase(Secur.AccMode,Secur.SID,Secur.LID,ICount,Value,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(NewValue!=NULL)
	{
		if(vBuf[1]==5)
			*NewValue = 0;
		else
			*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];
	}
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"Increase(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %06X, %06X, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
			Value,(NewValue!=NULL)?*NewValue:0,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI Decrease(sCARD_SecurParam Secur,
											  BYTE ICount,DWORD Value,
											  LPDWORD NewValue,sCARD_Status* Status)
/*****************************************************************
Decrease a counter file value

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	Icount		: Index of the counter
	Value		: Value to decreased

OUTPUT
	NewValue	: Counter new value ( Out of sessions Mode )
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Decrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %06X)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,ICount,Value);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_Decrease(Secur.AccMode,Secur.SID,Secur.LID,ICount,Value,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	if(NewValue!=NULL)
	{
		if(vBuf[1]==5)
			*NewValue = 0;
		else
			*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];	
	}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"Decrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %06X, %06X, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
			Value,(NewValue!=NULL)?*NewValue:0,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI DecreaseLG(sCARD_SecurParam Secur,
											    BYTE ICount,LPBYTE Value,
												sCARD_Status* Status,
											    LPDWORD NewValue)
/*****************************************************************
It is a command for CD97 card only.
Decreases the value contained in a counter file and writes the 5 free data.
Records the associated data.

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	Icount		: Index of the counter
	Value		: Value to decreased(3 bytes, binary number positive or nil) +  5 free bytes


OUTPUT
	Status		: Contains the card execution return status
	NewValue	: Counter new value ( Out of sessions Mode )(3 bytes, binary number signed)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"DecreaseLG(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %08X)",
					Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,ICount,*Value);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_DecreaseLG(Secur.AccMode,Secur.SID,Secur.LID,ICount,Value,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	if(NewValue!=NULL)
	{
		if(vBuf[1]==5)
			*NewValue = 0;
		else
			*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];	
	}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"DecreaseLG(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %06X, %06X, %02X%02X%02X)",
					Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
					*Value,(NewValue!=NULL)?*NewValue:0,
					Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI IncreaseLG(sCARD_SecurParam Secur,
											    BYTE ICount,LPBYTE Value,
												sCARD_Status* Status,
											    LPDWORD NewValue)
/*****************************************************************
It is a command for CD97 card only.
Increases the value contained in a counter file and writes the 5 free data.
Records the associated data.

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	Icount		: Index of the counter
	Value		: Value to decreased(3 bytes, binary number positive or nil) +  5 free bytes


OUTPUT
	NewValue	: Counter new value ( Out of sessions Mode )(3 bytes, binary number signed)
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;				// return value from CSC_SendReceive
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;				// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"IncreaseLG(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %08X)",
					Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,ICount,*Value);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_IncreaseLG(Secur.AccMode,Secur.SID,Secur.LID,ICount,Value,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	if(NewValue!=NULL)
	{
		if(vBuf[1]==5)
			*NewValue = 0;
		else
			*NewValue = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];	
	}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"IncreaseLG(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %06X, %06X, %02X%02X%02X)",
					Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,
					*Value,(NewValue!=NULL)?*NewValue:0,
					Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI Invalidate(sCARD_SecurParam Secur,
												sCARD_Status* Status)
/*****************************************************************
Invalidate the current DF

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Invalidate(AccMode:%d-LID:%04X-NKEY:%d-RFU:%02X)",
		Secur.AccMode,Secur.LID,Secur.NKEY,Secur.RFU);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_Invalidate(Secur.AccMode,Secur.LID,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"Invalidate(AccMode:%02X, LID:%04X, NKEY:%d, RFU:%02X, %02X%02X%02X)",
			Secur.AccMode,Secur.LID,Secur.NKEY,Secur.RFU,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI Rehabilitate(sCARD_SecurParam Secur,
												  sCARD_Status* Status)
/*****************************************************************
Rehabilitate the current DF

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC

OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"Rehabilitate(AccMode%d-LID:%04X-NKEY:%d-RFU:%02X)",
			Secur.AccMode,Secur.LID,Secur.NKEY,Secur.RFU);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_Rehabilitate(Secur.AccMode,Secur.LID,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
		{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Rehabilitate(AccMode:%02X-LID:%04X-NKEY:%d-RFU:%02X, %02X%02X%02X)",
				Secur.AccMode,Secur.LID,Secur.NKEY,Secur.RFU,
				Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
		}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI ReadRecord(sCARD_SecurParam Secur,
												BYTE NuRec,BYTE DataLen,
												LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Read a record from linear or circular file

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NuRec		: Record number
	DataLen		: Number of bytes to be read ( record length )

OUTPUT
	Data		: Data read
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)	
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"ReadRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_ReadRecord(Secur.AccMode,Secur.SID,NuRec,DataLen,Secur.LID,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	
	CopyMemory(Data,&vBuf[7],vBuf[1]-5);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"ReadRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d, %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen,wCSC_BTS(Data,vBuf[1]-5));
	} /* LOG DEBUG */

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];

		if(swDEBUG==1)	
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"ReadRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d, %s, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen,wCSC_BTS(Data,vBuf[1]-5),
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI SelectFile(BYTE SelectMode,
												LPBYTE IdPath,BYTE IdPathLen,
												LPBYTE FCI,sCARD_Status* Status)
/*****************************************************************
EF or DF select file

INPUTS
	SelectMode : Select Mode :
					GEN_SEL_MF	( Select the Master file )
					GEN_SEL_CURENT_EF ( Select the curent EF ID )
					GEN_SEL_PATH ( the path from MF ( exclude ) )

	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

OUTPUT
	FCI		   : File Control Information ( Length = 23 characters )
	Status	   : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"SelectFile(%d)",SelectMode);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(IdPath==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"SelectFile(%d, %s, %d)",
		SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_SelectFile(SelectMode,IdPath,IdPathLen);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(FCI!=NULL)
		CopyMemory(FCI,&vBuf[7],vBuf[1]-5);

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		if(swDEBUG==1)
		{ /* DEBUG */
			if(FCI!=NULL)
			{
				vLen=vBuf[1]-5;
				strcpy_s(vBuf,sizeof(vBuf),(wCSC_BTS(FCI,vLen)));
				sprintf_s(tdeb,sizeof(tdeb),"SelectFile(%d, %s, %d, %s, %02X%02X%02X)",
				SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,vBuf,
				Status->Code,Status->Byte1,Status->Byte2);
			}
			else
			{
				sprintf_s(tdeb,sizeof(tdeb),"SelectFile(%d, %s, %d, ..., %02X%02X%02X)",
				SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,
				Status->Code,Status->Byte1,Status->Byte2);
			}
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI StatusFile(BYTE SelectMode,
												LPBYTE IdPath,BYTE IdPathLen,
												LPBYTE FCI,sCARD_Status* Status)
/*****************************************************************
Same as SelectFile but only give the file status without
select the file

INPUTS
	SelectMode : Select Mode :
					GEN_SEL_MF	( Select the Master file )
					GEN_SEL_CURENT_EF ( Select the curent EF ID )
					GEN_SEL_PATH ( the path from MF ( exclude ) )

	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

OUTPUT
	FCI		   : File Control Information ( Length = 23 characters )
	Status	   : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"StatusFile(%d)",SelectMode);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(IdPath==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"StatusFile(%d , %s , %d)",
		SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_StatusFile(SelectMode,IdPath,IdPathLen);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(FCI!=NULL)
		CopyMemory(FCI,&vBuf[7],vBuf[1]-5);

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			if(FCI!=NULL)
			{
				vLen=vBuf[1]-5;
				strcpy_s(vBuf,sizeof(vBuf),(wCSC_BTS(FCI,vLen)));
				sprintf_s(tdeb,sizeof(tdeb),"SelectFile(%d, %s, %d, %s, %02X%02X%02X)",
				SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,vBuf,
				Status->Code,Status->Byte1,Status->Byte2);
			}
			else
			{
				sprintf_s(tdeb,sizeof(tdeb),"StatusFile(%d , %s , %d, ... ,%02X%02X%02X)",
				SelectMode,wCSC_BTS(IdPath,IdPathLen),IdPathLen,
				Status->Code,Status->Byte1,Status->Byte2);
			}
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI UpdateRecord(sCARD_SecurParam Secur,
												  BYTE NuRec,BYTE DataLen,
												  LPBYTE Data,sCARD_Status* Status)
/*****************************************************************
Erase and write a record to a EF

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NuRec		: Record number
	Data		: Data to write
	DataLen		: The size of data to write


OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"UpdateRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"UpdateRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d, %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen,wCSC_BTS(Data,DataLen));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_UpdateRecord(Secur.AccMode,Secur.SID,NuRec,Data,DataLen,Secur.LID,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"UpdateRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d, %s, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen,wCSC_BTS(Data,DataLen),
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI WriteRecord(sCARD_SecurParam Secur,
												 BYTE NuRec,BYTE DataLen,LPBYTE Data,
												 sCARD_Status* Status)
/*****************************************************************
Write a record to a EF

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NuRec		: Record number
	DataLen		: The size of data to write
	Data		: Data to write


OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"WriteRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %d)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"WriteRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d , %d , %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen,wCSC_BTS(Data,DataLen));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_WriteRecord(Secur.AccMode,Secur.SID,NuRec,Data,DataLen,Secur.LID,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"WriteRecord(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d , %d , %s , %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NuRec,DataLen,wCSC_BTS(Data,DataLen),
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GetEPStatus_CD97(sCARD_SecurParam Secur,BYTE Type,
													  LPDWORD EP,LPBYTE Log,sCARD_Status* Status)
/*****************************************************************
Purchase with the Electronic Purse ( EP )

INPUTS
	SecurParam	: Contain the parameters for the security
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC

  Type			: Transaction Type :
					- Loading Transaction   (0x00)
					- Purchase Transaction  (0x01)
					- Purchase cancellation (0x02)

OUTPUT
	EP			: Electronic Purse Value

	Log		    : if Type = Loading Transaction (0x00)
							 Log = Loading Log Record ( 22 characters )
							 if Type = 0x01 or 0x02
							 Log = Payement Log Record ( 19 characters )

	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"GetEPStatus_CD97(NKEY:%d-RFU:%02X-Type:%02X)",Secur.NKEY,Secur.RFU,Type);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(EP==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_GetEPStatus(Type,Secur.NKEY,Secur.RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<8)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	// Electonic Purse value
	*EP = (vBuf[7]*65536)+(vBuf[8]*256)+vBuf[9];

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"GetEPStatus_CD97(NKEY:%d-RFU:%02X, Type:%02X, EP:%d)",Secur.NKEY,Secur.RFU,Type,*EP);
	} /* LOG DEBUG */

	// copy the local buffer to the output log
	if(Type==0x00) // Loading transaction
		{
		if(vBuf[1]<30)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
		if(Log!=NULL)CopyMemory(Log,&vBuf[10],22);
		}
	else  // Purchase transaction
		{
		if(vBuf[1]<27)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
		if(Log!=NULL)CopyMemory(Log,&vBuf[10],19);
		}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"GetEPStatus_CD97(NKEY:%d-RFU:%02X, Type:%02X, EP:%d, Status:%02X%02X%02X)",
			Secur.NKEY,Secur.RFU,Type,*EP,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI Purchase_CD97(BYTE Type,
					LPBYTE DataLog,LPBYTE Disp,sCARD_Status* Status)
/*****************************************************************
Purchase with the Electronic Purse ( EP )

INPUTS
	Type	 : Purchase Type :
					- Purchase without display ( 0x00 )
					- Purchase with display    ( 0x01 )
	DataLog  : EP Log record ( 7 bytes )
	Disp	 : Display Message


OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Purchase_CD97(%d)",Type);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(DataLog==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((Disp==NULL)&&(Type==0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Purchase_CD97(%d, %s)",
		Type,wCSC_BTS(DataLog,7));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_Purchase(Type,DataLog,Disp);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);
	

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"Purchase_CD97(%d, %s, %02X%02X%02X)",
			Type,wCSC_BTS(DataLog,7),
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CancelPurchase_CD97(BYTE Type,
									LPBYTE DataLog,LPBYTE Disp,sCARD_Status* Status)
/*****************************************************************
Cancel Purchase with the Electronic Purse ( EP )

INPUTS
	Type	: Purchase Type :
					- Purchase without display ( 0x00 )
					- Purchase with display    ( 0x01 )
	DataLog : EP Log record ( 7 bytes )
	Disp	: Display Message


OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CancelPurchase_CD97(%d)",Type);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(DataLog==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if((Disp==NULL)&&(Type==0x01))return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CancelPurchase_CD97(%d, %s)",
		Type,wCSC_BTS(DataLog,7));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_CancelPurchase(Type,DataLog,Disp);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the CD97_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"CancelPurchase_CD97(%d, %s, %02X%02X%02X)",
			Type,wCSC_BTS(DataLog,7),
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI ReloadEP_CD97(LPBYTE ChargLog1,
												   LPBYTE ChargLog2,
												   sCARD_Status* Status)
/*****************************************************************
Reload Electronic Purse

INPUTS
	ChargLog1 : Loading Log record ( 5 characters )
				 ( Date, Money batch, Equipment type )

	ChargLog2 : Loading Log record, offset [0x08..0x13]
				 ( 5 characters ) ( Amount, Time )

OUTPUT
	Status	  : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"ReloadEP_CD97()");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(ChargLog1==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	if(ChargLog2==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(ChargLog2,5));
		sprintf_s(tdeb,sizeof(tdeb),"ReloadEP_CD97(%s , %s)",wCSC_BTS(ChargLog1,5),vBuf);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_ReloadEP(ChargLog1,ChargLog2);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]!=5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(ChargLog2,5));
			sprintf_s(tdeb,sizeof(tdeb),"ReloadEP_CD97(%s , %s , %02X%02X%02X)",
			wCSC_BTS(ChargLog1,5),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI OpenSession(BYTE Type,
												 sCARD_SecurParam Secur,
												 BYTE NRec,
												 sCARD_Session* Session,
												 sCARD_Status* Status)
/*****************************************************************
Open the secured session

INPUTS
	Type		: Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	SecurParam	: Contain the parameters for the security
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NRec		: Record number

OUTPUT
	Session		: Contains the application data return value
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	DWORD i;

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"OpenSession(%02X,SID:%02X-NKEY:%d-RFU:%02X, %d, %d)",
		Type,Secur.SID,Secur.NKEY,Secur.RFU,Type,NRec);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_OpenSecuredSession(Type,Secur.SID,NRec,Secur.NKEY,Secur.RFU,0);
																	//Standard Mode 

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Session!=NULL)
	{
		Session->NbApp=vBuf[7];
		for(i=0;i<(DWORD)vBuf[7];i++)
			{
			Session->Path[i]=(vBuf[(i*2)+8]*256)+vBuf[(i*2)+9];
			}
		CopyMemory(Session->Data,&vBuf[(i*2)+8],29);
	}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"OpenSession(%02X,SID:%02X-NKEY:%d-RFU:%02X, %d, %d , %02X%02X%02X)",
			Type,Secur.SID,Secur.NKEY,Secur.RFU,Type,NRec,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI OpenSessionExt(BYTE Type,
													sCARD_SecurParam Secur,
													BYTE NRec,BYTE* KVC,
													sCARD_Session* Session,
													sCARD_Status* Status)
/*****************************************************************
Open the secured session

INPUTS
	Type		: Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	SecurParam	: Contain the parameters for the security
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NRec		: Record number

OUTPUT
	Session		: Contains the application data return value
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	DWORD i;

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"OpenSessionExt(%02X,SID:%02X-NKEY:%d-RFU:%02X, %d)",
		Type,Secur.SID,Secur.NKEY,Secur.RFU,NRec);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_OpenSecuredSession(Type,Secur.SID,NRec,Secur.NKEY,Secur.RFU,1);
																	// Extended Mode
	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Session!=NULL)
	{
		Session->NbApp=vBuf[7];
		for(i=0;i<(DWORD)vBuf[7];i++)
			{
			Session->Path[i]=(vBuf[(i*2)+8]*256)+vBuf[(i*2)+9];
			}
		CopyMemory(Session->Data,&vBuf[(i*2)+8],29);
	}
	*KVC=vBuf[8+29];

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"OpenSessionExt(%02X,SID:%02X-NKEY:%d-RFU:%02X, %d, %02X , %02X%02X%02X)",
			Type,Secur.SID,Secur.NKEY,Secur.RFU,NRec,*KVC,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CloseSession(LPBYTE Result,
												  LPDWORD cbResult,
												  sCARD_Status* Status)
/*****************************************************************
Close the secured session


OUTPUT
	Result	 : Order result
	cbResult : The Result length
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CloseSession()");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_CloseSecuredSession();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	if((cbResult!=NULL)&&(Result!=NULL))
	{
		*cbResult=vBuf[1]-5;
		CopyMemory(Result,&vBuf[7],*cbResult);
	}

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"CloseSession(%02X%02X%02X)",
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI AbortSecuredSession(sCARD_Status* Status)
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-

OUTPUT
	Status	: Contains the card execution return status (3 Bytes)

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"AbortSecuredSession()");
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iCD97_AbortSecuredSession();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"AbortSecuredSession(%02X%02X%02X)",
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI Lock_Unlock(BYTE Type,
												 sCARD_Status* Status)
/*****************************************************************
Lock or unlock the card

INPUTS
	Type		: Operation Type
					- Lock the card (0x00)
					- Unlock the card (0x01)

OUTPUT
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Lock_Unlock(%02X)",Type);
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_Lock_Unlock(Type);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"Lock_Unlock(%02X, %02X%02X%02X)",
			Type,Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI MultiIncrease( sCARD_SecurParam Secur,
													BYTE NumberCpt,LPBYTE Data,
													LPBYTE NewData,
													sCARD_Status* Status)
/*****************************************************************
Increase several counters file value

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NumberCpt	: Number of counters to increase
	Data		: Values to increase (Lng=NumberCpt*4).
				  NumberCpt*Bloc :
						- Byte1		: Number of counter
						- Byte2-4	: Value to increase

OUTPUT
	NewData		: New value of the counters (Lng=NumberCpt*4).
				  NumberCpt*Bloc :
						- Byte1		: Number of counter
						- Byte2-4	: Value to increase
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"MultiIncrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,wCSC_BTS(Data,(NumberCpt*4)));
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(Data==NULL||NewData==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"MultiIncrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,wCSC_BTS(Data,(NumberCpt*4)));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_MultiIncrease(Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,Data);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	CopyMemory(NewData,&vBuf[7],vBuf[1]-5);	
	
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewData,(NumberCpt*4)));
			sprintf_s(tdeb,sizeof(tdeb),"MultiIncrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %s, %s, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,wCSC_BTS(Data,(NumberCpt*4)),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI MultiDecrease( sCARD_SecurParam Secur,
													BYTE NumberCpt,LPBYTE Data,
													LPBYTE NewData,
													sCARD_Status* Status)
/*****************************************************************
Decrease several counters file value

INPUTS
	SecurParam	: Contain the parameters for the security
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
	NumberCpt	: Number of counters to decrease
	Data		: Values to decrease (Lng=NumberCpt*4).
				  NumberCpt*Bloc :
						- Byte1		: Number of counter
						- Byte2-4	: Value to decrease

OUTPUT
	NewData		: New value of the counters (Lng=NumberCpt*4).
				  NumberCpt*Bloc :
						- Byte1		: Number of counter
						- Byte2-4	: Value to decrease
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	ZeroMemory(vBuf,sizeof(vBuf));

	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"Multidecrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,wCSC_BTS(Data,(NumberCpt*4)));
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check a good values
	if(Data==NULL||NewData==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
	
	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"MultiDecrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %s)",
		Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,wCSC_BTS(Data,(NumberCpt*4)));
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer
	iGEN_MultiDecrease(Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,Data);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Card_Status
	if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	CopyMemory(NewData,&vBuf[7],vBuf[1]-5);	
	
	if(Status!=NULL)
	{
		Status->Code=vBuf[4];
		Status->Byte1=vBuf[5];
		Status->Byte2=vBuf[6];
		
		if(swDEBUG==1)
		{ /* DEBUG */
			strcpy_s(vBuf,sizeof(vBuf),wCSC_BTS(NewData,(NumberCpt*4)));
			sprintf_s(tdeb,sizeof(tdeb),"MultiDecrease(AccMode:%02X-SID:%02X-LID:%04X-NKEY:%d-RFU:%02X, %d, %s, %s, %02X%02X%02X)",
			Secur.AccMode,Secur.SID,Secur.LID,Secur.NKEY,Secur.RFU,NumberCpt,wCSC_BTS(Data,(NumberCpt*4)),vBuf,
			Status->Code,Status->Byte1,Status->Byte2);
		} /* LOG DEBUG */
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx_Active (LPBYTE Data,BYTE* Status)
/*****************************************************************
Active CTx ticket

INPUTS
	Nothing
OUTPUTS
	Data	: Data read
	Status	: Contains the CTS execution return status


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CTx_Active");
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)		return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a activeCTx command
iCTx_Active();

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)	return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the Status and Data
if(vBuf[1]<4)		return wCSC_DebugLog(tdeb,RCSC_DataWrong);

CopyMemory(Data,&vBuf[6],vBuf[1]-4);
*Status = vBuf[5];
	
if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx_Active(Status:%02X-DATA:%s)",
			vBuf[5],wCSC_BTS(Data,vBuf[1]-4) );

} /* LOG DEBUG */
return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx_Read (BYTE ADD, BYTE NB,
												  LPBYTE Data,BYTE* Status)
/*****************************************************************
Read CTx ticket

INPUTS
	ADD		: adress of the first read (0 ... 31)
	NB		: Number of bytes to be read (from 1 up to 32)

OUTPUT
	Data	: Data read
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;						// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx_Read(%d , %d )", ADD, NB);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCTx_Read(ADD, NB);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the CD97_Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

CopyMemory(Data,&vBuf[6],vBuf[1]-4);
*Status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CTx_Read(%d , %d , %s )",
			ADD, NB,wCSC_BTS(Data,vBuf[1]-4));
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx_Update (BYTE ADD, BYTE NB,
												  LPBYTE DataToWrite,LPBYTE DataInCTS,
												  LPBYTE Data, BYTE* Status)

/*****************************************************************
Update CTx ticket

INPUTS
	ADD			: adress of the first byte to write (0 ... 31)
	NB			: Number of bytes to be written (from 1 up to 32)
	Data		: Data to write
	DataInCTS	: Data already read and store in CTS application
OUTPUT
	Data	: Data read
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx_Update(%d , %d )", ADD, NB);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check a good values
if(Data==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer
iCTx_Update(ADD, NB, DataToWrite, DataInCTS);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the Status
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

CopyMemory(Data,&vBuf[6],vBuf[1]-4);
*Status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx_Update(%d , %d , %s, %s )",
			ADD, NB, wCSC_BTS(Status,1), wCSC_BTS(Data,vBuf[1]-4));
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx_Release (BYTE Param, BYTE* Status)
/*****************************************************************
Release CTx ticket

INPUTS
	Param
OUTPUTS
	Status	: Contains the CTx execution return status


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx_Release(%d)", Param);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a activeCTS command
iCTx_Release(Param);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the Status 
if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

*Status = vBuf[4];
	
if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx_Release(Status: %s )", wCSC_BTS(Status,1));
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CheckCertificate (BYTE KeyType, BYTE Param,
									BYTE LngBuffer, LPBYTE Buffer,
									BYTE LngCertificat, LPBYTE Certificat,
									BYTE *Status )
/*****************************************************************
Check Certificate

INPUTS
	KeyType
	Param	(RFU)
	LngBuffer
	Buffer
	LngCertificat
	Certificat
OUTPUTS
	Status	: Contains the CTS execution return status


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CheckCertificate(KeyType: %02X-Param: %02X-Buffer: %s-Certificat: %s)", 
		KeyType, Param, wCSC_BTS(Buffer,LngBuffer), wCSC_BTS(Certificat,LngCertificat));
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a CheckCertificate command
iGEN_CheckCertificate( KeyType, Param, LngBuffer, Buffer, LngCertificat, Certificat);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the Status 
if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

*Status = vBuf[4];
	
if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CheckCertificate(Status: %s )", wCSC_BTS(Status,1));
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI GiveCertificate (BYTE KeyType, BYTE Param,
									BYTE LngBuffer, LPBYTE Buffer,
									BYTE LngCertificat, LPBYTE Certificat,
									BYTE *Status )
/*****************************************************************
Give Certificate

INPUTS
	KeyType
	Param	(RFU)
	LngBuffer
	Buffer
	LngCertificat
OUTPUTS
	Status	: Contains the CTS execution return status
	Certificat


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"GiveCertificate(KeyType: %02X-Param: %02X-Buffer: %s-LngCertificat: %02X)", 
		KeyType, Param, wCSC_BTS(Buffer,LngBuffer), LngCertificat);
} /* LOG DEBUG */

// CSC_Open no executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for a GiveCertificate command
iGEN_GiveCertificate( KeyType, Param, LngBuffer, Buffer, LngCertificat);

// Send a command frame to the CSC, and waits 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// copy the local buffer to the Status 
if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

CopyMemory(Certificat,&vBuf[5],vBuf[1]-3);
*Status = vBuf[4];
	
if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CheckCertificate(Status: %s - Cerificat: %s )", 
		wCSC_BTS(Status,1), wCSC_BTS(Certificat,vBuf[1]-3));
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);

}




/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ChangeRS485Address(BYTE CSCAddress485)
/*****************************************************************
Change the mode of protocol to CSC RS485 and set the Address value 

INPUTS
	CSCAddress485 : Address of the CSC on the RS485 Bus
	
OUTPUT

RETURNS
	RCSC_InputDataWrong		Bad Address Value go back to mode RS232
	RCSC_Ok					Good value
*****************************************************************/
{
	if(swDEBUG==1)
	{ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CSC_ChangeRS485Address(Address : %02X)", CSCAddress485);
	} /* LOG DEBUG */

	if(CSCAddress485>0x0F) 
	{
		if(swDEBUG==1)
		{ /* DEBUG */
			sprintf_s(tdeb,sizeof(tdeb),"Failed : Address not changed (mode RS232) ");
		} /* LOG DEBUG */


		giCSCMode485 = FALSE;
		giCSCNumber485= 0;		
		return RCSC_InputDataWrong;
	}

	giCSCMode485 = TRUE;
	giCSCNumber485= CSCAddress485;
	return RCSC_Ok;
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ChangeDLLSpeed(DWORD DLLSpeed)
/*****************************************************************
Change the PC communication port baud rate and the CSC baud rate

INPUTS
  DLLSpeed :	New baud rate
  
OUTPUTS
  Status

RETURNS
	RCSC_Ok					Good execution
	RCSC_OpenCOMError		Fail in opening com port
	RCSC_InputDataWrong		Speed out of limit 9600-MAX_BAUDRATE
*****************************************************************/
{

	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_ChangeDLLSpeed( %d )",DLLSpeed);
	} /* LOG DEBUG */

	// Check input values
	if ( DLLSpeed <9600 )		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( DLLSpeed >MAX_BAUDRATE )		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	ComSpeed = DLLSpeed;	// set new Windows DLL speed

	//CSC_Close();	

	//if (CSC_SearchCSC() != RCSC_Ok)
	//	return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SetTimings(DWORD func_timeout,
													DWORD search_timeout,
													DWORD RFU)
/*****************************************************************
Change the global timings values

INPUTS
  func_timeout		: timeout in CSC_SendReceive for DLL functions
  search_timeout	: timeout in CSC_SendReceive in CSC_SearchCard
						and CSC_SearchCardExt
  RFU				: RFU
  
OUTPUTS
  void

RETURNS
	RCSC_Ok					Good execution
*****************************************************************/
{
	if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CSC_SetTimings( %d,%d,%d )",func_timeout,search_timeout,RFU);
	} /* LOG DEBUG */

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// Set new values
	FuncTimeout = func_timeout;
	SearchTimeout = search_timeout;


	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ChangeCSCSpeed(DWORD RS232Speed, 
								DWORD RS485Speed, DWORD TTLSpeed, BYTE *Status)
/*****************************************************************
Send the Change Speed Command that change the CSC divisor for baud rate 
in EEPROM. This command will take effect only after a reset of the CSC.

INPUTS
  RS232Speed	:	Baud Rate choosen for the RS232 link (see microswitch configuration)
  RS485Speed	:	Baud Rate choosen for the RS485 link (see microswitch configuration)
  TTLSpeed		:	Baud Rate choosen for the serial TTL link (see microswitch configuration)
  
OUTPUTS
  Status :		Status of the operation (see CSC Interface documentation)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_ChangeCSCSpeed(RS232 Speed : %d RS485 Speed : %d TTL Speed : %d)", RS232Speed, RS485Speed, TTLSpeed );	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( RS232Speed <9600 ) || ( RS485Speed <9600 ) || ( TTLSpeed <9600 ) ) 		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if (( RS232Speed >MAX_BAUDRATE  ) || ( RS485Speed >MAX_BAUDRATE  ) || ( TTLSpeed >MAX_BAUDRATE  ) ) 		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}


	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_ChangeCSCSpeed((unsigned char) (1382400/RS232Speed), (unsigned char) (1382400/RS485Speed), (unsigned char) (1382400/TTLSpeed));

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[4];
	
	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_ChangeCSCSpeed(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SelectCID(BYTE CID, BYTE *Status)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	CID :		Index from 1 to 15 of the ISO14443 Card communication channel
OUTPUTS
	Status :	Status of operation 1 = Ok, 0 = Nok (Bad CID value)
RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
	RCSC_InputDataWrong
  
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_SelectCID(CID : %d )", CID );	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( CID == 0 ) || ( CID >15 ) ) 		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_SelectCID(CID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[4];
	
	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_SelectCID(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SelectDIV(BYTE Slot, BYTE Prot, 
												   BYTE *DIV, BYTE *Status)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Slot :	Slot of the SAM
  Prot :	0 for Innovatron, 1 for ISO7816
  DIV :		4 bytes serial number used for alg diversification
OUTPUTS
	Status :	Status of operation 1 = Ok, 0 = Nok (Bad CID value)
RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
	RCSC_InputDataWrong
  
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"iCSC_SelectDIV(Slot : %d, Prot : %d, DIV : %02x%02x%02x%02x )", Slot, Prot, DIV[0], DIV[1], DIV[2], DIV[3] );	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( Slot > 3 ) || ( Prot > 1 ) ) 		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_SelectDIV(Slot, Prot, DIV);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[4];
	
	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_SelectDIV(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_EHP_PARAMS(BYTE MaxNbCard, BYTE Req, BYTE NbSlot, 
													BYTE AFI, BYTE AutoSelDiv)
/*****************************************************************
Update the global buffer for the SendReceive command.
INPUTS
	MaxNbCard	 1 byte : Max number of card to look for
	Req :		 1 byte : 0 for ReqB / 1 for WupB
	NbSlot :	 1 byte : 0 for not the time slot method
	AFI  :		 1 byte : 0 for all ( default value )
	AutoSelDiv : 1 byte : 1 if yes ( default value )
OUTPUTS
	None 
RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
	RCSC_InputDataWrong  
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_EHP_PARAMS(MaxNbCard : %d, Req : %d, NbSlot : %02x, AFI : %02x, AutoSelDiv : %02x )", MaxNbCard, Req, NbSlot, AFI, AutoSelDiv );	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( MaxNbCard > 10 ) || ( Req > 1 ) || ( NbSlot > 15 ) || ( AutoSelDiv > 1 )) 		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_EHP_PARAMS(MaxNbCard, Req, NbSlot, AFI, AutoSelDiv);

		// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_EHP_PARAMS_EXT(BYTE MaxNbCard, BYTE Req, BYTE NbSlot, BYTE AFI, BYTE AutoSelDiv, 
														BYTE Deselect, BYTE SelectAppli, BYTE Lg, LPBYTE Data, 
														WORD FelicaAFI, BYTE FelicaNbSlot)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	MaxNbCard		: Max number of card to look for (1 byte)
	Req 			: 0 for ReqB / 1 for WupB (1 byte)
	NbSlot 			: 0 for not the time slot method (1 byte)
	AFI  			: 0 for all ( default value ) (1 byte)
	AutoSelDiv		: 1 if yes ( default value ) (1 byte)
	Deselect		: 0 switch field off / 1 real deselection of the found cards (1 byte)
	SelectAppli		: $000xxxx1 send select appli to card after detection (1 byte)
					  $000xxx1x force to $00 (instead of $94) the select appli "CLA" field
					  $000x1xxx add selected appli name in the EnterHuntPhase answer
    Lg				: Optional data Length "n" (1 byte)
	Data			: Optional name of the appli to select( default value is "1TIC" ) (n byte)
	FelicaAFI		: Card function identifier ( default is all cards = $FFFF ) (2 byte)
	FelicaNbSlot	: Slot Number for Felica Anticollision ( default value = 3 ) (1 byte)

OUTPUTS
	- 

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
	RCSC_InputDataWrong  
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"CSC_EHP_PARAMS(MaxNbCard : %d, Req : %d, NbSlot : %02x, AFI : %02x, AutoSelDiv : %02x )", MaxNbCard, Req, NbSlot, AFI, AutoSelDiv );	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( MaxNbCard > 10 ) || ( Req > 1 ) || ( NbSlot > 15 ) || ( AutoSelDiv > 1 ) || ( Deselect > 1 )) 		
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iCSC_EHP_PARAMS_EXT(MaxNbCard, Req, NbSlot, AFI, AutoSelDiv, Deselect, 
						SelectAppli, Lg, Data, FelicaAFI, FelicaNbSlot);

		// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_LoadReaderKeyIndex(BYTE KeyIndex, LPBYTE KeyVal, 
															   BYTE *Status)
/*****************************************************************
Load a MIFARE Key in one of the 32 locations of the Reader in EEPROM
that will be used by their Index for the Cryptographic operation by 
the Crypto Module.

INPUTS
  KeyIndex :	Index from 0 to 31 of the key to load in the Reader
  KeyVal :		Value of the key (6 bytes LSB First)
  
OUTPUTS
  Status :		Status of the operation (see CSC Interface documentation)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_LoadReaderKeyIndex(KeyIndex : %02X)", KeyIndex);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
      if ((KeyIndex >31 ) && (KeyIndex != 0xFF))
      	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_LoadReaderKeyIndex( KeyIndex, KeyVal);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_LoadReaderKeyIndex(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_ChangeKey(BYTE InitialKeyAorB, BYTE NumSector, 
							  BYTE InitialKeyIndex, BYTE FinalKeyAorB, 
							  LPBYTE NewKeyA, LPBYTE NewAccessBits, 
							  LPBYTE NewKeyB, LPBYTE MifareType, 
							  LPBYTE SerialNumber, BYTE *Status)
/*****************************************************************
Change a MIFARE Key in the card : 
* Realise the authentication of the sector with the key indexed by the initialKey specified
* Change the trailer block by a write operation with control made on the Access bits
* And then realise the finale authentication of the sector with the new keys

INPUTS
	InitialKeyAorB	:	Choice of the key needed for authentication before key change operation
	NumSector		:	Sector on which the ChangeKey operation need to be performed
	InitialKeyIndex :	Index from 0 to 31 of the Reader key used for initial authentication
	FinalKeyAorB	:	Choice of the key needed for authentication after key change operation  
	NewKeyA			:	(6 Bytes) New value for the A Key (Be Carefull it must be coded MSB first)
	NewAccessBits	:	(4 Bytes) New value for Access bits area
	NewKeyB			:	(6 Bytes) New value for the B Key (Be Carefull it must be coded MSB first) 
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	MifareType		:	Type of the card authenticated (08 for Mifare Classic) 
	SerialNumber	:	(4 Bytes) Serial Number of the card authenticated 

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ChangeKey(NumSector : %02X)", NumSector);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( InitialKeyAorB < 0x0A ) || ( InitialKeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if (( FinalKeyAorB < 0x0A ) || ( FinalKeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( InitialKeyIndex >31 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( NumSector > 39 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}



	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_ChangeKey( InitialKeyAorB, NumSector, InitialKeyIndex, FinalKeyAorB, 
							  NewKeyA, NewAccessBits, NewKeyB);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	*MifareType = vBuf[6];
	for (i=0; i<4; i++) SerialNumber[i] = vBuf[i+7];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ChangeKey(Status: %s, Type : %02x, NumSerie :  %02x %02x %02x %02x)", wCSC_BTS(Status,1), *MifareType, SerialNumber[0], SerialNumber[1], SerialNumber[2], SerialNumber[3]);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_Select(BYTE* SerialNumber,
												   BYTE  SerialNumberLn,
												   BYTE* Status,
												   BYTE* SerialNumberOut)
/*****************************************************************
Selects a MIFARE card with its unique ID. Allows to detect a card in case of collision.

INPUTS
	SerialNumber	:	Buffer containing the serial Number of teh card to select
	SerialNumberLn	:	Length of the serial number
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	SerialNumberOut	:	Buffer containing the serial Number of the card selected

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer and temporary index
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Select(serialNumber : %s)",
								wCSC_BTS(SerialNumber,SerialNumberLn));	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// check input buffer
	if(SerialNumber==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_Select( SerialNumber , SerialNumberLn);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=lng
	vBuf[5]=Status
	vBuf[6]=code $08
	vBuf[7]=serialNumber
		...
	vBuf[serialNumberLn+6]=serialNumber
	vBuf[serialNumberLn+7]=EOF
	vBuf[serialNumberLn+8]=CRCL
	vBuf[serialNumberLn+9]=CRCH
*/
	
	
	// copy the local buffer to the Status and SerialNumberOut 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	for (i=0;i<SerialNumberLn;i++) SerialNumberOut[i] = vBuf[i+7];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Select(serialNumber: %s / Status: %02X - serialNumberOut: %s)",
									wCSC_BTS(SerialNumber,SerialNumberLn), *Status, wCSC_BTS(SerialNumberOut,SerialNumberLn));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_Detect(BYTE *Status, BYTE *Code, LPBYTE PiccSerialNumber)
/*****************************************************************
Detect the Mifare Card present in the antenna field  

INPUTS
	-

OUTPUTS
	Status				:	Status of the operation (see CSC Interface documentation) (1 bytes)
	Code				:	Type card (1 bytes)
	PiccSerialNumber	:	Serial Number of the card authenticated (4 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Detect");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_Detect();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	*Code = vBuf[6];
	for (i=0; i<4; i++) PiccSerialNumber[i] = vBuf[i+7];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Detect(Status: %s, Type : %02x, NumSerie :  %02x %02x %02x %02x)", wCSC_BTS(Status,1), *Code, PiccSerialNumber[0], PiccSerialNumber[1], PiccSerialNumber[2], PiccSerialNumber[3]);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_Authenticate(BYTE NumSector, BYTE KeyAorB, 
							  BYTE KeyIndex, LPBYTE MifareType, 
							  LPBYTE SerialNumber, BYTE *Status)
/*****************************************************************
Change a MIFARE Key in the card : 
* Realise the authentication of the sector with the key indexed by the initialKey specified
* Change the trailer block by a write operation with control made on the Access bits
* And then realise the finale authentication of the sector with the new keys

INPUTS
	NumSector		:	Sector to authenticate
	KeyAorB			:	Choice of the key needed for authentication  
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	MifareType		:	Type of the card authenticated (08 for Mifare Classic) 
	SerialNumber	:	(4 Bytes) Serial Number of the card authenticated 
	Status			:	Status of the operation (see CSC Interface documentation)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Authenticate(NumSector : %02X)", NumSector);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// Check input values
	if (( KeyAorB < 0x0A ) || ( KeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
      if ((KeyIndex >31 ) && (KeyIndex != 0xFF))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( NumSector > 39 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}


	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_Authenticate(NumSector, KeyAorB, KeyIndex);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	*MifareType = vBuf[6];
	for (i=0; i<4; i++) SerialNumber[i] = vBuf[i+7];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Authenticate(Status: %s, Type : %02x, NumSerie :  %02x %02x %02x %02x)", wCSC_BTS(Status,1), *MifareType, SerialNumber[0], SerialNumber[1], SerialNumber[2], SerialNumber[3]);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_Halt(void)
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	None  
OUTPUTS
	None 

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_Halt");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_Halt();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_ReadBlock(BYTE NumBlock, 
							  LPBYTE DataRead, BYTE *Status)
/*****************************************************************
Read a block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 255 
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	DataRead		:	(16 bytes) DataRead in the card  or  
						(5 Bytes ) Mifare Type and serial Number in case 
									of bad transmission error

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer and temporary index
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadBlock(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_ReadBlock( NumBlock );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	for (i=0;i<16;i++) DataRead[i] = vBuf[i+6];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadBlock(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_ReadSector(BYTE NumSector, BYTE KeyAorB, 
							  BYTE KeyIndex, LPBYTE MifareType, 
							  LPBYTE SerialNumber, LPBYTE DataRead, 
							  BYTE *Status)
/*****************************************************************
Read a block in a MIFARE card : for this operation, the sector is authenticated and read
the authentication can be used for other following operation 
like increment, decrement, writeblock, .../...

INPUTS
	NumSector		:	Sector to authenticate and read
	KeyAorB			:	Choice of the key needed for authentication  
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	MifareType		:	Type of the card authenticated (08 for Mifare Classic) 
	SerialNumber	:	(4 Bytes) Serial Number of the card authenticated 
	DataRead		:	(64 bytes) data read in the sector specified

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadSector(NumSector : %02X)", NumSector);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( KeyAorB < 0x0A ) || ( KeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( KeyIndex >31 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( NumSector > 39 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_ReadSector( NumSector, KeyAorB, KeyIndex);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	*MifareType = vBuf[6];
	for (i=0; i<4; i++) SerialNumber[i] = vBuf[i+7];
	for (i=0; i<64;i++) DataRead[i] = vBuf[i+7+4];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadSector(Status: %s, Type : %02x, NumSerie :  %02x %02x %02x %02x)", wCSC_BTS(Status,1), *MifareType, SerialNumber[0], SerialNumber[1], SerialNumber[2], SerialNumber[3]);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_WriteBlock(BYTE NumBlock, LPBYTE DataToWrite, 
							  LPBYTE DataVerif, BYTE *Status)
/*****************************************************************
Write a block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 255 
	DataToWrite		:	(16 bytes) Data to write in the block (the whole block is written) 
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	DataVerif		:	(16 bytes) DataRead in the card  or  
						(5 Bytes ) Mifare Type and serial Number in case 
									of bad transmission error

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_WriteBlock(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_WriteBlock( NumBlock, DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	for (i=0; i<16;i++) DataVerif[i] = vBuf[i+6];
	
	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_WriteBlock(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_DecrementValue(BYTE NumBlock, LPBYTE Substract, 
							  LPBYTE Verif, BYTE *Status)
/*****************************************************************
Decrement a Value block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 255 (must be previously configured as a value block)
	Substract		:	(4 bytes) value to substract to the counter 
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	Verif			:	(4 bytes) Counter value read in the card after the operation
						(5 Bytes ) Mifare Type and serial Number in case 
									of bad transmission error

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255],i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_DecrementValue(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if ( NumBlock == 0 ) 
	{ // Block is a manufacturer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	//if ( NumBlock == (( NumBlock /4 )+3) )
	//{  // Block is a Trailer block
	//	return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	//}

	// Check Trailers
	if( NumBlock < 128 ) {
		if( ((NumBlock + 1) % 4) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);
	} else
		if( ((NumBlock + 1) % 16) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_DecrementValue( NumBlock, Substract);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	for (i=0;i<4;i++) Verif[i]=vBuf[6+i];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_DecrementValue(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_IncrementValue(BYTE NumBlock, LPBYTE Addition, 
							  LPBYTE Verif, BYTE *Status)
/*****************************************************************
Increment a Value block in a MIFARE card : For this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 255 (must be previously configured as a value block)
	Addition		:	(4 bytes) value to Add to the counter 
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
	Verif			:	(4 bytes) Counter value read in the card after the operation
						(5 Bytes ) Mifare Type and serial Number in case 
									of bad transmission error

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_IncrementValue(NumBlock : %02x, Value : %02x%02x%02x%02x )", NumBlock, Addition[0], Addition[1], Addition[2], Addition[3]);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if ( NumBlock == 0 ) 
	{ // Block is a manufacturer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	//if ( NumBlock == (( NumBlock /4 )+3) )
	//{  // Block is a Trailer block
	//	return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	//}
	// Check Trailers
	if( NumBlock < 128 ) {
		if( ((NumBlock + 1) % 4) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);
	} else
		if( ((NumBlock + 1) % 16) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_IncrementValue( NumBlock, Addition);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	for (i=0;i<4;i++) Verif[i]=vBuf[6+i];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_IncrementValue(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_BackUpRestoreValue(BYTE Origine, BYTE Destination, BYTE *Status)
/*****************************************************************
Perform a copy of a value block to an other value block location 
in a given sector of a MIFARE card : For this operation, the sector need to
be previously authenticated by an authenticate or read_sector command
The two blocks must be in the same sector

INPUTS
	Origine			:	Block number from 0 to 63 (must be previously configured as a value block)
	Destination		:	Block number from 0 to 63 (must be previously configured as a value block)
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_BackUpRestoreValue(Origine: %d, Destination : %d)", Origine, Destination);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( Origine >63 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( Destination >63 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if (( Origine /4 ) != ( Destination /4 )) 
	{ // Blocks are not in the same sector
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if (( Origine == 0 ) || ( Destination == 0 )) 
	{ // Block is a manufacturer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if (( Origine == (( Origine/4 )+3) ) || ( Destination == (( Destination/4 )+3) )) 
	{ // Block is a Trailer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}



	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_BackUpRestoreValue( Origine, Destination);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	
	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_BackUpRestoreValue(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_ReadMultipleBlock(BYTE BlockNum, BYTE NumBlock, BYTE *Status, LPBYTE DataRead)
/*****************************************************************
Read several blocks in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	BlockNum		:	Block number from 0 to 255 (1 byte)
	NumBlock		:	Number of Block "n" (1 byte)
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (1 byte)
	DataRead		:	(n x 16 bytes) DataRead in the card  or  
						(5 Bytes ) Mifare Type and serial Number in case 
									of bad transmission error

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer and temporary index
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadMultipleBlock(BlockNum : %02X, NumBlock : %02X)", BlockNum, NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( BlockNum > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_ReadMultipleBlock( BlockNum, NumBlock );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	for (i=0;i<(16*NumBlock);i++) DataRead[i] = vBuf[i+6];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadMultipleBlock(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SimpleWriteBlock(BYTE BlockNum, LPBYTE DataToWrite, BYTE *Status)
/*****************************************************************
Writes an authenticated block

INPUTS
	BlockNum		:	Block number from 0 to 255  (1 byte)
	DataToWrite		:	Data to Write in the selected authenticated block (16 bytes)
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (1 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer and temporary index
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SimpleWriteBlock(BlockNum : %02X)", BlockNum);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( BlockNum > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SimpleWriteBlock( BlockNum, DataToWrite );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SimpleWriteBlock(Status: %s )", wCSC_BTS(Status,1));	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_ReadSectorData(BYTE KeyAorB, BYTE NumSector, BYTE KeyIndex, 
															BYTE *Status, BYTE *MifareType, LPBYTE SerialNumber, LPBYTE DataRead)
/*****************************************************************
Read a the data blocks Sector of the PICC

INPUTS
	KeyAorB			:	Choice of the key needed for authentication  (1 byte)
	NumSector		:	Sector to authenticate and read  (1 byte)
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication  (1 byte)
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)  (1 byte)
	MifareType		:	Type of the card authenticated (08 for Mifare Classic)  (1 byte) 
	SerialNumber	:	Serial Number of the card authenticated  (4 Bytes)
	DataRead		:	data read in the sector specified	(48 bytes) 

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadSectorData(NumSector : %02X)", NumSector);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( KeyAorB < 0x0A ) || ( KeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( KeyIndex > 31 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( NumSector > 39 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_ReadSectorData(  KeyAorB, NumSector, KeyIndex);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	*MifareType = vBuf[6];
	for (i=0; i<4; i++) 	SerialNumber[i] = vBuf[i+7];
	if(*MifareType == 0x08)				// Mifare 1K
		for (i=0; i<48; i++)	DataRead[i] = vBuf[i+7+4];
	else								// Mifare 4K
		for (i=0; i<240; i++)	DataRead[i] = vBuf[i+7+4];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_ReadSectorData(Status: %s, Type : %02x, NumSerie :  %02x %02x %02x %02x)", wCSC_BTS(Status,1), *MifareType, SerialNumber[0], SerialNumber[1], SerialNumber[2], SerialNumber[3]);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_WriteSectorData(BYTE KeyAorB, BYTE NumSector, BYTE KeyIndex, LPBYTE DataToWrite,
															BYTE CardType, BYTE *Status)
/*****************************************************************
Write a the data blocks Sector of the PICC

INPUTS
	KeyAorB			:	Choice of the key needed for authentication  (1 byte)
	NumSector		:	Sector to authenticate and read  (1 byte)
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication  (1 byte)
	DataToWrite		:	Data to write in the Sector (the whole sector is written)  (48 byte)
	CardType		:	Type Card 1k ou 4k (1 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)  (1 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_WriteSectorData(NumSector : %02X)", NumSector);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( KeyAorB < 0x0A ) || ( KeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( KeyIndex > 31 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	// Check input values
	if ( NumSector > 39 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_WriteSectorData(  KeyAorB, NumSector, KeyIndex, DataToWrite, CardType);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_WriteSectorData(Status: %s)", wCSC_BTS(Status,1));	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_Authenticate(BYTE NumKey, BYTE VersionKey, BYTE KeyAorB,  
																BYTE NumBlock, BYTE LgDiversifier, BYTE BlockDiversifier,
																BYTE *StatusCard, WORD *StatusSam)
/*****************************************************************
Realise the authentication of block

INPUTS
	pNumKey				:	Block to authenticate (1 byte)
	pVersionKey			:	Version Key (1 byte)
	pKeyAorB			:	PICC Key (1 byte)
	pNumBlock			:	Number Block (1 byte)
	pLgDiversifier		:	Length Diversifier (1 byte)
	pBlockDiversifier	:	Block Diversifier (1 byte)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_Authenticate(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// Check input values
	if (( KeyAorB < 0x0A ) || ( KeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_Authenticate(NumKey, VersionKey, KeyAorB, NumBlock, LgDiversifier, BlockDiversifier);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_Authenticate(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_ReAuthenticate(BYTE NumKey, BYTE VersionKey, BYTE KeyAorB,  
																  BYTE NumBlock, BYTE LgDiversifier, BYTE BlockDiversifier,
																  BYTE *StatusCard, WORD *StatusSam)
/*****************************************************************
Realise the Re-authenticate the block already authenticated

INPUTS
	pNumKey				:	Block to authenticate (1 byte)
	pVersionKey			:	Version Key (1 byte)
	pKeyAorB			:	PICC Key (1 byte)
	pNumBlock			:	Number Block (1 byte)
	pLgDiversifier		:	Length Diversifier (1 byte)
	pBlockDiversifier	:	Block Diversifier (1 byte)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_ReAuthenticate(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// Check input values
	if (( KeyAorB < 0x0A ) || ( KeyAorB > 0x0B ))
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_ReAuthenticate(NumKey, VersionKey, KeyAorB, NumBlock, LgDiversifier, BlockDiversifier);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_ReAuthenticate(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_ReadBlock(BYTE NumBlock, BYTE *StatusCard, WORD *StatusSam,
															 LPBYTE DataRead)
/*****************************************************************
Read a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	NumBlock			:	Number Block (1 byte)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 bytes)
	DataRead			:   Data Read (16 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_ReadBlock(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_ReadBlock(NumBlock);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	for (i=0;i<16;i++) DataRead[i] = vBuf[i+8];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_ReadBlock(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_WriteBlock(BYTE NumBlock, LPBYTE DataToWrite, 
															  BYTE *StatusCard, WORD *StatusSam, BYTE *StatusWrite)
/*****************************************************************
Write a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	NumBlock			:	Number Block (1 byte)
	DataToWrite		:	Data to Write in block (16 bytes)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 bytes)
	StatusWrite			:   Status Write (1 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_WriteBlock(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_WriteBlock(NumBlock, DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	*StatusWrite = vBuf[8];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_WriteBlock(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_ChangeKey(BYTE NumKey, BYTE VersionKeyA, BYTE VersionKeyB,
															 LPBYTE DefaultAccess, BYTE NumBlock, BYTE LgDiversifier,
															 BYTE BlockDiversifier, BYTE *StatusCard, WORD *StatusSam, BYTE *StatusChangeKey)
/*****************************************************************
Change a MIFARE Key in the card

INPUTS
	NumKey				:	Number Key (1 byte)
	VersionKeyA			:	Version Key A (1 byte)
	VersionKeyB			:	Version Key B (1 byte)
	DefaultAccess		:	Default Access (4 bytes)
	NumBlock			:	Number Block (1 byte)
	LgDiversifier		:	Lenght Diversiifer (1 byte)
	BlockDiversifier	:	Block Diversifier (1 byte)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 bytes)
	StatusChangeKey		:   Status Write (1 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_ChangeKey(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_ChangeKey(NumKey, VersionKeyA, VersionKeyB, DefaultAccess, NumBlock, LgDiversifier, BlockDiversifier);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	*StatusChangeKey = vBuf[8];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_ChangeKey(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_Increment(BYTE NumBlock, LPBYTE Increment,
															 BYTE *StatusCard, WORD *StatusSam, BYTE *StatusIncrement)
/*****************************************************************
Increment a Value block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	NumBlock			:	Number Block (1 byte)
	Increment			:	Increment Value to add (4 bytes)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 bytes)
	StatusIncrement		:   Status Write (1 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_Increment(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if ( NumBlock == 0 ) 
	{ // Block is a manufacturer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check Trailers
	if( NumBlock < 128 ) {
		if( ((NumBlock + 1) % 4) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);
	} else
		if( ((NumBlock + 1) % 16) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_Increment(NumBlock, Increment);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	*StatusIncrement = vBuf[8];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_Increment(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_Decrement(BYTE NumBlock, LPBYTE Decrement,
															 BYTE *StatusCard, WORD *StatusSam, BYTE *StatusDecrement)
/*****************************************************************
Decrement a Value block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	NumBlock			:	Number Block (1 byte)
	Decrement			:	Decrement Value to substract (4 bytes)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 bytes)
	StatusDecrement		:   Status Write (1 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_Decrement(NumBlock : %02X)", NumBlock);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( NumBlock > 255 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if ( NumBlock == 0 ) 
	{ // Block is a manufacturer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check Trailers
	if( NumBlock < 128 ) {
		if( ((NumBlock + 1) % 4) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);
	} else
		if( ((NumBlock + 1) % 16) == 0 )
			return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_Decrement(NumBlock, Decrement);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	*StatusDecrement = vBuf[8];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_Decrement(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_BackUpValue(BYTE Source, BYTE Destination,
															 BYTE *StatusCard, WORD *StatusSam, BYTE *StatusBackUp)
/*****************************************************************
Perform a copy of a value block to an other value block location.

INPUTS
	Source				:	Number Block Source (1 byte)
	Destination			:	Number Block Destination (1 byte)

OUTPUTS
	StatusCard			:	Status Card (1 byte)
	StatusSam			:	Status Sam (2 bytes)
	StatusBackUp		:   Status Write (1 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_BackUpValue(Source : %02X, Destination : %02X)", Source, Destination);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if (( Source == 0 ) || ( Destination == 0 )) 
	{ // Block is a manufacturer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}

	// Check input values
	if (( Source == (( Source/4 )+3) ) || ( Destination == (( Destination/4 )+3) )) 
	{ // Block is a Trailer block
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_BackUpValue(Source, Destination);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	*StatusBackUp = vBuf[8];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_BackUpValue(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MIFARE_SAMNXP_KillAuthentication(WORD *StatusSam)
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	None 

OUTPUTS
	StatusSam			:	Status Sam (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_KillAuthentication");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMIFARE_SAMNXP_KillAuthentication();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusSam = (WORD)(vBuf[5]<<8|vBuf[6]);
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MIFARE_SAMNXP_KillAuthentication(StatusSam: %02X)", *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_Authentication(BYTE SamKeyNum, BYTE SamKeyVersion, WORD KeyBlockNum,
														    BYTE LgDiversifier, LPBYTE Diversifier, 
														    BYTE *StatusCard, WORD *StatusSam)														
/*****************************************************************
Realise the authentication of block

INPUTS
	SamKeyNum			:	Sam Key Number (1 bytes)
	SamKeyVersion		:	Sam Key Version (1 bytes)
	KeyBlockNum			:	Key Block Number - HigherByte, LowerByte (2 bytes)
	LgDiversifier		:	Length Diversifier (1 byte)
	Diversifier			:	Diversifier data (0 to 31 byte)

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_Authentication");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_Authentication(SamKeyNum, SamKeyVersion, KeyBlockNum, LgDiversifier, Diversifier);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_Authentication(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_ResetAuthentication(BYTE Mode, BYTE *StatusCard, WORD *StatusSam)														
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	Mode				:	Reset Mode (1 bytes)

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_ResetAuthentication");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_ResetAuthentication(Mode);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_ResetAuthentication(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_ReadBlock(BYTE Mode, WORD BlockNum, BYTE NumBlock, 
													   BYTE *StatusCard, WORD *StatusSam, LPBYTE DataRead)														
/*****************************************************************
Read a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	Mode				:	Read Mode (1 bytes)
	BlockNum			:	Block Number to start reading (2 bytes)
	NumBlock			:	Number of block to read (1 bytes)

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)
	DataRead			:	Data read from the card (0 - 240 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_ReadBlock");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_ReadBlock(Mode, BlockNum, NumBlock);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	for (i=0;i<(NumBlock*16);i++) DataRead[i] = vBuf[i+8];	// lg data :0 - 240 bytes
	
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_ReadBlock(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);} /* LOG DEBUG */
			
	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_WriteBlock(BYTE Mode, WORD BlockNum, BYTE NumBlock, LPBYTE DataToWrite, 
													    BYTE *StatusCard, WORD *StatusSam)														
/*****************************************************************
Write a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	Mode				:	Read Mode (1 bytes)
	BlockNum			:	Block Number to start writing (2 bytes)
	NumBlock			:	Number of block to write (1 bytes)
	DataToWrite			:	Data to Write in block (16 - 48 bytes)

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_WriteBlock");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_WriteBlock(Mode, BlockNum, NumBlock, DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_WriteBlock(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);} /* LOG DEBUG */
			
	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_ChangeKey(BYTE SamKeyNum, BYTE SamKeyVersion, WORD KeyBlockNum, 
													   BYTE LgDiversifier, LPBYTE Diversifier, 
													   BYTE *StatusCard, WORD *StatusSam)														
/*****************************************************************
Change a MIFARE Key in the card

INPUTS
	SamKeyNum			:	Sam Key Number (1 bytes)
	SamKeyVersion		:	Sam Key Version (1 bytes)
	KeyBlockNum			:	Key Block Number (2 bytes)
	LgDiversifier		:	Length Diversifier (1 byte)
	Diversifier			:	Diversifier data (0 to 31 byte)

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_ChangeKey");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_ChangeKey(SamKeyNum, SamKeyVersion, KeyBlockNum, 
					   LgDiversifier, Diversifier);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_ChangeKey(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);} /* LOG DEBUG */
			
	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_VirtualCardSupport(BYTE SamKeyNumVCENC, BYTE SamKeyVersionVCENC,  
																BYTE SamKeyNumVCMAC, BYTE SamKeyVersionVCMAC, LPBYTE IID,
																BYTE *StatusCard, WORD *StatusSam, LPBYTE UID)														
/*****************************************************************
Check Virtual Card is supported and retreive the UID

INPUTS
	SamKeyNumVCENC		:	Sam Key Number for VC polling ENC (1 bytes)
	SamKeyVersionVCENC	:	Sam Key Version for VC polling ENC (1 bytes)
	SamKeyNumVCMAC		:	Sam Key Number for VC polling MAC (1 bytes)
	SamKeyVersionVCMAC	:	Sam Key Version for VC polling MAC (1 bytes)
	IID					:	Installation Identifier (16 byte)

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)
	UID					:	Real Card UID (4 - 7 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_VirtualCardSupport");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_VirtualCardSupport(SamKeyNumVCENC, SamKeyVersionVCENC,  
								SamKeyNumVCMAC, SamKeyVersionVCMAC, IID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	*StatusSam = (WORD)(vBuf[6]<<8|vBuf[7]);
	for (i=0;i<(vBuf[4]-4);i++) UID[i] = vBuf[i+8];	// UID :4 - 7 bytes
	
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_VirtualCardSupport(StatusCard: %02X, StatusSam: %02X)", *StatusCard, *StatusSam);} /* LOG DEBUG */
			
	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI MFP_SL3_DeselectVirtualCard(BYTE *StatusCard)														
/*****************************************************************
Deselect the Virtual Card

INPUTS
	-

OUTPUTS
	StatusCard			:	Status Card (1 bytes)
	StatusSam			:	Status Sam (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_DeselectVirtualCard");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iMFP_SL3_DeselectVirtualCard();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*StatusCard = vBuf[5];
	
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"MFP_SL3_DeselectVirtualCard(StatusCard: %02X)", *StatusCard);} /* LOG DEBUG */
			
	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CreateApplication(LPBYTE AppID, BYTE Opt, BYTE KeyNum, WORD *Status)
/*****************************************************************
Create a new application in the card

INPUTS
	AppID			:	ID Number of the Appl in the card (3 byte)
	Opt				:	Options (1 byte)
						xxxx0001b Config changeable
						xxxx0010b Create/Delete operation are free (without master key)
						xxxx0100b Access to list directory is free (without master key)
						xxxx1000b master key setting can be changed
	KeyNum			:	Key Number usable for that new application (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateApplication(AppID : %02X)", *AppID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CreateApplication( AppID, Opt, KeyNum );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateApplication(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_DeleteApplication(LPBYTE AppID, WORD *Status)
/*****************************************************************
Deactivate application in the card

INPUTS
	AppID			:	ID Number of the Appl in the card (3 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_DeleteApplication(AppID : %02X)", *AppID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_DeleteApplication( AppID );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_DeleteApplication(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SelectApplication(LPBYTE AppID, WORD *Status)
/*****************************************************************
Select one Application for further access in the card

INPUTS
	AppID			:	ID Number of the Appl in the card (3 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SelectApplication(AppID : %02X)", *AppID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SelectApplication( AppID );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SelectApplication(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_FormatPICC(WORD *Status)
/*****************************************************************
Format card File system

INPUTS
	-

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_FormatPICC");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_FormatPICC();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_FormatPICC(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetApplicationIDs(BYTE NumID, BYTE *Lg, WORD *Status, LPBYTE IDs)
/*****************************************************************
Retreive the current application ID

INPUTS
	NumID			:	Number of ID (1 byte)

OUTPUTS
	Lg				:	response length
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)
	IDs				:	ID for each application	( n x 3 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetApplicationIDs(NumID : %02X)", NumID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if(NumID > 32) return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetApplicationIDs( NumID );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<(vBuf[4]-2);i++) IDs[i] = vBuf[i+7];	// IDs : nx3 bytes
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetApplicationIDs(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetVersion(WORD *Status, LPBYTE HardInfo, LPBYTE SoftInfo, 
														LPBYTE UID, LPBYTE Batch, BYTE *Cw, BYTE *Year)
/*****************************************************************
Version of the card firmware

INPUTS
	-

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)
	HardInfo		:	Hard Info (7 bytes)
							byte 1: code of the vendor
							byte 2; code of the type
							byte 3: code of the subtype
							byte 4: code of the major version number
							byte 5: code of the minor version number
							byte 6: code of the storage size
							byte 7: code of the communication protocol
	SoftInfo:		:	Soft Info (7 bytes)
							byte 1: code of the vendor
							byte 2; code of the type
							byte 3: code of the subtype
							byte 4: code of the major version number
							byte 5: code of the minor version number
							byte 6: code of the storage size
							byte 7: code of the communication protocol
	UID				:	Unique serial number (7 bytes)
	Batch			:	Production batch number	(5 bytes)
	Cw				:	Calendar year of prod (1 byte)
	Year			:	Year of manufacturing (1 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetVersion");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetVersion();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<7;i++) HardInfo[i] = vBuf[i+7];
	for (i=0;i<7;i++) SoftInfo[i] = vBuf[i+14];
	for (i=0;i<7;i++) UID[i] = vBuf[i+21];
	for (i=0;i<5;i++) Batch[i] = vBuf[i+28];
	*Cw = vBuf[33];
	*Year = vBuf[34];

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetVersion(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetFreeMem(WORD *Status, LPBYTE Size)
/*****************************************************************
retrieve the size available on the card

INPUTS
	-

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)
	Size			:	Size of free memory available (3 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetFreeMem");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetFreeMem();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<3;i++) Size[i] = vBuf[i+7];

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetFreeMem(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD DESFIRE_PrepareAuthentication (	BYTE AuthMode,
          								BYTE SAMKeyNumber,
          								BYTE SAMKeyVersion,
										WORD *Status)
/*****************************************************************
This function sets parameters used for authentication.
Parameters  :
I	BYTE	AuthMode		Authentication parameters (see SAM AV2 specification).
I	BYTE	SAMKeyNumber	Key number in the SAM.
I	BYTE	SAMKeyVersion	Key version of the specified key in the SAM.
O	WORD	*Status			Status (2 byte) : 0x9000 = OK
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	
		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_PrepareAuthentication(%02X, %02X, %02X, ...)", AuthMode,SAMKeyNumber,SAMKeyVersion);	
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_PrepareAuthentication( AuthMode,SAMKeyNumber,SAMKeyVersion );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */	
		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_PrepareAuthentication(%02X, %02X, %02X, Status %04X)", AuthMode,SAMKeyNumber,SAMKeyVersion,*Status);	
	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_Authenticate(BYTE KeyNum, WORD *Status)
/*****************************************************************
Realise the authentication

INPUTS
	KeyNum			:	Number of the access key which will be used for the authetication (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_Authenticate(KeyNum : %02X)", KeyNum);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_Authenticate( KeyNum );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_Authenticate(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_AuthenticateEV1 (	BYTE PICCKeyNumber,
								BYTE AuthMode,
								BYTE SAMKeyNumber,
								BYTE SAMKeyVersion,
								BYTE Type,
								BYTE LgDiversifier,
								BYTE *Diversifier,
								WORD *Status)
/*****************************************************************
This function authenticates a PICC or an application.
Parameters  :
I	BYTE	PICCKeyNumber	Specify the number of the access key which will be used for the authentication.
I	BYTE	AuthMode		Authentication parameters (see RD_ST_08167-XX Coupler Software Interface GEN5XX or SAM AV2 specification).
I	BYTE	SAMKeyNumber	Key number in the SAM.
I	BYTE	SAMKeyVersion	Key version of the specified key in the SAM.
I	BYTE	Type			Authentication type used.
							$00: TDEA DESFire 4
							$01: TDEA ISO 10116
							$02: AES
I	BYTE	LgDiversifier	length of the diversifier used for key diversification (0 if no diversification)
I	BYTE	*Diversifier	diversification data used for key diversification
O	WORD	*Status			Status (2 byte) : 0x9100 -->OK

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum	
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	
		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_AuthenticateEV1(%02X, %02X, %02X, %02X, %02X, %02X, ...)", PICCKeyNumber, AuthMode,SAMKeyNumber,SAMKeyVersion,Type,LgDiversifier);	
	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_AuthenticateEV1( PICCKeyNumber,AuthMode,SAMKeyNumber,SAMKeyVersion,Type,LgDiversifier,Diversifier );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */	
		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_AuthenticateEV1(..., Status %04X)", *Status);	
	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CommitTransaction(WORD *Status)
/*****************************************************************
Commits the transaction to end a transaction operation with changes

INPUTS
	-

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CommitTransaction");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CommitTransaction();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CommitTransaction(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_AbortTransaction(WORD *Status)
/*****************************************************************
Aborts the current transaction to end a transaction operation with no changes

INPUTS
	-

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_AbordTransaction");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_AbortTransaction();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_AbordTransaction(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_ChangeKey(	BYTE CurKeyNo,
								BYTE CurKeyV,
								BYTE NewKeyNo,
								BYTE NewKeyV,
								BYTE KeyCompMeth,
								BYTE Cfg,
								BYTE Algo,
								BYTE LgDiversifier,
								BYTE *Diversifier,
								WORD *Status)

/*****************************************************************
Parameters :
I	BYTE	CurKeyNo		Current Key number in the SAM.
I	BYTE	CurKeyV			Current Key version in the SAM.
I	BYTE	NewKeyNo		New Key number in the SAM.
I	BYTE	NewKeyV			New Key version in the SAM.
I	BYTE	KeyCompMeth		Mask key compilation method. (See RD_ST_08167-XX Coupler Software Interface GEN5XX or SAM AV2 specification).
I	BYTE	Cfg				Key configuration
								bit 3...0: number of DESFire key to be changed
								bit 4: 1 if DESFire master key is to be changed.
I	BYTE	Algo			Algorithm used if PICC master key is changed
								bit 6...7: ‘00’ specifies DES/2K3DES
								‘01’ specifies 3K3DES
								‘10’ specifies AES
I	BYTE	LgDiversifier	Length of the diversifier used for key diversification (0 if no diversification)
I	BYTE	*Diversifier	Diversification data used for key diversification.
O	WORD	*Status			Status (2 byte) : 0x9100 --> OK

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ChangeKey(%02X, %02X, %02X, %02X, %02X, %02X, %02X, %02X, ...)", CurKeyNo, CurKeyV, NewKeyNo, NewKeyV, KeyCompMeth, Cfg, Algo, LgDiversifier);	
	}

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_ChangeKey(CurKeyNo,CurKeyV, NewKeyNo,NewKeyV, KeyCompMeth, Cfg, Algo,LgDiversifier, Diversifier);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ // DEBUGG 
		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ChangeKey(Status: %02X)", *Status);	} // LOG DEBUG 
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_ChangeKeySetting(BYTE KeySetting, WORD *Status)
/*****************************************************************
Changes the key settings information  

INPUTS
	KeySetting		:	new master key settings either for the currently selected application or for the whole PICC  (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ChangeKeySetting(KeySetting: %02X)", KeySetting);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_ChangeKeySetting(KeySetting);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ChangeKeySetting(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetKeySetting(WORD *Status, BYTE *KeySetting, BYTE *NumKey)
/*****************************************************************
Gets the configuration information on the PIDD and the application master key configuration settings.

INPUTS
	-

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	KeySetting		:	key settings either for the currently selected application (1 byte)
	NumKey			:	Number of keys defined for the current selected application (1 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetKeySetting");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetKeySetting();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	*KeySetting = vBuf[7];
	*NumKey = vBuf[8];

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetKeySetting(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetKeyVersion(BYTE KeyNum, WORD *Status, BYTE *KeyVersion)
/*****************************************************************
Gets Key Version.

INPUTS
	KeyNum			:	Specify the number of the access key (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	KeyVersion		:	key Version (1 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetKeyVersion(KeyNum: %02X)", KeyNum);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetKeyVersion(KeyNum);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	*KeyVersion = vBuf[7];

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetKeyVersion(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_ChangeFileSetting(BYTE FileID, BYTE CommEncrypted, BYTE CommMode, 
															   BYTE AccessRight, WORD *Status)
/*****************************************************************
Changes the file configuration on the card

INPUTS
	FileID			:	ID of the file whose communication mode and access rights settings shall be changed (1 byte)
	CommEncrypted	:	Encrypt the communication (1 byte)
	CommMode		:	New communication mode (1 byte)
	AccessRight		:	Specify the access right setting for this file (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ChangeFileSetting(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_ChangeFileSetting(FileID, CommEncrypted, CommMode, AccessRight);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ChangeFileSetting(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_ClearRecordFile(BYTE FileID, WORD *Status)
/*****************************************************************
Clears the record files selected by the input param

INPUTS
	FileID			:	ID of the file which shall be cleared (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ClearRecordFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_ClearRecordFile(FileID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ClearRecordFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CreateBackUpDataFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
																	LPBYTE FileSize, WORD *Status)
/*****************************************************************
Creation of a Backup Data File

INPUTS
	FileID			:	ID of the file for which the new Backup File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	FileSize		:	Size of the new Backup File in bytes (3 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateBackUpDataFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CreateBackUpDataFile(FileID, CommMode, AccessRight, FileSize);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateBackUpDataFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CreateCyclicRecordFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
																	LPBYTE RecordSize, LPBYTE MaxNumRecord, WORD *Status)
/*****************************************************************
Creation of a Cyclic Data File

INPUTS
	FileID			:	ID of the file for which the new Cyclic record File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	RecordSize		:	Size of the new Cyclic File in bytes (3 byte)
	MaxNumRecord	:	Number of the records for the new Cyclic File (3 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateCyclicRecordFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CreateCyclicRecordFile(FileID, CommMode, AccessRight, RecordSize, MaxNumRecord);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateCyclicRecordFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CreateLinearRecordFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
																	LPBYTE RecordSize, LPBYTE MaxNumRecord, WORD *Status)
/*****************************************************************
Creation of a Linear Data File

INPUTS
	FileID			:	ID of the file for which the new Linear record File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	RecordSize		:	Size of the new linear File in bytes (3 byte)
	MaxNumRecord	:	Number of the records for the new linear File (3 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateLinearRecordFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CreateLinearRecordFile(FileID, CommMode, AccessRight, RecordSize, MaxNumRecord);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateLinearRecordFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CreateStandardDataFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
																	LPBYTE FileSize, WORD *Status)
/*****************************************************************
Creation of a Standard Data File

INPUTS
	FileID			:	ID of the file for which the new File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	FileSize		:	Size of the new File in bytes (3 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateStandardDataFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CreateStandardDataFile(FileID, CommMode, AccessRight, FileSize);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateStandardDataFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_CreateValueFile(BYTE FileID, BYTE CommMode, WORD AccessRight, LPBYTE Lower, 
															 LPBYTE Upper, LPBYTE Initial, BYTE Limited, WORD *Status)
/*****************************************************************
Creation of a Value File

INPUTS
	FileID			:	ID of the file for which the new File is to be credited (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	Lower			:	Min amount for the value file (4 byte)
	Upper			:	Max amount for the value file (4 byte)
	Initial			:	Amount with which the value file will be created (4 byte)
	Limited			:	Limited credit command is enabled for the new value file (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateValueFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_CreateValueFile(FileID, CommMode, AccessRight, Lower, Upper, Initial, Limited );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_CreateValueFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_Credit(BYTE FileID, BYTE CommMode, LPBYTE Amount, WORD *Status)
/*****************************************************************
Credit a Value on a Value File

INPUTS
	FileID			:	ID of the file for which the new File is to be debited (1 byte)
	CommMode		:	File communication mode (1 byte)
	Amount			:	Amount to be credited in the value file (4 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_Credit(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_Credit(FileID, CommMode, Amount );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_Credit(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_Debit(BYTE FileID, BYTE CommMode, LPBYTE Amount, WORD *Status)
/*****************************************************************
Debit a Value on a Value File

INPUTS
	FileID			:	ID of the file for which the new File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	Amount			:	Amount to be debited in the value file (4 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_Debit(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_Debit(FileID, CommMode, Amount );

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_Debit(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_DeleteFile(BYTE FileID, WORD *Status)
/*****************************************************************
Delete a File 

INPUTS
	FileID			:	ID of the file for which the new File is to be deleted (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_DeleteFile(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_DeleteFile(FileID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_DeleteFile(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetFileID(BYTE MaxFileID, WORD *Status, BYTE *NbFound, LPBYTE FileId)
/*****************************************************************
Get File ID for the current application 

INPUTS
	MaxFileID		:	Max response expected  (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	NbFound			:	Number of FileId found "n" (1 byte)
	FileId			:	FileID array (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetFileID(MaxFileID: %02X)", MaxFileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetFileID(MaxFileID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	*NbFound = vBuf[7];
	for (i=0;i<(vBuf[4]-2);i++) FileId[i] = vBuf[i+8];

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetFileID(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetFileSetting(BYTE FileID, WORD *Status, BYTE *FileType, BYTE *CommMode, WORD *AccessRight)
/*****************************************************************
Get File Settings for the current application 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	FileType		:	Type of File (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	File access rights settings (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetFileSetting(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetFileSetting(FileID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	*FileType = vBuf[7];
	*CommMode = vBuf[8];
	*AccessRight = (WORD)(vBuf[9]<<8|vBuf[10]); 

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetFileSetting(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_GetValue(BYTE FileID, BYTE CommMode, WORD *Status, LPBYTE Amount)
/*****************************************************************
Get File Settings for the current application 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	CommMode		:	File communication mode (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	Amount			:	Amount of the value returned (4 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetValue(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_GetValue(FileID, CommMode);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<(vBuf[4]-2);i++) Amount[i] = vBuf[i+7];	

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_GetValue(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_LimitedCredit(BYTE FileID, BYTE CommMode, LPBYTE Amount, WORD *Status)
/*****************************************************************
Limited Credit 

INPUTS
	FileID			:	ID of the file for which the credit is to increase (1 byte)
	CommMode		:	File communication mode (1 byte)
	Amount			:	Max Amount that can be added to the File value (4 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_LimitedCredit(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_LimitedCredit(FileID, CommMode, Amount);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_LimitedCredit(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_ReadData(BYTE FileID, BYTE CommMode, WORD FromOffset, WORD NumByteToRead, 
													  WORD *Status, WORD *NumByteRead, LPBYTE DataRead)
/*****************************************************************
Read Data standard File 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	CommMode		:	File communication mode (1 byte)
	FromOffset		:	Offset in the File (2 bytes)
	NumByteToRead	:	Nb byte to read (2 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	NumByteRead		:	Nb Bytes read "n" (2 bytes)
	DataRead		:	Data read in the File (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ReadData(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_ReadData(FileID, CommMode, FromOffset, NumByteToRead);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[6]<<8|vBuf[7]);
	*NumByteRead = (WORD)(vBuf[8]<<8|vBuf[9]);
	for (i=0;i<(int)(*NumByteRead);i++) DataRead[i] = vBuf[i+10];	// Sam Version

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ReadData(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_WriteData(BYTE FileID, BYTE CommMode, WORD FromOffset, WORD NumByteToWrite, 
													   LPBYTE DataToWrite, WORD *Status)
/*****************************************************************
Write Data standard File 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	CommMode		:	File communication mode (1 byte)
	FromOffset		:	Offset in the File (2 bytes)
	NumByteToWrite	:	Nb byte to write (2 bytes)
	DataToWrite		:	Data write in the File (n bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_WriteData(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_WriteData(FileID, CommMode, FromOffset, NumByteToWrite, DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_WriteData(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_ReadRecord(BYTE FileID, BYTE CommMode, WORD FromRecord, WORD NumRecordToRead, 
														WORD RecordSize, WORD *Status, WORD *NumRecordRead, LPBYTE DataRead)
/*****************************************************************
Read Data Record File 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	CommMode		:	File communication mode (1 byte)
	FromRecord		:	Record number from which Data are read (2 bytes)
	NumRecordToRead	:	Number of record to read (2 bytes)
	RecordSize		:	Record size (2 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	NumRecordRead	:	Nb Bytes read "n" (2 bytes)
	DataRead		:	Data read in the File (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ReadRecord(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_ReadRecord(FileID, CommMode, FromRecord, NumRecordToRead, RecordSize);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[6]<<8|vBuf[7]);
	
	if (*Status == 0x9100)
	{
		*NumRecordRead = (WORD)(vBuf[8]<<8|vBuf[9]);
		for (i=0;i<(int)(*NumRecordRead * RecordSize);i++) DataRead[i] = vBuf[i+10];
	}

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_ReadRecord(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_WriteRecord(BYTE FileID, BYTE CommMode, WORD FromRecord, WORD NumRecordToWrite, 
														 LPBYTE DataToWrite, WORD *Status)
/*****************************************************************
Write Data Record File 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	CommMode		:	File communication mode (1 byte)
	FromRecord		:	Record number from which Data are written (2 bytes)
	NumRecordToWrite:	Number of record to write (2 bytes)
	DataToWrite		:	Data To Write (n bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_WriteRecord(FileID: %02X)", FileID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen) return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_WriteRecord(FileID, CommMode, FromRecord, NumRecordToWrite, DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok) return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3) return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);

	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_WriteRecord(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SamGetVersion(BYTE *Lg, WORD *Status, LPBYTE SamVersion)
/*****************************************************************
Sam Firmware Info

INPUTS
	-

OUTPUTS
	Lg				:	Length response	(1 byte)
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)
	SamVersion		:	Version SAM (32 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamGetVersion");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SamGetVersion();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<(vBuf[4]-2);i++) SamVersion[i] = vBuf[i+7];	// Sam Version
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamGetVersion(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SamSelectApplication(LPBYTE DirFileAID, WORD *Status)
/*****************************************************************
Select an application in the SAM

INPUTS
	DirFileAID:	Directory File AID (3 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamSelectApplication(DirFileAID : %02X)",*DirFileAID);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SamSelectApplication(DirFileAID);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamSelectApplication(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SamLoadInitVector(LPBYTE InitVector, WORD *Status)
/*****************************************************************
Load an init vector in the SAM for 3DES seeding

INPUTS
	InitVector:	Crypto seed (8 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamLoadInitVector(InitVector : %02X)",*InitVector);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SamLoadInitVector(InitVector);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamLoadInitVector(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SamGetKeyEntry(BYTE KeyNum, BYTE *Lg, WORD *Status, LPBYTE KeyEntry)
/*****************************************************************
Get Key entry Info

INPUTS
	KeyNum:	Key Entry Number (1 bytes)

OUTPUTS
	Lg				:	Length response	(1 byte)
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)
	KeyEntry		:	3 Key Versions (3 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamGetKeyEntry(KeyNum : %02X)",KeyNum);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SamGetKeyEntry(KeyNum);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<(vBuf[4]-2);i++) KeyEntry[i] = vBuf[i+7];	// Key Entry
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamGetKeyEntry(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SamGetKucEntry(BYTE RefKucNum, BYTE *Lg, WORD *Status, LPBYTE KucEntry)
/*****************************************************************
Get Key Usage Counter Info

INPUTS
	RefKucNum		:	Key Usage Counter Entry Reference Number (1 bytes)

OUTPUTS
	Lg				:	Length response	(1 byte)
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)
	KucEntry		:	Key Usage Counter Versions (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255], i;			// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamGetKucEntry(RefKucNum : %02X)",RefKucNum);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SamGetKucEntry(RefKucNum);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	for (i=0;i<(vBuf[4]-2);i++) KucEntry[i] = vBuf[i+7];	// Kuc Entry
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamGetKucEntry(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI DESFIRE_SamDisableCrypto(WORD PROMAS, WORD *Status)
/*****************************************************************
Disable the crypto of certain function on the SAM/PICC

INPUTS
	PROMAS			:	Programming bit Mask (2 bytes)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 byte)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamDisableCrypto(PROMAS : %02X)",PROMAS);	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iDESFIRE_SamDisableCrypto(PROMAS);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = (WORD)(vBuf[5]<<8|vBuf[6]);
	
	if(swDEBUG==1){ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"DESFIRE_SamDisableCrypto(Status: %02X)", *Status);	} /* LOG DEBUG */
	
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI SRX_Active(BYTE *Status, BYTE *ChipType, LPBYTE UID)														
/*****************************************************************
Activate and select a SR, SRI, SRT or SRIX ticket and send back the chip type and the 64-bit UID.

INPUTS
	-

OUTPUTS
	Status				:	Status  (1 bytes)
	ChipType			:	Type Chip (1 bytes)
	UID					:	UID from LSB to MSB (8 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{

	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"SR_Active");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iSRX_Active();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[5];
	*ChipType = vBuf[6];
	for (i=0;i<(vBuf[4]-2);i++) UID[i] = vBuf[i+7];	// UID : 8 bytes
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"SR_Active(Status: %02X, ChipType: %02X)", *Status, *ChipType);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI SRX_ReadBlock(BYTE BlockNum, BYTE NumBlock, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead)														
/*****************************************************************
Read Blocks.

INPUTS
	BlockNum			:	Block Number to start reading (1 bytes)
	NumBlock			:	Number of block to read (1 bytes)
	ChipType			:	Type Chip (1 bytes)

OUTPUTS
	Lg					:	Length -> Status + DataRead (1 bytes)
	Status				:	Status SRx (1 bytes)
	DataRead			:	Data read from the card (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"SRX_ReadBlock");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( (ChipType == 0) && (BlockNum > 15) )									// SR176
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else if	( (ChipType == 1) && (!(BlockNum == 255) && !(BlockNum <= 15)) )	// SR512
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else if	( (ChipType == 2) && (!(BlockNum == 255) && !(BlockNum <= 127)) )	// SR4K
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }

	// Check input values
	if ( ((ChipType == 0) || (ChipType == 1)) && ((NumBlock < 1) || (NumBlock > 16)) )	// SR176 et SR512
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else if	( (ChipType == 2) && ((NumBlock < 1) || (NumBlock > 60)) )					// SR4K
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }

	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iSRX_ReadBlock(BlockNum, NumBlock);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = vBuf[5];
	for (i=0;i<(vBuf[4]-1);i++) DataRead[i] = vBuf[i+6];	// DataRead : n bytes
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"SRX_ReadBlock(Status: %02X)", *Status);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI SRX_WriteBlock(BYTE BlockNum, BYTE NumBlock, LPBYTE DataToWrite, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead)														
/*****************************************************************
Read Blocks.

INPUTS
	BlockNum			:	Block Number to start writing (1 bytes)
	NumBlock			:	Number of block to write (1 bytes)
	DataToWrite			:	Data to Write (n bytes)
	ChipType			:	Type Chip (1 bytes)

OUTPUTS
	Lg					:	Length -> Status + DataRead (1 bytes)
	Status				:	Status SRx (1 bytes)
	DataRead			:	Data read from the card (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"SRX_WriteBlock");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( (ChipType == 0) && (BlockNum > 15) )										// SR176
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);								
	else if	( (ChipType == 1) && (!(BlockNum == 255) && !(BlockNum <= 15)) )		// SR512
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);								
	else if	( (ChipType == 2) && (!(BlockNum == 255) && !(BlockNum <= 127)) )		// SR4K
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }

	// Check input values
	if ( ((ChipType == 0) || (ChipType == 1)) && ((NumBlock < 1) || (NumBlock > 16)) )	// SR176 et SR512
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);									
	else if	( (ChipType == 2) && ((NumBlock < 1) || (NumBlock > 60)) )					// SR4K
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }
		
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iSRX_WriteBlock(BlockNum, NumBlock, DataToWrite, ChipType);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = vBuf[5];
	for (i=0;i<(vBuf[4]-1);i++) DataRead[i] = vBuf[i+6];	// DataRead : n bytes
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"SRX_WriteBlock(Status: %02X)", *Status);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI SRX_Release(BYTE Param, BYTE *Status)														
/*****************************************************************
Deactivate SRx ticket.

INPUTS
	Param				:	Param deactivation of the ticket (1 bytes)

OUTPUTS
	Status				:	Status SRx (1 bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"SRX_Release");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// Check input values
	if ( Param != 0 )
	{
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	}
		
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iSRX_Release(Param);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Status = vBuf[4];
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"SRX_Release(Status: %02X)", *Status);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI SRX_Read(WORD Add, BYTE NumBytes, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead)														
/*****************************************************************
Read Bytes at a given address.

INPUTS
	Add					:	Address of the first reading (2 bytes)
	NumBytes			:	Number of bytes to read (1 bytes)
	ChipType			:	Type Chip (1 bytes)

OUTPUTS
	Lg					:	Length -> Status + DataRead (1 bytes)
	Status				:	Status SRx (1 bytes)
	DataRead			:	Data read from the card (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"SRX_Read");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);
	
	// Check input values
	if ( (ChipType == 0) && (Add > 0x001F) )												// SR176 : 0 to 31
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);								
	else if	( (ChipType == 1) && (((Add > 0x003F) && (Add < 0x03FC)) || (Add > 0x03FF)) )	// SR512 : 0 to 63 or 1020 to 1023
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);								
	else if	( (ChipType == 2) && (((Add > 0x01FF) && (Add < 0x03FC)) || (Add > 0x03FF)) )	// SR4K : 0 to 511 or 1020 to 1023
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }

	// Check input values
	if ( (ChipType == 0) && ((NumBytes < 1) || (NumBytes > 32)) )			// SR176
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);									
	else if ( (ChipType == 1) && ((NumBytes < 1) || (NumBytes > 64)) )		// SR512
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);									
	else if	( (ChipType == 2) && ((NumBytes < 1) || (NumBytes > 240)) )		// SR4K
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iSRX_Read(Add, NumBytes);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = vBuf[5];
	for (i=0;i<(vBuf[4]-1);i++) DataRead[i] = vBuf[i+6];	// DataRead : n bytes
		
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"SRX_Read(Status: %02X)", *Status);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI SRX_Write(WORD Add, BYTE NumBytes, LPBYTE DataToWrite, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead)														
/*****************************************************************
Write and Verify Bytes at a given address.

INPUTS
	Add					:	Address of the first reading (2 bytes)
	NumBytes			:	Number of bytes to write (1 bytes)
	DataToWrite			:	Data to Write
	ChipType			:	Type Chip (1 bytes)

OUTPUTS
	Lg					:	Length -> Status + DataRead (1 bytes)
	Status				:	Status SRx (1 bytes)
	DataRead			:	Data read from the card (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/
{
	INT vRet;					// return value
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size
	int i = 0;

	if(swDEBUG==1)
	{ /* DEBUG */	sprintf_s(tdeb,sizeof(tdeb),"SRX_Write");	} /* LOG DEBUG */

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);
	
	// Check input values
	if ( (ChipType == 0) && (Add > 0x001F) )												// SR176 : 0 to 31
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);								
	else if	( (ChipType == 1) && (((Add > 0x003F) && (Add < 0x03FC)) || (Add > 0x03FF)) )	// SR512 : 0 to 63 or 1020 to 1023
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);								
	else if	( (ChipType == 2) && (((Add > 0x01FF) && (Add < 0x03FC)) || (Add > 0x03FF)) )	// SR4K : 0 to 511 or 1020 to 1023
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }

	// Check input values
	if ( (ChipType == 0) && ((NumBytes < 1) && (NumBytes > 32)) )			// SR176
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);									
	else if ( (ChipType == 1) && ((NumBytes < 1) && (NumBytes > 64)) )		// SR512
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);									
	else if	( (ChipType == 2) && ((NumBytes < 1) && (NumBytes > 240)) )		// SR4K
		return wCSC_DebugLog(tdeb,RCSC_InputDataWrong);		
	else { /* rien */ }
	
	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	// prepares the command buffer 
	iSRX_Write(Add, NumBytes, DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the Status 
	if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

	*Lg = vBuf[4];
	*Status = vBuf[5];
	for (i=0;i<(vBuf[4]-1);i++) DataRead[i] = vBuf[i+6];	// DataRead : n bytes
	
	if(swDEBUG==1)
	{ /* DEBUG */		sprintf_s(tdeb,sizeof(tdeb),"SRX_Write(Status: %02X)", *Status);	} /* LOG DEBUG */

	return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512B_List(BYTE	RFU,
												  BYTE* nbTickets,
												  BYTE* serialNumbers,
												  BYTE* status)
/*****************************************************************
LIST CTX512B tickets
Performs anticollision and answers serial numbers of all the chips
present in the antenna field

INPUTS
	RFU				: 0x00, RFU
OUTPUTS
	nbTickets		: number of tickets in the antenna field
	serialNumbers	: list of the serial numbers retrieved
					(2 LSB serial number bytes for each ticket)
	status			: CTX512B execution status returned


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// returned value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// answer frame size

if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CTx512B_List(RFU:%d)",RFU);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)		return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointers value
if(nbTickets==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(serialNumbers==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepare the command buffer for CTx512B_List command
iCTX_512B_List(RFU);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=nb
	vBuf[7]=serialNum
	vBuf[8]=serialNum
	vBuf[9]=serialNum
	...	
	vBuf[x]=serialNum
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)	return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<4)		return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status and Data
*nbTickets = vBuf[6];
CopyMemory(serialNumbers,&vBuf[7],vBuf[1]-5);
*status = vBuf[5];
	
if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_List(RFU:%d / nb tickets:%d, serial numbers:%s, Status:%02X)",
			RFU,*nbTickets,wCSC_BTS(serialNumbers,vBuf[1]-5),*status);

} /* LOG DEBUG */
return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512B_Select(BYTE* serialNumber,
													BYTE* serialNumberRead,
													BYTE* status)
/*****************************************************************
SELECT CTX512B
Selects a ticket with its serial number

INPUT
	serialNumber : pointer to the buffer containing the serial
					number (2 bytes)

OUTPUTS
	serialNumberRead	: pointer to serial number read (2 bytes)
						(sould be equal to serialNumber)
	status				: CTX512B execution status returned


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// returned value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// answer frame size

if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Select(%02X%02X)",serialNumber[0],serialNumber[1]);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)		return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(serialNumberRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepare the command buffer for CTx512B_Select command
iCTX_512B_Select(serialNumber);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=serialNum
	vBuf[7]=serialNum
	vBuf[8]=EOF
	vBuf[9]=CRCL
	vBuf[10]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)	return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<4)		return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status and Data
CopyMemory(serialNumberRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];
	
if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Select(serialNumber:%02X%02X / serialNumberRead:%02X%02X, Status:%02X)",
			serialNumber[0],serialNumber[1],
			serialNumberRead[0],serialNumberRead[1],*status);

} /* LOG DEBUG */
return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512B_Read (BYTE ADD,
												   BYTE NB,
												   BYTE* dataRead,
												   BYTE* status)
/*****************************************************************
READ CTX512B
Reads a number of bytes (NB) from a given address (ADD)

INPUTS
	ADD		: adress of the first byte (0 ... 63)
	NB		: Number of bytes to be read (from 1 up to 64)

OUTPUT
	dataRead	: pointer to data read
	status		: CTX512B execution status returned

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// returned value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Read(%d,%d )", ADD, NB);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(dataRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512B_Read command
iCTx_512B_Read(ADD,NB);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=dataRead
	vBuf[7]=dataRead
	vBuf[8]=dataRead
	...	
	vBuf[x]=dataRead
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the CD97_Status
CopyMemory(dataRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Read(add:%d, nb:%d / dataRead:%s, Status:%02X, )",
		ADD,NB,wCSC_BTS(dataRead,vBuf[1]-4),*status);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512B_Update(BYTE ADD, BYTE NB,
												  BYTE* dataToWrite,
												  BYTE* dataRead, BYTE* status)
/*****************************************************************
UPDATE CTX512B
deletion if necessary, update then checking (reading bytes written)

INPUTS
	ADD			: adress of the first byte to write (0 ... 63)
	NB			: Number of bytes to write (from 1 up to 64)
	dataToWrite	: Data to write

OUTPUT
	dataRead	: Data read
	status		: CTX512B execution status returned

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Update(%d, %d, %s)",
		ADD,NB,wCSC_BTS(dataToWrite,NB));
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(dataRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512B_Update command
iCTx_512B_Update(ADD,NB,dataToWrite);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=dataRead
	vBuf[7]=dataRead
	vBuf[8]=dataRead
	...	
	vBuf[x]=dataRead
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status
CopyMemory(dataRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Update(add:%d ,bnBytes:%d ,dataToWrite:%s / dataRead:%s, status:%d)",
			ADD,NB,wCSC_BTS(dataToWrite,NB),
			wCSC_BTS(dataRead,vBuf[1]-4),*status);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512B_Halt (BYTE param, BYTE* status)
/*****************************************************************
HALT CTX512B

INPUTS
	param	0x00 : desactivates ticket using 'desactivate' instruction
			(others RFU)
OUTPUTS
	status	: CTX512B execution status returned


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Halt(%02X)", param);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for CTx512B_Halt command
iCTx_512B_Halt(param);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=status
	vBuf[5]=EOF
	vBuf[6]=CRCL
	vBuf[7]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status 
*status = vBuf[4];
	
if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512B_Halt(param:%02X / status:%d )",param,*status);
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);

}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_List(BYTE	RFU,
												  BYTE* nbTickets,
												  BYTE* serialNumbers,
												  BYTE* status)
/*****************************************************************
LIST CTX512X tickets
Performs anticollision and answers serial numbers of all the chips
present in the antenna field

INPUTS
	RFU				: 0x00, RFU
OUTPUTS
	nbTickets		: number of tickets in the antenna field
	serialNumbers	: list of the serial numbers retrieved
					(2 LSB serial number bytes for each ticket)
	status			: CTX512X execution status returned


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// returned value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// answer frame size

if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CTx512x_List(RFU:%d)",RFU);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)		return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointers value
if(nbTickets==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);
if(serialNumbers==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepare the command buffer for CTx512X_List command
iCTX_512X_List(RFU);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=nb
	vBuf[7]=serialNum
	vBuf[8]=serialNum
	vBuf[9]=serialNum
	...	
	vBuf[x]=serialNum
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)	return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<4)		return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status and Data
*nbTickets = vBuf[6];
CopyMemory(serialNumbers,&vBuf[7],vBuf[1]-5);
*status = vBuf[5];
	
if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_List(RFU:%d / nb tickets:%d, serial numbers:%s, Status:%02X)",
			RFU,*nbTickets,wCSC_BTS(serialNumbers,vBuf[1]-5),*status);

} /* LOG DEBUG */
return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_Select(BYTE* serialNumber,
													BYTE* serialNumberRead,
													BYTE* status)
/*****************************************************************
SELECT CTX512X
Selects a ticket with its serial number

INPUT
	serialNumber : pointer to the buffer containing the serial
					number (2 bytes)

OUTPUTS
	serialNumberRead	: pointer to serial number read (2 bytes)
						(sould be equal to serialNumber)
	status				: CTX512X execution status returned


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// returned value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// answer frame size

if(swDEBUG==1){ /* DEBUG */
		sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Select(%02X%02X)",serialNumber[0],serialNumber[1]);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)		return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(serialNumberRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepare the command buffer for CTx512X_Select command
iCTX_512X_Select(serialNumber);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=serialNum
	vBuf[7]=serialNum
	vBuf[8]=EOF
	vBuf[9]=CRCL
	vBuf[10]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)	return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<4)		return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status and Data
CopyMemory(serialNumberRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];
	
if(swDEBUG==1)
{ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Select(serialNumber:%02X%02X / serialNumberRead:%02X%02X, Status:%02X)",
			serialNumber[0],serialNumber[1],
			serialNumberRead[0],serialNumberRead[1],*status);

} /* LOG DEBUG */
return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_Read (BYTE ADD,
												   BYTE NB,
												   BYTE* dataRead,
												   BYTE* status)
/*****************************************************************
READ CTX512X
Reads a number of bytes (NB) from a given address (ADD)

INPUTS
	ADD		: adress of the first byte (0 ... 63)
	NB		: Number of bytes to be read (from 1 up to 64)

OUTPUT
	dataRead	: pointer to data read
	status		: CTX512X execution status returned

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// returned value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Read(%d,%d )", ADD, NB);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(dataRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512X_Read command
iCTx_512X_Read(ADD,NB);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=dataRead
	vBuf[7]=dataRead
	vBuf[8]=dataRead
	...	
	vBuf[x]=dataRead
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the CD97_Status
CopyMemory(dataRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Read(add:%d, nb:%d / dataRead:%s, Status:%02X, )",
		ADD,NB,wCSC_BTS(dataRead,vBuf[1]-4),*status);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_Update(BYTE ADD, BYTE NB,
												  BYTE* dataToWrite,
												  BYTE* dataRead, BYTE* status)
/*****************************************************************
UPDATE CTX512X
deletion if necessary, update then checking (reading bytes written)

INPUTS
	ADD			: adress of the first byte to write (0 ... 63)
	NB			: Number of bytes to write (from 1 up to 64)
	dataToWrite	: Data to write

OUTPUT
	dataRead	: Data read
	status		: CTX512X execution status returned

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Update(%d, %d, %s)",
		ADD,NB,wCSC_BTS(dataToWrite,NB));
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(dataRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512X_Update command
iCTx_512X_Update(ADD,NB,dataToWrite);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=dataRead
	vBuf[7]=dataRead
	vBuf[8]=dataRead
	...	
	vBuf[x]=dataRead
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status
CopyMemory(dataRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Update(add:%d ,bnBytes:%d ,dataToWrite:%s / dataRead:%s, status:%d)",
			ADD,NB,wCSC_BTS(dataToWrite,NB),
			wCSC_BTS(dataRead,vBuf[1]-4),*status);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_Halt (BYTE param, BYTE* status)
/*****************************************************************
HALT CTX512X

INPUTS
	param	0x00 : desactivates ticket using 'desactivate' instruction
			(others RFU)
OUTPUTS
	status	: CTX512X execution status returned


RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;					// return value from CSC_SendReceive
BYTE vBuf[255];				// local temp buffer
DWORD vLen;					// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Halt(%02X)", param);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the command buffer for CTx512X_Halt command
iCTx_512X_Halt(param);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=status
	vBuf[5]=EOF
	vBuf[6]=CRCL
	vBuf[7]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<3)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status 
*status = vBuf[4];
	
if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Halt(param:%02X / status:%d )",param,*status);
} /* LOG DEBUG */

return wCSC_DebugLog(tdeb,RCSC_Ok);

}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_Write(BYTE ADD, BYTE NB,
												  BYTE* dataToWrite,
												  BYTE* dataRead, BYTE* status)
/*****************************************************************
WRITE CTX512X
deletion if necessary, update then checking (reading bytes written)

INPUTS
	ADD			: adress of the first byte to write (0 ... 63)
	NB			: Number of bytes to write (from 1 up to 64)
	dataToWrite	: Data to write

OUTPUT
	dataRead	: Data read (former existing data computed with the
						logical OR with the written data)
	status		: CTX512X execution status returned

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Write(%d, %d, %s)",
		ADD,NB,wCSC_BTS(dataToWrite,NB));
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// check pointer value
if(dataRead==NULL)return wCSC_DebugLog(tdeb,RCSC_Fail);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512x_Write command
iCTx_512X_Write(ADD,NB,dataToWrite);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Lng : number of response bytes
	vBuf[5]=status
	vBuf[6]=dataRead
	vBuf[7]=dataRead
	vBuf[8]=dataRead
	...	
	vBuf[x]=dataRead
	vBuf[x+1]=EOF
	vBuf[x+2]=CRCL
	vBuf[x+3]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<5)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status
CopyMemory(dataRead,&vBuf[6],vBuf[1]-4);
*status = vBuf[5];

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Write(add:%d ,nbBytes:%d ,dataToWrite:%s / dataRead:%s, status:%d)",
			ADD,NB,wCSC_BTS(dataToWrite,NB),
			wCSC_BTS(dataRead,vBuf[1]-4),*status);
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_Authenticate(BYTE ADD,
													BYTE kif_kref,
													BYTE kvc_zero,
													BYTE* status,
													BYTE* dataSAMLength,
													BYTE* dataSAM)
/*****************************************************************
Authenticate CTX512X

Authentication of a CTM512B area

INPUTS
	ADD			: address of the area to authenticate
	kif_kref	: specifies the KIF or the key reference
					(if key reference used, kvc_zero must be set to 0x00)
	kvc_zero	: specifies the KVC if the KIF has been specified in kif_kref
					(if the KIF has not been specified in kif_kref, must be set to 0x00)

OUTPUT
	status		: CTX512X execution status returned
	dataSAMLength : length of the data returned in dataSAM
	dataSAM		: buffer containing the SAM status returned when
					an error occurs, i.e. when status = $06

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Authenticate(%d, %d, %d)",
		ADD,kif_kref,kvc_zero);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512x_Authenticate command
iCTx_512X_Authenticate(ADD,kif_kref,kvc_zero);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Length (ln(status) + ln(dataSAM))
	vBuf[5]=status
	vBuf[6]=dataSAM			... if present
	...
	vBuf[6+x]=dataSAM		... if present
	vBuf[7+x]=EOF
	vBuf[8+x]=CRCL
	vBuf[9+x]=CRCH
*/

// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<4)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status
*status = vBuf[5];

// copy the local buffer to the dataSAMLength
*dataSAMLength = vBuf[4] - 1;

// copy the local buffer to the dataSAM buffer
CopyMemory(dataSAM, &vBuf[6], *dataSAMLength);


if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_Authenticate(add:%d ,kif_kref:%d ,kvc_zero:%d / status:%d, dataSAMLength:%d, dataSAM:%s)",
			ADD,kif_kref,kvc_zero,*status,*dataSAMLength,wCSC_BTS(dataSAM,*dataSAMLength));
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CTx512x_WriteKey( BYTE kif_kref,
												BYTE kvc_zero,
												BYTE* status,
												BYTE* dataSAMLength,
												BYTE* dataSAM)
/*****************************************************************
WriteKey CTM512B

Compute and write the key in the CTM512B

INPUTS
	kif_kref	: specifies the KIF or the key reference
					(if key reference used, kvc_zero must be set to 0x00)
	kvc_zero	: specifies the KVC if the KIF has been specified in kif_kref
					(if the KIF has not been specified in kif_kref, must be set to 0x00)

OUTPUT
	status		: CTX512X execution status returned
	dataSAMLength : length of the data returned in dataSAM
	dataSAM		: buffer containing the SAM status returned when
					an error occurs, i.e. when status = $06

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_Fail
	RCSC_DataWrong
	RCSC_NoAnswer
	RCSC_UnknowClassCommand
	RCSC_Ok
*****************************************************************/
{
INT vRet;				// return value from CSC_SendReceive
BYTE vBuf[255];			// local temp buffer
DWORD vLen;				// The answer frame size

if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_WriteKey(%d, %d)",
		kif_kref,kvc_zero);
} /* LOG DEBUG */

// if CSC_Open not executed
if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

// discard all characters from the output or input buffer.
wCSC_FlushCOM();

// prepares the buffer for CTx512x_Authenticate command
iCTx_512X_WriteKey(kif_kref,kvc_zero);

// Send a command frame to the CSC, and wait 2 seconds for the answer
vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

/*	data received :
	vBuf[0]=STA
	vBuf[1]=LNG
	vBuf[2]=CLASS
	vBuf[3]=INS
	vBuf[4]=Length (ln(status) + ln(dataSAM))
	vBuf[5]=status
	vBuf[6]=dataSAM			... if present
	...
	vBuf[6+x]=dataSAM		... if present
	vBuf[7+x]=EOF
	vBuf[8+x]=CRCL
	vBuf[9+x]=CRCH
*/
// if CSC_SendReceived command failed
if(vRet!=RCSC_Ok)return wCSC_DebugLog(tdeb,vRet);

// if not enough data received
if(vBuf[1]<4)return wCSC_DebugLog(tdeb,RCSC_DataWrong);

// copy the local buffer to the Status
*status = vBuf[5];

// copy the local buffer to the dataSAMLength
*dataSAMLength = vBuf[4] - 1;

// copy the local buffer to the dataSAM buffer
CopyMemory(dataSAM, &vBuf[6], *dataSAMLength); 


if(swDEBUG==1){ /* DEBUG */
	sprintf_s(tdeb,sizeof(tdeb),"CTx512x_WriteKey(kif_kref:%d ,kvc_zero:%d / status:%d, dataSAMLength:%d, dataSAM:%s)",
			kif_kref,kvc_zero,*status,*dataSAMLength,wCSC_BTS(dataSAM,*dataSAMLength));
} /* LOG DEBUG */


return wCSC_DebugLog(tdeb,RCSC_Ok);
}



/****************************************************************/
__declspec( dllexport ) BOOL WINAPI PortNameIsPresent(LPSTR ComName, BOOL All)
/*****************************************************************
PortNameIsPresent

Wrapper on the CDCUtil function
Look if the given Port is present or not

INPUTS
	ComName		: Name of the Communication port to look for
				the format syntax is like "COM2"
	All			: Look for all devices instead of USB only

OUTPUT

RETURNS
	FALSE		if the COM port is not present
	TRUE		if the COM port is present
*****************************************************************/
{
	CHAR LongComName[50];
	sprintf_s(LongComName,sizeof(LongComName),"\\\\.\\%s",ComName);

	return (InternalUsePortNameIsPresent(LongComName, All));
}

/****************************************************************/
__declspec( dllexport ) BOOL WINAPI PortIsCDC(LPSTR ComName)
/*****************************************************************
PortIsCDC

Wrapper on the CDCUtil function
Look if the given input name matches with a CDC type.


INPUTS
	ComName		: Name of the Communication port to look for
				the format syntax is like "COM2"

OUTPUT

RETURNS
	FALSE		if the COM port is not present
	TRUE		if the COM port is present
*****************************************************************/
{
	return (CDCUtilPortIsCDC(ComName));
}

/****************************************************************/
__declspec( dllexport ) BOOL WINAPI RecoverCDCPort (LPSTR ComName,DWORD dwDisconnectTimeout, DWORD dwReconnectTimeout)
/*****************************************************************
RecoverCDCPort

Wrapper on the CDCUtil function
Manage the Disconnect / Reconnect with a CDC port 

INPUTS
	ComName				: Name of the Communication port to look for
							the format syntax is like "COM2"
	dwDisconnectTimeout	: Time before Disconnection
	dwReconnectTimeout	: Time before Reconnection

OUTPUT

RETURNS
	FALSE		if the operation fails
	TRUE		if the operation Succeed
*****************************************************************/
{
	return (CDCUtilRecoverCDCPort(ComName, dwDisconnectTimeout, dwReconnectTimeout));
}

/****************************************************************/
__declspec( dllexport ) BOOL WINAPI CSC_SendCOM(BYTE* BufIN,DWORD LnIN)
/*****************************************************************
Send only data to the communication port

INPUTS
	BufIN							Frame to send to COM port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Function fails
*****************************************************************/
{
	return wCSC_SendCOM(BufIN,LnIN);
}

/****************************************************************/
__declspec( dllexport ) BOOL WINAPI CSC_ReceiveCOM(DWORD TimeOut,DWORD Len,BYTE* BufOUT)

/*****************************************************************
Send only data to the communication port

INPUTS
	BufIN							Frame to send to COM port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Function fails
*****************************************************************/
{
	return wCSC_ReceiveCOM(TimeOut,Len,BufOUT);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_SetSAMBaudratePPS( BYTE ProProt, BYTE ParamFD, WORD *Status)
/*****************************************************************
Perform a PPS on SAM using ISO17816 mode
Parameters:
I	BYTE	ProProt		Proposed protocol (0 for T=0; 1 for T=1)
I	BYTE	ParamFD		FiDi parameter
O	WORD*	Status		$0000 : OK
						$FFFF: error on 1st received byte
						$FFFE: error on 2nd received byte
						$FFFD: error on 3rd received byte
						$FFFC: error on 4th received byte
*****************************************************************/

{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
	sprintf_s(tdeb,sizeof(tdeb),"CSC_SetSAMBaudratePPS( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"CSC_SetSAMBaudratePPS(%02X, %02X, ...)", ProProt, ParamFD);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iCSC_SetSAMBaudratePPS(ProProt, ParamFD);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if(Status != NULL)
	{
		*Status = vBuf[4]*256+vBuf[5];
		
		if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"CSC_SetSAMBaudratePPS(%02X, %02X, %04X)", ProProt, ParamFD, *Status);
																						
		} // LOG DEBUG 
	}

	if (*Status != 0)
		return wCSC_DebugLog(tdeb,RCSC_Fail);

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI EMVCo_UserInterface (BYTE SequenceNumber,LPBYTE Status)
/*****************************************************************
Performs EMV’s standard LEDs activation and buzzer tones.
Parameters:
I	BYTE	SequenceNumber	$01: Not ready: all LEDs off, buzzer off
							$02: Idle: LED1 on during 200 ms, buzzer off
							$03: Ready to Read: LED1 on, buzzer off
							Option 1 for Card Read Successfully / Processing Error
							$11: Card read successfully: 4 LEDs in sequence (250 ms sequence and 750 ms remaining) and success tone
							$12: Processing Error: all LEDs off and alert tone
							Option 2 for Card Read Successfully / Processing Error
							$21: Card read successfully: 3 LEDs in sequence (125 ms sequence and 750 ms remaining) and success tone.
							$22: Processing Error: LED 4 on and alert tone
O	LPBYTE Status			$00: Ok
							$FF: Sequence not implemented
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
	sprintf_s(tdeb,sizeof(tdeb),"EMVCo_UserInterface( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"EMVCo_UserInterface(%02X, ...)", SequenceNumber);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iEMVCo_UserInterface(SequenceNumber);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if(Status != NULL)
	{
		*Status = vBuf[4];
		
		if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"EMVCo_UserInterface(%02X, %02X)", SequenceNumber, *Status);
																						
		} // LOG DEBUG 
	}

	if (*Status != 0)
		return wCSC_DebugLog(tdeb,RCSC_Fail);

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI EMVCo_Contactless (BYTE CommandNumber,
								LPBYTE Parameters,
								LPBYTE Status,
								LPBYTE Length,
								LPBYTE PICCData)
/*****************************************************************
Performs EMV’s featured commands: RF field reset, PICC activation or PICC removal
Parameters:
I	BYTE	CommandNumber	$00: RF field off, Parameters empty
							$01: RF field reset, Parameters empty
							$02: Polling / Anti-collision / Activation, Parameters, 1 byte = number of polling loops
							$03: Removal, Parameters, 1 byte = number of polling loops
							$04: EMV internal loop-back, Parameters, 1 byte = number of loops ($FF = infinite)
							$05: Set/Reset EMV flag. Parameters, 1 byte = EMV flag value. This allows to set/reset the EMV behavior (EMV’s ISO14443 implementation), using no EMV command set. This flag is automatically managed if EMV command set is used.
							$06: Polling / Anti-collision / Activation + other technologies polling.
							Parameters:
							Byte 1: number of polling loops
							Byte 2 to byte 6: EHP parameters (5 first bytes), as define in “Enter Hunt Phase” command.
I	LPBYTE	Parameters		See above
O	LPBYTE	Status			$00: No PICC found or action accomplished
							$01: Type A PICC found
							$02: Type B PICC found
							$03: Type INNOVATRON PICC found
							$06: Type CTS/CTM PICC found
							$0D: Type ST SR PICC found
							$0E: Type Felica PICC found
							$10: More than one PICC found
							$11: Communication error
							$12: Timeout error
							$FF: Command not implemented
IO	LPBYTE	Length			Length of the PICC data
O	LPBYTE	PICCData		PICC data depends of the PICC type detected:
							Type A:
							ATQA (2), SAK (1), UID Length (1), UID (UID Length), ATS (ATS Length)
							Type B:
							ATQB (12), ATTRIB Response Length (1), ATTRIB Response (ATTRIB Response Length)
							Other types: no data
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
	sprintf_s(tdeb,sizeof(tdeb),"EMVCo_Contactless( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"EMVCo_Contactless(%02X, %s, ...)", CommandNumber,wCSC_BTS(Parameters,8));
	} // LOG DEBUG 

	// prepares the command buffer for command
	iEMVCo_Contactless(CommandNumber,Parameters);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (Length != NULL) && (PICCData != NULL))
	{
		*Status = vBuf[4];
		*Length = vBuf[5];
		CopyMemory (PICCData,&vBuf[6],*Length);
		
		if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"EMVCo_Contactless(%02X, %02X, ..., %02X, %02X, %s)", CommandNumber, Parameters[0], *Status, *Length, wCSC_BTS(PICCData,*Length));
																						
		} // LOG DEBUG 
	}

	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CalypsoRev3_GetMode (BYTE *Mode)
/*****************************************************************
Get the Calypso Rev3 mode flag. In Calypso Rev3 mode, the reader will try to manage the card as a Calypso rev3 card if the card is compliant.
Parameters:
O	BYTE*	Mode			$00: Calypso Rev3 mode disabled.
							$01: Calypso Rev3 mode enabled.
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"CalypsoRev3_GetMode( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"CalypsoRev3_GetMode(...)");
	} // LOG DEBUG 

	// prepares the command buffer for command
	iCalypsoRev3_GetMode();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if(Mode != NULL)
	{
		*Mode = vBuf[4];
		
		if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"CalypsoRev3_GetMode(%02X)", *Mode);
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD WINAPI CalypsoRev3_SetMode (BYTE Mode)
/*****************************************************************
Set the Calypso Rev3 mode flag. In Calypso Rev3 mode, the reader will try to manage the card as a Calypso rev3 card if the card is compliant.
Parameters:
I	BYTE	Mode			$00: Disable Calypso Rev3 mode.
							$01: Enable Calypso Rev3 mode.
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"CalypsoRev3_SetMode( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"CalypsoRev3_SetMode(%02X)",Mode);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iCalypsoRev3_SetMode(Mode);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"CalypsoRev3_SetMode(%02X)", Mode);
	} // LOG DEBUG 
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFUL_Identify (BYTE RFU, BYTE *Status)
/*****************************************************************
Determines the Mifare UltraLight type. This command does not card detection. 
The card must first be detected using CSC_SearchCardExt function with ISOA type. 
This command is not mandatory. 
However, this command will allow strict parameters checking for other functions of this section.
Parameters :
I	BYTE	RFU			RFU, should be set to 0.
O	BYTE	*Status		$00 no answer
						$01 bad CRC
						$10 + NAK code from MFUL (see NAK codes)
						$20 Mifare UltraLight (MF0ICU1)
						$21 Mifare UltraLight C (MF0ICU2
						$22 Mifare UltraLight EV1 640 bits (MF0UL11)
						$23 Mifare UltraLight EV1 1312 bits (MF0UL21)
						$24 unknown Mifare UltraLight
						$25 another ISO14443A chip
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
	sprintf_s(tdeb,sizeof(tdeb),"MFUL_Identify( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFUL_Identify(%02X ,...)", RFU);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFUL_Identify(RFU);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if(Status != NULL)
	{
		*Status = vBuf[5];
		
		if(swDEBUG==1){ // DEBUG 
		sprintf_s(tdeb,sizeof(tdeb),"MFUL_Identify(%02X, %02X)", RFU, *Status);
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFUL_Read (BYTE ByteAddress, BYTE Nb, BYTE *Status,
				 BYTE *LngData, BYTE *ReadData)
/*****************************************************************
Reads of a number of bytes at a given address
Parameters :
I	BYTE	ByteAddress		Address of the first byte to read, multiple of 4.
							0…$3C for Mifare UltraLight (MF0ICU1)
							0…$AC for Mifare UltraLight C (MF0ICU2)
							0…$4C for Mifare UltraLight EV1 640 bits (MF0UL11)
							0…$A0 for Mifare UltraLight EV1 1312 bits (MF0UL21)
I	BYTE	Nb				Number of bytes to read
							0…$40 for Mifare UltraLight (MF0ICU1)
							0…$B0 for Mifare UltraLight C (MF0ICU2)
							0…$50 for Mifare UltraLight EV1 640 bits (MF0UL11)
							0…$A4 for Mifare UltraLight EV1 1312 bits (MF0UL21)
O	BYTE	*Status			$00 No answer
							$01 Bad CRC
							$02 Success
							$03 Bad Parameters
							$10 + NAK code from MFUL (see NAK codes)
							Note: if Status is different from $02 or $03, the card will come into the HALT state, 
							so CSC_SearchCardExt function should be called to perform other operation.
O	BYTE	*LngData		Read data length
O	BYTE	*ReadData		Read data
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFUL_Read( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFUL_Read(%02X ,%02X, ...)", ByteAddress,Nb);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFUL_Read(ByteAddress,Nb);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (LngData != NULL) && (ReadData != NULL))
	{
		*Status = vBuf[5];
		*LngData = vBuf[4]-1;
		CopyMemory (ReadData,&vBuf[6],*LngData);

		if(swDEBUG==1){ // DEBUG 
		 sprintf_s(tdeb,sizeof(tdeb),"MFUL_Read(%02X ,%02X, %02X, %02X, %s)", ByteAddress,Nb,*Status,*LngData,wCSC_BTS(ReadData, *LngData));
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFUL_Write (BYTE ByteAddress, BYTE Nb,BYTE *DataToWrite, 
				  BYTE *Status, BYTE *LngData, BYTE *ReadData)
/*****************************************************************
Writes, then checks by reading the bytes written at a given address
Parameters :
I	BYTE	ByteAddress		address of the first byte to write, multiple of 4
							0…$3C for Mifare UltraLight (MF0ICU1)
							0…$BC for Mifare UltraLight C (MF0ICU2)
							0…$4C for Mifare UltraLight EV1 640 bits (MF0UL11)
							0…$A0 for Mifare UltraLight EV1 1312 bits (MF0UL21)
I	BYTE	Nb				number of bytes to write, multiple of 4
							0…$40 for Mifare UltraLight (MF0ICU1)
							0…$C0 for Mifare UltraLight C (MF0ICU2)
							0…$50 for Mifare UltraLight EV1 640 bits (MF0UL11)
							0…$A4 for Mifare UltraLight EV1 1312 bits (MF0UL21)
I	BYTE	*DataToWrite	data to write
O	BYTE	*Status			$00 No answer
							$01 Bad CRC
							$02 Success
							$03 Bad parameters
							$10 + NAK code from MFUL (see NAK codes)
							$82 Verification failure; read data are returned.
							Note: if Status is different from $02 or $03, the card will come into the HALT state, 
							so CSC_SearchCardExt function should be called to perform other operation.
O	BYTE	*LngData		Read data length
O	BYTE	*ReadData		Read data
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFUL_Write( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFUL_Write(%02X, %02X, %s, ...)", ByteAddress,Nb,wCSC_BTS(DataToWrite, Nb));
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFUL_Write(ByteAddress,Nb,DataToWrite);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (LngData != NULL) && (ReadData != NULL))
	{
		*Status = vBuf[5];
		*LngData = vBuf[4]-1;
		CopyMemory (ReadData,&vBuf[6],*LngData);

		if(swDEBUG==1){ // DEBUG 
		 sprintf_s(tdeb,sizeof(tdeb),"MFUL_Write(%02X, %02X, ..., %02X, %02X, %s)", ByteAddress,Nb,*Status,*LngData,wCSC_BTS(ReadData, *LngData));
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


/****************************************************************/
__declspec( dllexport ) DWORD MFULC_Authenticate (BYTE KeyNo, BYTE KeyV,
						  BYTE DIVLength, BYTE *DIVInput,
						  BYTE *Status, WORD *SAMStatus)
/*****************************************************************
Performs mutual authentication, to access protected area. 
This function uses a NXP SAM AV2. After power up or coupler reset, 
the SAM must be reset before using this function.
Parameters :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
O	BYTE	*Status		$00 No answer
						$01 Bad CRC
						$02 Success
						$03 Bad parameters
						$10 + NAK code from MFUL (see NAK codes)
O	WORD	*SAMStatus	$90 00 correct execution, authentication successful
						$90 1E correct execution, authentication failed
						Other execution not correct, see Mifare SAM AV2 (P5DF081) datasheet.
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULC_Authenticate( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULC_Authenticate(%02X, %02X, %02X, %s, ...)", KeyNo,  KeyV,DIVLength,wCSC_BTS(DIVInput, DIVLength));
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULC_Authenticate(KeyNo, KeyV, DIVLength, DIVInput);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (SAMStatus != NULL))
	{
		*Status = vBuf[5];
		*SAMStatus = vBuf[6]*256+vBuf[7];

		if(swDEBUG==1){ // DEBUG 
		 sprintf_s(tdeb,sizeof(tdeb),"MFULC_Authenticate(%02X, %02X, %02X, %s, %02X, %04X)",  KeyNo, KeyV,DIVLength,wCSC_BTS(DIVInput, DIVLength),*Status,*SAMStatus);
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULC_WriteKeyFromSAM  (BYTE KeyNo, BYTE KeyV, 
       						  BYTE DIVLength, BYTE *DIVInput,
							  BYTE *Status, WORD *SAMStatus)
/*****************************************************************
Retrieves the key from the NXP AV2 SAM and writes it in the Mifare UltraLight C. 
The key can also be written directly by the application, using the MFUL_Write function.
Note: as the SAM key entry should be dumpable, this key should be only present on SAMs in protected personalizing/issuing machines.
This function uses a NXP SAM AV2. After power up or coupler reset, the SAM must be reset before using this function.
Parameters  :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
O	BYTE	*Status		$00 No answer
						$01 Bad CRC
						$02 Success
						$03 Bad parameters
						$10 + NAK code from MFUL (see NAK codes)
O	WORD	*SAMStatus	$90 00 correct execution, authentication successful
						$90 1E correct execution, authentication failed
						Other execution not correct, see Mifare SAM AV2 (P5DF081) datasheet.
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULC_WriteKeyFromSAM( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULC_WriteKeyFromSAM(%02X, %02X, %02X, %s, ...)", KeyNo,  KeyV,DIVLength,wCSC_BTS(DIVInput, DIVLength));
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULC_WriteKeyFromSAM(KeyNo, KeyV, DIVLength, DIVInput);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (SAMStatus != NULL))
	{
		*Status = vBuf[5];
		*SAMStatus = vBuf[6]*256+vBuf[7];

		if(swDEBUG==1){ // DEBUG 
		 sprintf_s(tdeb,sizeof(tdeb),"MFULC_WriteKeyFromSAM(%02X, %02X, %02X, %s, %02X, %04X)",  KeyNo, KeyV,DIVLength,wCSC_BTS(DIVInput, DIVLength),*Status,*SAMStatus);
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULEV1_PasswordAuthenticate (BYTE *Password, BYTE *Status, BYTE *PACK)
/*****************************************************************
Performs password authentication, to access protected area.
Parameters  :
I	BYTE	*Password	password value for authentication (4 bytes)
O	BYTE	*Status		$00 No answer
						$01 Bad CRC
						$02 Success
						$03 Bad parameters
						$10 + NAK code from MFUL (see NAK codes)
O	BYTE	*PACK		Password Authentication Acknowledge (2 bytes, this is the value from the memory, PACK area)
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_PasswordAuthenticate( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_PasswordAuthenticate(%s, ...)", wCSC_BTS(Password, 4));
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULEV1_PasswordAuthenticate(Password);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (PACK != NULL))
	{
		*Status = vBuf[5];
		PACK[0] = vBuf[6];
		PACK[1] = vBuf[7];

		if(swDEBUG==1){ // DEBUG 
		 sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_PasswordAuthenticate(%s, %02X, %02X %02X)", wCSC_BTS(Password, 4), *Status, PACK[0], PACK[1]);
																						
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULEV1_CreateDiversifiedPasswordandPACK (BYTE KeyNo, BYTE KeyV, 
       											BYTE DIVLength, BYTE *DIVInput,
												WORD *SAMStatus,
												BYTE *Password, BYTE *PACK)
/*****************************************************************
Create a diversified password and password acknowledge from SAM.
Can be used before to personalize PWD and PACK, and before to use the MFULEV1_PasswordAuthenticate function. 
This function is not mandatory. It helps the application to create a diversified password. 
It does not write the password to the MFUL EV1. 
The application should write the password and PACK values in the memory using the MFUL_Write function.
This function uses a NXP SAM AV2. 
After power up or coupler reset, the SAM must be reset before using this function.
Parameters  :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
O	WORD	*SAMStatus	$90 00 correct execution, authentication successful
						$90 1E correct execution, authentication failed
						Other execution not correct, see Mifare SAM AV2 (P5DF081) datasheet.
O	BYTE	*Password	Diversified password (4 bytes)
O	BYTE	*PACK		Diversified Password Authentication Acknowledge (2 bytes)
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_CreateDiversifiedPasswordandPACK( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_CreateDiversifiedPasswordandPACK(%02X, %02X, %02X, %s, ...)", KeyNo,  KeyV,DIVLength,wCSC_BTS(DIVInput, DIVLength));
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULEV1_CreateDiversifiedPasswordandPACK(KeyNo,KeyV,DIVLength,DIVInput);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((SAMStatus != NULL) && (Password !=NULL) || (PACK != NULL)) 
	{
		*SAMStatus = vBuf[5]*256+vBuf[6];
		Password[0] = vBuf[7];
		Password[1] = vBuf[8];
		Password[2] = vBuf[9];
		Password[3] = vBuf[10];
		PACK[0] = vBuf[11];
		PACK[1] = vBuf[12];

		if(swDEBUG==1){ // DEBUG 
			sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_CreateDiversifiedPasswordandPACK(%02X, %02X, %02X, %s, %04X, %02X %02X %02X %02X, %02X %02X)", KeyNo,  KeyV,DIVLength,wCSC_BTS(DIVInput, DIVLength),*SAMStatus ,
				Password[0],Password[1],Password[2], Password[3],PACK[0], PACK[1]);
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULEV1_ReadCounter ( BYTE CounterNb, BYTE *Status,
							DWORD *CounterValue)
/*****************************************************************
Reads the current value of one of the 3 one-way counters.
Parameters  :
I	BYTE	CounterNb		counter number from $00 to $02
O	BYTE	*Status			$00 No answer
							$01 Bad CRC
							$02 Success
							$03 Bad parameters
							$10 + NAK code from MFUL (see NAK codes)
O	DWORD	*CounterValue	counter value from $000000 to $FFFFFF
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_ReadCounter( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_ReadCounter(%02X, ...)", CounterNb);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULEV1_ReadCounter(CounterNb);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (CounterValue !=NULL)) 
	{
		*Status = vBuf[5];
		*CounterValue = vBuf[6]*256*256+vBuf[7]*256+vBuf[8];

		if(swDEBUG==1){ // DEBUG 
			sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_ReadCounter(%02X, %02X, %u)", CounterNb, *Status, *CounterValue);
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULEV1_IncrementCounter (BYTE CounterNb, 
								DWORD IncrementValue,
								BYTE *Status)
/*****************************************************************
Increments one of the 3 one-way counters.
Parameters  :
I	BYTE	CounterNb		counter number from $00 to $02
I	DWORD	IncrementValue	increment value from $000000 to $FFFFFF
O	BYTE	*Status			$00 No answer
							$01 Bad CRC
							$02 Success
							$03 Bad parameters
							$10 + NAK code from MFUL (see NAK codes)
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_IncrementCounter( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_IncrementCounter(%02X, %u ...)", CounterNb, IncrementValue);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULEV1_IncrementCounter(CounterNb,IncrementValue);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if(Status != NULL)
	{
		*Status = vBuf[5];

		if(swDEBUG==1){ // DEBUG 
			sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_IncrementCounter(%02X, %u, %02X)", CounterNb, IncrementValue, *Status);
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULEV1_GetVersion ( BYTE *Status, BYTE *LngData, BYTE *Data)
/*****************************************************************
Retrieves information about the Mifare UltraLight EV1.
Parameters  :
O	BYTE	*Status		$00 No answer
						$01 Bad CRC
						$02 Success
						$03 Bad parameters
						$10 + NAK code from MFUL (see NAK codes)
O	BYTE	*LngData	Read data length (8)
O	BYTE	*ReadData	Version Information, 8 bytes, see below
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_GetVersion( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_GetVersion(...)");
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULEV1_GetVersion();

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (LngData != NULL) && (Data != NULL))
	{
		*Status = vBuf[5];
		*LngData = vBuf[4]-1;
		CopyMemory (Data,&vBuf[6],*LngData);

		if(swDEBUG==1){ // DEBUG 
			sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_GetVersion(%02X, %d,%s)",  *Status, *LngData, wCSC_BTS(Data,*LngData));
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}

/****************************************************************/
__declspec( dllexport ) DWORD MFULEV1_CheckTearingEvent (BYTE CounterNb,
								 BYTE *Status,
								 BYTE *Valid)
/*****************************************************************
Identifies if a tearing event happened on a specified counter.
Parameters  :
I	BYTE	CounterNb	counter number from $00 to $02
O	BYTE	*Status		$00 No answer
						$01 Bad CRC
						$02 Success
						$03 Bad parameters
						$10 + NAK code from MFUL (see NAK codes)
O	BYTE	*Valid		valid flag, $BD for normal operation, otherwise a tearing event has happened.
*****************************************************************/
{
	INT vRet;					// return value from CSC_SendReceive
	BYTE vBuf[255];				// local temp buffer
	DWORD vLen;					// The answer frame size

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_CheckTearingEvent( )");
	} // LOG DEBUG 

	// CSC_Open no executed
	if(!gCOMOpen)return wCSC_DebugLog(tdeb,RCSC_OpenCOMError);

	// discard all characters from the output or input buffer.
	wCSC_FlushCOM();

	if(swDEBUG==1){ // DEBUG
		sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_CheckTearingEvent(%02X, ...)", CounterNb);
	} // LOG DEBUG 

	// prepares the command buffer for command
	iMFULEV1_CheckTearingEvent(CounterNb);

	// Send a command frame to the CSC, and waits 2 seconds for the answer
	vRet=CSC_SendReceive(FuncTimeout,giCSCTrame,giCSCTrameLn,vBuf,&vLen);

	if(vRet!=RCSC_Ok)
		return wCSC_DebugLog(tdeb,vRet);

	// copy the local buffer to the external buffer
	if((Status != NULL) && (Valid !=NULL)) 
	{
		*Status = vBuf[5];
		*Valid = vBuf[6];

		if(swDEBUG==1){ // DEBUG 
			sprintf_s(tdeb,sizeof(tdeb),"MFULEV1_CheckTearingEvent(%02X, %02X, %02X)", CounterNb, *Status, *Valid);
		} // LOG DEBUG 
	}
	return wCSC_DebugLog(tdeb,RCSC_Ok);
}


