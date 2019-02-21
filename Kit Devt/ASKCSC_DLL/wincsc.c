/*****************************************************************
  Interface Windows Functions for CSC Module ( WINCSC.C )

  WIN32 Plateform.

  Copyright (C)2002-1999 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Thierry J. - ASK
*****************************************************************/


/*****************************************************************
  HISTORY :
  
Ver 4.05.03.253		 03-09-10  BL  
Ver 4.05.03.218	Beta 03-08-06  BL
Ver 4.04.03.022		 03-01-22  BL
Ver 4.04.02.333 Beta 02-11-19  BL
Ver 4.04.02.332 Alpha02-11-18  BL 
Ver 4.03.00.275		 02-10-02  BL
Ver 4.02.00.246		 02-09-04  BL
Ver	4.01.00.133-Beta 02-08-21  BL	
Ver 4.00.02.036		 02-02-05  SM		Add change speed capabilities
Ver 1.50.99.227      99-08-10  PMO		Parallel communication
Ver 1.07.99.142      99-05-18  THJ		First Commercial Version
Ver 1.06.99.130      99-05-06  THJ		Add the DEBUG LOG
Ver 1.01.99.081      99-03-26  THJ		Created
*****************************************************************/

/* Includes for constants, external variables and structures ****/
#include <windows.h>
#include <stdio.h>
#include <conio.h>

#include "csc_def.h"
#include "csc_ord.h"
#include "WinIo.h"

#define __WIN_CSC__
#include "wincsc.h"    // Interface WIN Fonctions prototypes
#include "FTD2XX.H"
// PC/SC header files
#include <winscard.h>
#include <scarderr.h>

#include "askcsc.h"
#include "ASKPCSCEsc.h"


/* Internal constants *******************************************/
#define INPUT_SIZE	512  // Buffer RX size
#define OUTPUT_SIZE	512  // Buffer TX size
#define FORWARD 0		 //	Parallel port configured to send data 
#define REVERSE 1		 //	Parallel port configured to receive data


/* Global Variables for internal use ****************************/
HINSTANCE HmdStub;			// Handler for Stub DLL
MYPROC ProcCallAppliFunc;
MYPROCCLOSE ProcPcscFilterClose; 
MYPROCOPEN ProcPcscFilterOpen; 

HANDLE hCOM;            // Serial Communication handle
BYTE bIOChannel=SERIAL;	// SERIAL, PARLLEL, USB or PCSC
HMODULE hLib;
BOOL 	SlowFrame;	// temporary for slow CSC rx at high baud rate
BOOL 	SoftReset;	// use soft reset, useful for GEN5XX USB CDC (avoid hard reset, loosing virtual com port)
BOOL 	PreserveCPUUsage;	// preserve CPU usage on host communication. Suitable for most operation. Unrecommended on some test suites
BOOL	NoRetryOnHostTimeout;	// no retry on timeout host

char m_INIFileName[MAX_PATH];

extern char swDEBUG;		// if =1 : Debug log actived
extern BOOL	bDirectIO;		// 1 : direct , 0 via driver

extern SCARDCONTEXT    hSC;
SCARDHANDLE     hCardHandle;

extern char sExtendedComName[MAX_PATH];
/* Definitions for parallel communication ***********************/

int myout( unsigned short port, int vl )
{
	if (bDirectIO)
	{
/*	__asm
		{
		xor edx,edx
		mov dx,port
		mov al,BYTE PTR vl
		out dx,al
		}
*/	}
	else
		SetPortVal(port, vl,1);		
	return 0;
}

int myin ( unsigned short port )
{
	if (bDirectIO)
		return (_inp (port));
	else
	{
		DWORD vl;
		GetPortVal (port,&vl,1);
		return vl;
	}
}

unsigned short PORTADRESS;
unsigned short DATA;
unsigned short STATUS;
unsigned short CONTROL;
unsigned short ECR;


/****************************************************************/
DWORD WINAPI wCSC_GetWinVersion(void)
/*****************************************************************
Find Windows Version

RETURNS
  wCSC_VER_ERROR    PlatForm Error
	wCSC_VER_WIN95    WIN95, WIN98 or later
	wCSC_VER_WINNT4   WIN NT4 or later
*****************************************************************/
{
OSVERSIONINFO osVer;

// Get Windows Version
osVer.dwOSVersionInfoSize=sizeof(osVer);
if(!GetVersionEx(&osVer))
			return wCSC_VER_ERROR;  // if GetVersionEx fails -> error

if(osVer.dwPlatformId==VER_PLATFORM_WIN32s)
			return wCSC_VER_ERROR;  // WIN32s found -> error

if(osVer.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
			return wCSC_VER_WIN95;  // WIN95 or WIN98

if(osVer.dwPlatformId==VER_PLATFORM_WIN32_NT)
	{
	if(osVer.dwMajorVersion>=4)return wCSC_VER_WINNT4; // WIN NT4 or more
	}
return wCSC_VER_ERROR;  // if other -> Error
}

/****************************************************************/
void WINAPI InitPCom( int sense)
/*****************************************************************
initialize the parallel port registers

INPUT
	sense		direction of the port
				(FORWARD or REVERSE)
*****************************************************************/
{
	/* outp(ECR,0x20); */
	if (sense ==  FORWARD)
		myout(CONTROL,0x04);
	else
		myout(CONTROL,0x25);
}



/****************************************************************/
BOOL WINAPI wCSC_OpenCOM(LPSTR ComName)
/*****************************************************************
Open the PC communication port

INPUTS
  ComName           Communication port Name (ex: "COM1", "LPT1" or "USB1") 

RETURNS
  TRUE              Function success
	FALSE             Function fail
*****************************************************************/
{

	LONG            lReturn;
	DWORD           cch = SCARD_AUTOALLOCATE;
	DWORD           dwAP;

	int iLatencyTimer;
	HANDLE hC;
	DCB dcb;
	COMMTIMEOUTS tmo={MAXDWORD, // The read operation is to return immediately
		0,		  // with the characters that have already been
		0,   // received, even if no characters have been received.
		0,
		0 };
	
	HmdStub = LoadLibrary(TEXT("CSC.DLL"));
	// If the handle is valid, try to get the function address.
	if (HmdStub != NULL)// STUB Lib exist and is present
	{
		ProcCallAppliFunc = (MYPROC) GetProcAddress(HmdStub, "StubSendAndReceive");
		ProcPcscFilterClose = (MYPROCCLOSE) GetProcAddress(HmdStub, "PcscFilterClose");
		ProcPcscFilterOpen = (MYPROCOPEN) GetProcAddress(HmdStub, "PcscFilterOpen");
		// If the function address is valid, call the Open function.
        if (NULL != ProcPcscFilterOpen) 
        {
			(ProcPcscFilterOpen) (ComName);
		}
		hCOM= (HANDLE)1;		// port open equivalent
		bIOChannel = STUB;
		return TRUE;
	}

if(hCOM)wCSC_CloseCOM();    // if COM already open -> close COM

bIOChannel=SERIAL;

if(ComName==NULL)return FALSE;

if(strstr(ComName,"ASK-RFID GEN5XX CCID"))	// CCID	
{
	DWORD NumPCSCDevices;
	if (CSC_GetPCSCNumDevices (&NumPCSCDevices) != RCSC_Ok)
		return (FALSE);

	lReturn = SCardConnect( hSC,ComName,SCARD_SHARE_DIRECT,	SCARD_PROTOCOL_UNDEFINED,
							&hCardHandle,&dwAP );

	if (SCARD_S_SUCCESS != lReturn )
		return (FALSE);

	memcpy(sExtendedComName,ComName,strlen(ComName));

	SetCCIDPolling(FALSE);


	hCOM= (HANDLE)1;		// port open equivalent
	bIOChannel=CCID;
	return TRUE;            /* No error */
}
else if(strstr(ComName,"ASK"))	// PCSC	
{
	DWORD NumPCSCDevices;
	if (CSC_GetPCSCNumDevices (&NumPCSCDevices) != RCSC_Ok)
		return (FALSE);

	lReturn = SCardConnect( hSC,ComName,SCARD_SHARE_DIRECT,	SCARD_PROTOCOL_UNDEFINED,
							&hCardHandle,&dwAP );
	if (SCARD_S_SUCCESS != lReturn )
		return (FALSE);

	if (SetPCSCPolling (0) != SCARD_S_SUCCESS)
		return (FALSE);

	if (SetPCSCCRC (1) != SCARD_S_SUCCESS)
		return (FALSE);

	hCOM= (HANDLE)1;		// port open equivalent
	bIOChannel=PCSC;
	return TRUE;            /* No error */
}

if(strstr(ComName,"LPT"))
	{
		{  
			char pnum;
			if (!bDirectIO)
			{
				if ((hLib = LoadLibrary ("WINIO.DLL")) == NULL)
					return FALSE;
				InitializeWinIo = 	(BOOL  (_stdcall * )()) GetProcAddress (hLib,"InitializeWinIo");			
				ShutdownWinIo = (void  (_stdcall *)())GetProcAddress (hLib,"ShutdownWinIo");			
				GetPortVal = (BOOL  (_stdcall *)(WORD, PDWORD, BYTE))GetProcAddress (hLib,"GetPortVal");			
				SetPortVal = (BOOL(_stdcall *)(WORD , DWORD , BYTE ))GetProcAddress (hLib,"SetPortVal");
				InitializeWinIo ();
			}
			/* Reads ports adresses in the BIOS */
			memcpy(&pnum,&ComName[7],1);
			switch(pnum)
			{
				case '1' :
					PORTADRESS = 0x378;
					break;
				case '2' :
					PORTADRESS = 0x278;
					break;
				case '3' :
					PORTADRESS = 0x3BC;
					break;
				default :
					PORTADRESS = 0;
			}
			if ( PORTADRESS != 0 )            /* Interface is available ? */
			{                                                      /* Yes */
				DATA = PORTADRESS;
				STATUS = PORTADRESS + 1;
				CONTROL = PORTADRESS + 2;
				ECR = PORTADRESS + 0x402;
				myout(ECR,0x20);		/* Port configured as bidirectionnal PS/2 port */
				bIOChannel=PARALLEL;
				hCOM= (HANDLE)1;		// port open equivalent
				return TRUE;            /* No error */
			}
			else
			return FALSE;                    /* Error: no interface */
		}
	}

else if(strstr(ComName,"USB"))
{
	if (FT_Open(ComName[3]-'0'-1, &hCOM)!=FT_OK) 
		return FALSE;

	bIOChannel=USB;

	// Reset Device
	if (FT_ResetDevice(hCOM)!=FT_OK) return wCSC_CloseCOM();

	// Initializes the communications parameters 
	iLatencyTimer = GetPrivateProfileInt ("Configuration","USBLatencyTimer",2,m_INIFileName);
	if (FT_SetBaudRate (hCOM, ComSpeed) != FT_OK) return wCSC_CloseCOM();
	if (FT_SetDataCharacteristics (hCOM,FT_BITS_8,FT_STOP_BITS_1,FT_PARITY_NONE) != FT_OK) return wCSC_CloseCOM();
	if (FT_SetLatencyTimer(hCOM, iLatencyTimer) != FT_OK) return wCSC_CloseCOM();
	if (FT_SetUSBParameters(hCOM, 512, 0) != FT_OK) return wCSC_CloseCOM();
	if (FT_SetTimeouts(hCOM, 2, 0) != FT_OK) return wCSC_CloseCOM();
	return TRUE;
}
if (PreserveCPUUsage == 0)
	hC=CreateFile(ComName,
			GENERIC_READ | GENERIC_WRITE,          // Read and Write communication
			0,NULL,                                // No Security attributs
			OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL /*| FILE_FLAG_OVERLAPPED*/,NULL);
else
	hC=CreateFile(ComName,
			GENERIC_READ | GENERIC_WRITE,          // Read and Write communication
			0,NULL,                                // No Security attributs
			OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,NULL);



if(hC==INVALID_HANDLE_VALUE)return FALSE;

ZeroMemory(&dcb,sizeof(DCB));
dcb.DCBlength = sizeof (DCB);
dcb.BaudRate=ComSpeed;		  // set BAUD RATE
dcb.ByteSize=8;               // 8 bits
dcb.Parity=NOPARITY;          // no parity
dcb.StopBits=ONESTOPBIT;      // one stop bit
dcb.fAbortOnError=FALSE;

hCOM=hC;
// Configures a communications device 
if(!SetCommState(hC,&dcb))return wCSC_CloseCOM();

// Sets the time-out parameters
if(!SetCommTimeouts(hC,&tmo))return wCSC_CloseCOM();

// Specifies a set of events to be monitored 
//if(!SetCommMask(hC,EV_RXCHAR|EV_TXEMPTY|EV_ERR))return wCSC_CloseCOM();

// Initializes the communications parameters 
if(!SetupComm(hC,INPUT_SIZE,OUTPUT_SIZE))return wCSC_CloseCOM();

return TRUE;
}

#include <setupapi.h>
const char ReaderName[] = {'A','S','K',0x00};
const char PCSCName[]   = {'(','P','C','/','S','C',')',0x00};

BOOL Restart_ASK_PCSC_Device ()
{
HDEVINFO				hDevInfo;
SP_DEVINFO_DATA			DeviceInfoData;
DWORD					i;
SP_PROPCHANGE_PARAMS	pcp;
DWORD					DataT;
LPTSTR					buffer = NULL;
DWORD					buffersize = 0;
char					Reader[4];
char					Driver[8];

	// Create a HDEVINFO with all present devices.
	hDevInfo = SetupDiGetClassDevs(NULL,
								   0, // Enumerator
								   0,
								   DIGCF_PRESENT | DIGCF_ALLCLASSES );

	if (hDevInfo == INVALID_HANDLE_VALUE) return FALSE;

	// Enumerate through all devices in Set.
	memset(Reader,0x00,sizeof(Reader));
	memset(Driver,0x00,sizeof(Driver));
	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	for (i=0;SetupDiEnumDeviceInfo(hDevInfo,i,&DeviceInfoData);i++)
	{
		//
		// Call function with null to begin with, 
		// then use the returned buffer size (doubled)
		// to Alloc the buffer. Keep calling until
		// success or an unknown failure.
		//
		//  Double the returned buffersize to correct
		//  for underlying legacy CM functions that 
		//  return an incorrect buffersize value on 
		//  DBCS/MBCS systems.
		// 
		while (!SetupDiGetDeviceRegistryProperty(hDevInfo,&DeviceInfoData,
												SPDRP_DEVICEDESC,
												&DataT,
												(PBYTE)buffer,
												buffersize,
												&buffersize))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				// Change the buffer size.
				if (buffer) LocalFree(buffer);
				// Double the size to avoid problems on 
				// W2k MBCS systems per KB 888609. 
				buffer = (char *)LocalAlloc(LPTR,buffersize * 2);
			}
			else
			{
				//  Cleanup
				if (buffer) LocalFree(buffer);
				SetupDiDestroyDeviceInfoList(hDevInfo);
				return FALSE;
			}
		}

		if (buffersize>12)
		{
			memcpy(Reader,buffer,3);
			memcpy(Driver,&buffer[buffersize-8],8);

			if (memcmp(ReaderName,Reader,3)==0) 
			{
				if (memcmp(PCSCName,Driver,8)==0)
				{
					// Inform setup about property change so that it can restart the device.
					pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
					pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
					pcp.StateChange = DICS_PROPCHANGE;
					pcp.Scope = DICS_FLAG_CONFIGSPECIFIC;
					pcp.HwProfile = 0;
					if (SetupDiSetClassInstallParams(hDevInfo, &DeviceInfoData, &pcp.ClassInstallHeader,sizeof(pcp))==FALSE) break;
					if (SetupDiChangeState(hDevInfo, &DeviceInfoData)==FALSE) break;
				}      
			}
		}
	}

	if ( GetLastError()!=NO_ERROR && GetLastError()!=ERROR_NO_MORE_ITEMS )
	{
		//  Cleanup
		if (buffer) LocalFree(buffer);
		SetupDiDestroyDeviceInfoList(hDevInfo);
		return FALSE;
	}

	//  Cleanup
	if (buffer) LocalFree(buffer);
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return TRUE;
}

/****************************************************************/
BOOL WINAPI wCSC_CloseCOM(void)
/*****************************************************************
Close the PC communication port

RETURNS
  Always FALSE
*****************************************************************/
{
    BOOL fFreeResult;

	if (bIOChannel == STUB)
	{

	// If the handle is valid, try to get the function address.
		if (HmdStub != NULL)// STUB Lib exist and is present
		{
			// If the function address is valid, call the function.
			if (NULL != ProcPcscFilterClose) 
			{
				(ProcPcscFilterClose) ();
			}
			fFreeResult = FreeLibrary(HmdStub);
		}	
		hCOM=NULL;
		HmdStub=NULL;
		ProcCallAppliFunc=NULL;
		ProcPcscFilterClose=NULL; 
		ProcPcscFilterOpen=NULL; 
		return FALSE; // COM already Close -> out
	}
	if((hCOM == INVALID_HANDLE_VALUE) || (hCOM==NULL))
	{
		hCOM=NULL;
		return FALSE; // COM already Close -> out
	}

	switch (bIOChannel)
	{
		case PARALLEL:
			if (!bDirectIO)
				ShutdownWinIo ();
			hCOM=NULL;
			return FALSE;// parallel mode -> out

		case USB:
			// close the USB port
			FT_Close(hCOM);
			hCOM=NULL;
			return FALSE;

		case PCSC:
			SetPCSCCRC (0);
			SetPCSCPolling (300);
			SetPCSCCommandTimeout (8000);
			SCardDisconnect(hCardHandle,SCARD_LEAVE_CARD);
			SCardReleaseContext (hSC);
			hSC =(SCARDCONTEXT )NULL;
			hCOM=NULL;
			if (GetPrivateProfileInt ("Configuration","PCSCDontRestart",0,m_INIFileName) == 0)
				Restart_ASK_PCSC_Device ();
			return FALSE;

		case CCID:
			SetCCIDPolling(TRUE);
			SCardDisconnect(hCardHandle,SCARD_LEAVE_CARD);
			SCardReleaseContext (hSC);
			hSC =(SCARDCONTEXT )NULL;
			hCOM=NULL;
			return FALSE;

		
		default:
			CloseHandle( hCOM ); // close the COM port
			hCOM=NULL;
			return FALSE;
	}
}


/****************************************************************/
void WINAPI wCSC_FlushCOM(void)
/*****************************************************************
This Function discard all characters from the output or input
buffer in serial mode.
In parallel mode, discard ONE character from the output buffer of
the parallel interface of the coupler(made to receive reset byte 
0x10).
*****************************************************************/
{
DWORD vDt;
DWORD TimeOut=1;
char buf;

	if (bIOChannel == STUB)
		return;

	if (bIOChannel == PARALLEL)
	{
		vDt=wCSC_GetTimer(0); // begin timer
		InitPCom(REVERSE);
		while (((myin(STATUS) & 0x08) != 0x00) && (wCSC_GetTimer(vDt)<=TimeOut));
		buf = myin(DATA);
		myout(CONTROL,0x27);
		while (((myin(STATUS) & 0x08) != 0x08) && (wCSC_GetTimer(vDt)<=TimeOut));
		myout(CONTROL,0x25);
	}
	else if (bIOChannel == USB)
	{
		if((hCOM == INVALID_HANDLE_VALUE) || (hCOM==NULL))return;
		FT_Purge(hCOM, FT_PURGE_RX || FT_PURGE_TX);
	}
	else
	{
		// If the COM close or on error -> out
		if((hCOM == INVALID_HANDLE_VALUE) || (hCOM==NULL))return;
		PurgeComm(hCOM,PURGE_TXABORT | PURGE_TXCLEAR 
									| PURGE_RXABORT | PURGE_RXCLEAR );
	}
}


/****************************************************************/
BOOL WINAPI wCSC_PSendData(BYTE* BufIN,DWORD LnIN)
/*****************************************************************
Send data through parallel port

INPUTS
	BufIN							Frame to send to // port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Time Out
*****************************************************************/
{
DWORD vDt;
DWORD vTo;
DWORD TimeOut=1000;
DWORD i=0;

vDt=wCSC_GetTimer(0); // begin timer

if (BufIN[0]==0xFF)
	return TRUE;
InitPCom(FORWARD);
do	
	{
		myout(DATA,BufIN[i]);
		myout(CONTROL,0x06);
		while (((myin(STATUS) & 0x08) != 0x00) && (wCSC_GetTimer(vDt)<=TimeOut));
		myout(CONTROL,0x04);
		while (((myin(STATUS) & 0x08) != 0x08) && (wCSC_GetTimer(vDt)<=TimeOut));
		vTo=wCSC_GetTimer(vDt);
		i++;
	}
while ((i<LnIN) && (vTo<=TimeOut));

if (vTo>TimeOut)
	return FALSE;
else
	return TRUE;
}

/****************************************************************/
BOOL WINAPI wCSC_SendCOM(BYTE* BufIN,DWORD LnIN)
/*****************************************************************
Send data to the communication port

INPUTS
	BufIN							Frame to send to COM port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Function fails
*****************************************************************/
{
	DWORD lnw=0;
	DWORD ln=0;
	OVERLAPPED ov = {0};
	int i;

	if (bIOChannel == STUB)
		return 0;

	if (bIOChannel == PARALLEL)	
		return wCSC_PSendData(BufIN,LnIN);	// Parallel communication 
	else if (bIOChannel == USB)
	{
		// If the COM close or on error -> Error
		if((hCOM == INVALID_HANDLE_VALUE) || (hCOM==NULL))
			return FALSE;

		if (FT_Write(hCOM,(LPSTR)BufIN,LnIN,&lnw)!=FT_OK)
		{
			return FALSE;
		}

		// lnw : number of bytes effectively send
		if(lnw!=LnIN)
			return FALSE;

	return TRUE; // function success
	}
	else		
	{										// Serial communication 
		// If the COM close or on error -> Error
		if((hCOM == INVALID_HANDLE_VALUE) || (hCOM==NULL))
			return FALSE;

		// async write to prevent blocking
		// Send to Comm. port (async)
		ov.hEvent= CreateEvent(NULL, TRUE, FALSE, NULL);
		if (NULL != ov.hEvent)
		{

			// Send to Comm. port
			if (SlowFrame)
			{
				for (i=0;i < (signed) LnIN;i++)
				{
					if(WriteFile(hCOM,(LPSTR)&BufIN[i],1,&ln,NULL)!=1)return FALSE;
					lnw += ln;
				}
			}
			else
			{
				if (WriteFile(hCOM,(LPSTR)BufIN,LnIN,&lnw,&ov)==0)
				{
					if (ERROR_IO_PENDING != GetLastError())
					{
						CloseHandle(ov.hEvent);
						return FALSE;
					}

					if (WAIT_TIMEOUT == WaitForSingleObject(ov.hEvent,3000))
					{
						CloseHandle(ov.hEvent);
						return FALSE;
					}
				}
				GetOverlappedResult (hCOM,&ov,&lnw,TRUE);
			}
			CloseHandle(ov.hEvent);
		}

		// lnw : number of bytes effectively send
		if(lnw!=LnIN)
			return FALSE;

	return TRUE; // function success
	}
}



/****************************************************************/
DWORD WINAPI wCSC_iRecCOM (DWORD TimeOut,DWORD Len,BYTE* BufOUT)
/*****************************************************************
WARNING : Dimension of 'BufOUT' must be upper than the 
					value of 'Len'
******************************************************************
Receive data from the communication port ( Internal function )

INTERNAL FUNCTION

INPUTS
	Len								Number of byte wanted to receive

OUTPUTS
	BufOUT						Received bytes from the COM port

RETURNS
	Number of byte effectively receive
	0 -> Error
*****************************************************************/
{
BOOL Succ;
DWORD LenRead;
DWORD i;

// If the COM close or on error -> Error
if((hCOM == INVALID_HANDLE_VALUE) || (hCOM==NULL))return 0;

if (bIOChannel == STUB)
		return 0;

if	(bIOChannel == USB)
{
	Succ=FT_Read(hCOM,BufOUT,Len,&LenRead);
	if(Succ!=FT_OK)return 0;
}
else
{
	if (PreserveCPUUsage == 0)
	{
		Succ=ReadFile(hCOM,BufOUT,Len,&LenRead,NULL);
		if(Succ!=TRUE)return 0;
	}
	else
	{
		OVERLAPPED ov = {0};

		ov.hEvent = CreateEvent (NULL,TRUE,FALSE,NULL);
		if (!ReadFile(hCOM,BufOUT,Len,&LenRead,&ov))
		{
			if (ERROR_IO_PENDING != GetLastError())
			{
				CloseHandle(ov.hEvent);
				return -1;
			}
			
			i = TimeOut;
			while (i--)
			{
				wCSC_IdleLoop ();
				if (WAIT_TIMEOUT == WaitForSingleObject(ov.hEvent,1))
					continue;
			}
			if (i==0)
			{
				CloseHandle(ov.hEvent);
				return -1;
			}
		}
		GetOverlappedResult (hCOM,&ov,&LenRead,TRUE);
		CloseHandle(ov.hEvent);
		if (LenRead != Len)
			return (0);
	}
}

return LenRead;
}



/****************************************************************/
INT WINAPI wCSC_ReceiveCOM(DWORD TimeOut,DWORD Len,BYTE* BufOUT)
/*****************************************************************
WARNING : Dimension of 'BufOUT' must be upper than the 
					value of 'Len'
******************************************************************
Receive data from the communication port during 'TimeOut' ms

INPUTS
	TimeOut						Time out in milliseconds
	Len								Number of byte wanted to receive

OUTPUTS
	BufOUT						Received bytes from the COM port

RETURNS
  LnOUT							Number of byte effectively receive
										if zero -> error
										if -1 -> timeout
*****************************************************************/
{
DWORD vDt;				// timer lap
DWORD nb;				// Number of byte effectively receive
DWORD vTo;				// Timer lap for parallel comm.
INT nbData;
WORD wNb;
COMMTIMEOUTS tmo={MAXDWORD, // The read operation is to return immediately
		0,			 // with the characters that have already been
		0,   // received, even if no characters have been received.
		0,
		0 };
OVERLAPPED ov = {0};

*BufOUT=0;

// debug <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//TimeOut=10000;
// fin debug <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// this function can't receive more than 300 characters
if(Len>600)return 0;

if (giCRCNeeded==1)	nbData=5;
else				nbData=2;

vDt=wCSC_GetTimer(0); // begin timer
	
if (bIOChannel == STUB)
		return 0;
/* Parallel communication */
if	(bIOChannel == PARALLEL)
	{
	int i = 0;
	BufOUT[0] = 0x01;
	BufOUT[1] = 0x00;
	InitPCom(REVERSE);
	do
	{
		while (((myin(STATUS) & 0x08) != 0x00) && (wCSC_GetTimer(vDt)<=TimeOut));
		BufOUT[i] = myin(DATA);
		myout(CONTROL,0x27);
		while (((myin(STATUS) & 0x08) != 0x08) && (wCSC_GetTimer(vDt)<=TimeOut));
		myout(CONTROL,0x25);
		vTo=wCSC_GetTimer(vDt);
		i++;
		if (BufOUT[1]==255)
			wNb = BufOUT[1]+BufOUT[2]+1;
		else
			wNb = BufOUT[1];
	}
	while (((i < wNb + nbData) && (BufOUT[0] == 0x01)) && (vTo<=TimeOut));
	if (BufOUT[1] == 0x00)
		nb = 1;
	else
		nb = wNb + nbData;
	if(vTo>TimeOut)
		return -1;
	else
		return nb;
	}
/* Serial & USB communication */
/*else if (bIOChannel == SERIAL)	
	{
		OVERLAPPED ov = {0};
		DWORD LenRead;
		COMMTIMEOUTS tmo={1, // The read operation is to return immediately
		0,			 // with the characters that have already been
		0,   // received, even if no characters have been received.
		0,
		0 };

		tmo.ReadTotalTimeoutConstant = TimeOut; 
		// Sets the time-out parameters
		SetCommTimeouts(hCOM,&tmo);


		ov.hEvent = CreateEvent (NULL,TRUE,FALSE,NULL);
		if (!ReadFile(hCOM,BufOUT,Len,&LenRead,&ov))
		{
			if (ERROR_IO_PENDING != GetLastError())
			{
				CloseHandle(ov.hEvent);
				return -1;
			}

			if (WAIT_TIMEOUT == WaitForSingleObject(ov.hEvent,TimeOut))
			{
				CloseHandle(ov.hEvent);
				return -1;
			}
		}
		GetOverlappedResult (hCOM,&ov,&LenRead,TRUE);
		CloseHandle(ov.hEvent);
		return (LenRead); 
	}*/
	else  // USB
	{
	int i = 0;
	BufOUT[0] = 0x01;
	BufOUT[1] = 0x00;

	if (PreserveCPUUsage == 1)
	{
		tmo.ReadTotalTimeoutConstant = TimeOut; 
		// Sets the time-out parameters
		SetCommTimeouts(hCOM,&tmo);
	}

	do
	{
		if (i==2)	// frame timeout
		{
			vDt=wCSC_GetTimer(0); // begin timer
			TimeOut = 100;		  // 100 ms
		}
		while (((wCSC_iRecCOM (TimeOut,1,&BufOUT[i])) != 1) && (wCSC_GetTimer(vDt)<=TimeOut))
		wCSC_IdleLoop ();
		vTo=wCSC_GetTimer(vDt);
		i++;
		if (BufOUT[0] == 0x41)	// DF : Trame etendue 0x41 -> lg = LgLow + 256*LgHigh
		{
			nbData = 6;
			wNb = BufOUT[1] + (256*BufOUT[2]);
		}
		else if (BufOUT[1]==255)
			wNb = BufOUT[1]+BufOUT[2]+1;
		else
			wNb = BufOUT[1];
	}
	while (((i < wNb+nbData) && ((BufOUT[0] == 0x01) || (BufOUT[0] == 0x41))) && (vTo<=TimeOut));		// DF : Trame etendue 0x41

	if (BufOUT[1] == 0x00)
		nb = 1;
	else
		nb = wNb + nbData;
	if(vTo>TimeOut)
		return -1;
	else
		return nb;
	}
}


/****************************************************************/
INT WINAPI wCSC_DtrCOM(BOOL Value)
/*****************************************************************
Set or clear the DTR signal

INPUTS
	Value							TRUE:Set   FALSE:Clear

RETURNS
	1: OK
	0: Not OK
*****************************************************************/
{
if(Value==TRUE)
	{ // Set
	if(EscapeCommFunction(hCOM,SETDTR)==TRUE)return 1;
	}
else
	{ // Clear
	if(EscapeCommFunction(hCOM,CLRDTR)==TRUE)return 1;
	}
return 0;
}


/****************************************************************/
DWORD WINAPI wCSC_GetTimer(DWORD StartValue)
/*****************************************************************
Start and read a timer in milliseconds

INPUTS
	StartValue				Start value of the counter

RETURNS
  The subtraction between StartValue and the present TickCount
	value
*****************************************************************/
{
// x= the number of milliseconds that have elapsed since
// the system was started.
DWORD x=GetTickCount();

return x-StartValue;
}

/****************************************************************/
void WINAPI wCSC_IdleLoop(void)
/*****************************************************************
Process the Windows kernel message

*****************************************************************/
{
MSG msg;

while(PeekMessage(&msg,0,0,0,PM_REMOVE))
	{
	if(msg.message!=WM_QUIT)
		{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
		}
	}
}



/****************************************************************/
DWORD WINAPI wCSC_DebugLog(LPSTR Text,DWORD RetValue)
/*****************************************************************
Write 'text' in a log file

INPUTS
	Text								Text string
	RetValue						Return Value

RETURNS
	Always RetValue
*****************************************************************/
{
HANDLE hf=NULL;
BYTE fn[512];
BYTE tx[512];
BYTE txr[512];
SYSTEMTIME SyT;
DWORD ln;

if(swDEBUG==1){ /* DEBUG */

	GetWindowsDirectory(fn,256);
	strcat_s(fn,sizeof(fn),"\\ASKCSC.LOG");

	hf=CreateFile(fn,GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hf==INVALID_HANDLE_VALUE)return RetValue;

	GetLocalTime(&SyT);

	if(RetValue)
		{
		switch(RetValue)
			{
			case RCSC_Ok:
				strcpy_s(txr,sizeof(txr),"RCSC_Ok");break;
			case RCSC_NoAnswer:
				strcpy_s(txr,sizeof(txr),"RCSC_NoAnswer");break;
			case RCSC_CheckSum:
				strcpy_s(txr,sizeof(txr),"RCSC_CheckSum");break;
			case RCSC_Fail:
				strcpy_s(txr,sizeof(txr),"RCSC_Fail");break;
			case RCSC_Timeout:
				strcpy_s(txr,sizeof(txr),"RCSC_Timeout");break;
			case RCSC_Overflow:
				strcpy_s(txr,sizeof(txr),"RCSC_Overflow");break;
			case RCSC_OpenCOMError:
				strcpy_s(txr,sizeof(txr),"RCSC_OpenCOMError");break;
			case RCSC_DataWrong:
				strcpy_s(txr,sizeof(txr),"RCSC_DataWrong");break;
			case RCSC_CardNotFound:
				strcpy_s(txr,sizeof(txr),"RCSC_CardNotFound");break;
			case RCSC_ErrorSAM:
				strcpy_s(txr,sizeof(txr),"RCSC_ErrorSAM");break;
			case RCSC_CSCNotFound:
				strcpy_s(txr,sizeof(txr),"RCSC_CSCNotFound");break;
			case RCSC_BadATR:
				strcpy_s(txr,sizeof(txr),"RCSC_BadATR");break;
			case RCSC_TXError:
				strcpy_s(txr,sizeof(txr),"RCSC_TXError");break;
			case RCSC_UnknownClassCommand:
				strcpy_s(txr,sizeof(txr),"RCSC_UnknowClassCommand");break;
			default:
				sprintf_s(txr,sizeof(txr),"Unknown Error = %04X",RetValue);break;
			}
		sprintf_s(tx,sizeof(tx),"%02d/%02d/%04d %02d:%02d:%02d [%s] %s\r\n",SyT.wDay,SyT.wMonth,SyT.wYear,
																			SyT.wHour,SyT.wMinute,SyT.wSecond,txr,Text);
	}
	else sprintf_s(tx,sizeof(tx),"%s\r\n",Text);
	SetFilePointer(hf,0,NULL,FILE_END);

	WriteFile(hf,tx,(DWORD)strlen(tx),&ln,NULL);

	CloseHandle(hf);

} /* LOG DEBUG */

return RetValue;
}


/****************************************************************/
LPSTR wCSC_BTS(BYTE* data,DWORD lndata)
/*****************************************************************
Convert the binary bytes by ASCII characters 

INPUTS
	data								binary buffer
	lndata							lenght of data

RETURNS
	ASCII buffer
*****************************************************************/
{
static char tx[4096];
char c[5];
DWORD i;

tx[0]=0;
for(i=0;i<lndata;i++)
	{
	wsprintf(c,"%02X ",data[i]);
	strcat_s(tx,sizeof(tx),c);
	}
return (LPSTR)tx;
}

/****************************************************************/
DWORD SetPCSCCommandTimeout (DWORD CommandTimeout)
/****************************************************************/
{
	DWORD			BytesReturned;
	BYTE			OutBuffer[4];

	return (SCardControl( hCardHandle,IOCTL_SMARTCARD_VENDOR_SET_TIMEOUT,
							&CommandTimeout,sizeof (CommandTimeout),
							OutBuffer,sizeof (OutBuffer),&BytesReturned ));
}

/****************************************************************/
DWORD SetPCSCPolling (DWORD CardPollingTime)
/****************************************************************/
{
	DWORD			BytesReturned;
	BYTE			OutBuffer[4];

	return (SCardControl( hCardHandle,IOCTL_SMARTCARD_VENDOR_CONTROL_POLLING,
							&CardPollingTime,sizeof (CardPollingTime),
							OutBuffer,sizeof (OutBuffer),&BytesReturned ));
}

/****************************************************************/
DWORD SetPCSCCRC (DWORD CRCON)
/****************************************************************/
{
	DWORD			BytesReturned;
	BYTE			OutBuffer[4];

	return (SCardControl( hCardHandle,IOCTL_SMARTCARD_VENDOR_ENABLE_CRC,
							&CRCON,sizeof (CRCON),
							OutBuffer,sizeof (OutBuffer),&BytesReturned ));

	return (SCARD_S_SUCCESS);
}
/****************************************************************/
INT wCSC_RxTxPCSC	(BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT)
/*****************************************************************
Send data and Rx Data trough PCSC control interface

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
	Number of byte effectively receive
	0 -> Error
*****************************************************************/
{
	DWORD BytesReturned;

	if (SCardControl( hCardHandle,IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE,BufIN,LnIN,
						BufOUT,300,&BytesReturned ) != SCARD_S_SUCCESS)
		BytesReturned = -1;
	return (BytesReturned);


}

extern const ushort kiCSC_CRCTABLE[256];
/****************************************************************/
INT wCSC_RxTxCCID	(BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT)
/*****************************************************************
Send data and Rx Data trough CCID control interface

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
	Number of byte effectively receive
	0 -> Error
*****************************************************************/
{
	DWORD BytesReturned;
	BYTE BufCCID[2048];
	ushort CRCVal=0;
	DWORD i;

	BufCCID[0]=CCID_EXCHANGE_CODE;
	if (giCRCNeeded == TRUE){
		if (LnIN>5)
			LnIN-=5; // suppress CMD LG [] 00 CRC
	} else {
		if (LnIN>2)
			LnIN-=2; // suppress CMD LG [] 
	}

	memcpy(&BufCCID[1],&BufIN[2], LnIN);

	if (SCardControl( hCardHandle,IOCTL_CCID_CODE,BufCCID,LnIN+1,
						BufOUT+3,300,&BytesReturned ) != SCARD_S_SUCCESS)
	{
		BytesReturned = -1;
	}
	else
	{
		BufOUT[0]=0x01;
		BufOUT[1]=(BYTE) BytesReturned+1;
		BufOUT[2]=BufCCID[1];
		BufOUT[3]=BufCCID[2];
		BufOUT[BytesReturned+3]=0;
		BytesReturned+=4;

		for(i=0;i<BytesReturned;i++)
			CRCVal=kiCSC_CRCTABLE[(CRCVal^=(BufOUT[i]&0xFF))&0xFF]^(CRCVal>>8);

		BufOUT[BytesReturned  ]=CRCVal%256;
		BufOUT[BytesReturned+1]=CRCVal/256;
		BytesReturned+=2;

	}
	return (BytesReturned);


}

/****************************************************************/
DWORD SetCCIDPolling (BOOL CCIDPollingOnOff)
/****************************************************************/
{
	DWORD			BytesReturned;
	BYTE			SenBuffer[4];
	BYTE			RecBuffer[10];

	SenBuffer[0]= 0x01;
	SenBuffer[1]= (CCIDPollingOnOff==FALSE)?0x00:0x01;

	return (SCardControl( hCardHandle,IOCTL_CCID_CODE,
							SenBuffer,2,
							RecBuffer,sizeof (RecBuffer),&BytesReturned ));
}