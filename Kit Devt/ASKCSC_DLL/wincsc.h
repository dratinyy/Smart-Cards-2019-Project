/*****************************************************************
  Interface Windows Functions for CSC Module ( WINCSC.H )

  P R O T O T Y P E S

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
Ver 4.01.00.133-Beta 02-08-21  BL
Ver 4.00.02.036		 02-02-05  SM	Change Speed Capabilities
Ver 1.50.99.227      99-08-10  PMO	Parallel communication
Ver 1.07.99.142      99-05-18  THJ  First Commercial Version
Ver 1.06.99.130      99-05-06  THJ  Add the DEBUG LOG
Ver 1.01.99.081      99-03-26  THJ  Created
*****************************************************************/
#ifndef __WIN_CSC_H__
#define __WIN_CSC_H__


#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char (__cdecl *MYPROC)(unsigned char FunctionClass, unsigned char FunctionID, 
							unsigned char * pDataIn, unsigned char * pDataOut, 
							unsigned short int * pDataOutLength, 
			    				unsigned short int LgDataIn
						    	); 
typedef int (__cdecl *MYPROCOPEN)(LPSTR); 
typedef int (__cdecl *MYPROCCLOSE)(); 	
	
extern MYPROC ProcCallAppliFunc;
extern MYPROCCLOSE ProcPcscFilterClose; 
extern MYPROCOPEN ProcPcscFilterOpen; 

/* Constants ****************************************************/

//  wCSC_GetWinVersion 
#define  wCSC_VER_ERROR					0
#define  wCSC_VER_WIN95					1
#define  wCSC_VER_WINNT4				2

#define SERIAL		0
#define PARALLEL	1
#define USB			2
#define PCSC		3
#define CCID		4
#define STUB		5

#define CCID_EXCHANGE_CODE	0
#define IOCTL_CCID_CODE		SCARD_CTL_CODE(3500)


/* Prototypes ***************************************************/


/****************************************************************/
DWORD WINAPI wCSC_GetWinVersion(void);
/*****************************************************************
Find Windows Version

RETURNS
  wCSC_VER_ERROR    PlatForm Error
	wCSC_VER_WIN95    WIN95, WIN98 or more
	wCSC_VER_WINNT4   WIN NT4 or more
*****************************************************************/



/****************************************************************/
BOOL WINAPI wCSC_OpenCOM(LPSTR ComName);
/*****************************************************************
Open the PC communication port

INPUTS
  ComName           Communication port Name  ( ex: "COM1" ) 

RETURNS
  TRUE              Function success
	FALSE             Function fail
*****************************************************************/




/****************************************************************/
BOOL WINAPI wCSC_CloseCOM(void);
/*****************************************************************
Close the PC communication port

RETURNS
  Always FALSE
*****************************************************************/



/****************************************************************/
void WINAPI wCSC_FlushCOM(void);
/*****************************************************************
This Function discard all characters from the output or input 
buffer.
*****************************************************************/



/****************************************************************/
BOOL WINAPI wCSC_PSendData(BYTE* BufIN,DWORD LnIN);
/*****************************************************************
Send data through parallel port

INPUTS
	BufIN							Frame to send to // port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Time Out
*****************************************************************/



/****************************************************************/
BOOL WINAPI wCSC_SendCOM(BYTE* BufIN,DWORD LnIN);
/*****************************************************************
Send data to the communication port

INPUTS
	BufIN							Frame to send to COM port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Function fails
*****************************************************************/



/****************************************************************/
INT WINAPI wCSC_ReceiveCOM(DWORD TimeOut,DWORD Len,BYTE* BufOUT);
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



/****************************************************************/
INT WINAPI wCSC_DtrCOM(BOOL Value);
/*****************************************************************
Set or clear the DTR signal

INPUTS
	Value							TRUE:Set   FALSE:Clear

RETURNS
	1: OK
	0: Not OK
*****************************************************************/



/****************************************************************/
DWORD WINAPI wCSC_GetTimer(DWORD StartValue);
/*****************************************************************
Start and read a timer in milliseconds

INPUTS
	StartValue				Start value of the counter

RETURNS
  The subtraction between StartValue and the present TickCount
	value
*****************************************************************/


/****************************************************************/
void WINAPI wCSC_IdleLoop(void);
/*****************************************************************
Process the Windows kernel message

*****************************************************************/


/****************************************************************/
DWORD WINAPI wCSC_DebugLog(LPSTR Text,DWORD RetValue);
/*****************************************************************
Write 'text' in a log file

INPUTS
	Text								Text string
	RetValue						Return Value

RETURNS
	Always RetValue
*****************************************************************/


/****************************************************************/
LPSTR wCSC_BTS(BYTE* data,DWORD lndata);
/*****************************************************************
Convert the binary bytes by ASCII characters 

INPUTS
	data								binary buffer
	lndata							lenght of data

RETURNS
	ASCII buffer
*****************************************************************/
DWORD SetPCSCCommandTimeout (DWORD CommandTimeout);
DWORD SetPCSCPolling (DWORD CardPollingTime);
DWORD SetPCSCCRC (DWORD CRCON);
INT wCSC_RxTxPCSC	(BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT);
INT wCSC_RxTxCCID	(BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT);
DWORD SetCCIDPolling (BOOL CCIDPollingOnOff);

#ifdef __cplusplus
}
#endif

#endif /* __WIN_CSC_H__ */
