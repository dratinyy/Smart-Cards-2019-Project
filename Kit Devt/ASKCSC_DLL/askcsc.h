/*****************************************************************
  HEADER INCLUDE FILE for ASKCSC.DLL 

  Copyright (C)1999-2002 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Thierry J. / Jean-Luc M. / Serge M. - ASK
*****************************************************************/


/*****************************************************************
  HISTORY :
  
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
Ver 4.01.00.133-Beta 02-08-21  BL	Add first CTx512B functions : list, select, read, update, halt
Ver 4.00.02.036		 02-02-05  SM   Add MIFARE, RS485, Speed commands
Ver 3.11.01.260		 01-09-17  SM	No modif
Ver 3.10.01.087		 01-03-28  CCV  harmonisation des commandes CTS (prevision CTM)
Ver 3.10.01.064		 01-03-05  CCV  Add CTS functions and modify CSC_SearchCard()
Ver 3.01.00.329	Beta 00-11-24  JLM  Add GEN 3XX Managment
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
Ver 1.05.99.119      99-03-26  THJ  Created
*****************************************************************/

#ifndef __ASKCSC_H__
#define __ASKCSC_H__


#include "csc_def.h"  // Constants defines CSC module


#ifdef __cplusplus
extern "C" {
#endif


// sCARD_Status Structure 
// for CD97_... or GTML_... functions
typedef struct sCARD_StatusTag
{
BYTE Code;		// Status Code
BYTE Byte1;		// First detail byte
BYTE Byte2;		// Last detail byte
}sCARD_Status;


typedef struct sCARD_SessionTag
{
BYTE NbApp;		// Number of Application
SHORT Path[128];// Path of the Applications
BYTE Data[29];	// Data record
}sCARD_Session;

typedef struct sCARD_SecurParamTag
{
BYTE  AccMode;	// Acces Mode
BYTE  SID;		// Short ID
WORD  LID;		// Long ID
BYTE  NKEY;		// Number of Key (SAM)
BYTE  RFU;		// Reserved for the KVC
}sCARD_SecurParam;


typedef struct sCARD_SearchTag
{
BYTE  CONT;		// Contact Mode
BYTE  ISOB;		// ISO B Protocol Mode
BYTE  ISOA;		// ISO A Protocol Mode
BYTE  TICK;		// Ticket Mode
BYTE  INNO;		// Innovatron Protocol Mode
}sCARD_Search;


typedef struct sCARD_SearchExtTag
{
BYTE  CONT;		// Contact Mode
BYTE  ISOB;		// ISO B Protocol Mode
BYTE  ISOA;		// ISO A Protocol Mode
BYTE  TICK;		// Ticket Mode
BYTE  INNO;		// Innovatron Protocol Mode
BYTE  MIFARE;	// Mifare Mode
BYTE  MV4k;		// MV4k protocol mode
BYTE  MV5k;		// MV5k protocol mode
BYTE  MONO;		// mono-search mode
BYTE  SRX;		// SRx Family Mode
}sCARD_SearchExt;


//-- for ascendent compatibility --------------------------------
// sCARD_Status Structure 
// for CD97_...  function
#define sCD97_Status sCARD_Status
#define sCD97_Session sCARD_Session



#ifndef __ASKCSC_IN__

/****************************************************************/
DWORD CSC_GetUSBNumDevices (DWORD *NumDevices);
/****************************************************************
Get number of CSC USB devices

OUTPUTS
	NumDevices return the number of USB devices

RETURNS
	RCSC_Ok
	RCSC_Fail
*****************************************************************/

/****************************************************************/
DWORD CSC_GetPCSCNumDevices (DWORD *NumDevices);
/****************************************************************
Get number of CSC PCSC devices

OUTPUTS
	NumDevices return the number of CSC PCSC devices

RETURNS
	RCSC_Ok
	RCSC_Fail
*****************************************************************/

/****************************************************************/
DWORD CSC_GetPCSCDeviceName (DWORD DeviceNumber,char *sName);
/****************************************************************
Get the name of DeviceNumber PCSC ASK reader

INPUTS
	DeviceNumber 

OUTPUTS
	sName 

RETURNS
	RCSC_Ok
	RCSC_Fail
*****************************************************************/

/****************************************************************/
DWORD WINAPI CSC_Open(LPSTR ComName);
/*****************************************************************
Open the PC communication port

INPUTS
  ComName     : Communication port Name (ex: "COM1", "LPT1" or "USB1") 

RETURNS
	RCSC_Ok
	RCSC_OpenCOMError
*****************************************************************/


/****************************************************************/
void WINAPI CSC_Close(void);
/*****************************************************************
Close the PC communication port
*****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_ResetCSC(void);
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
****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_DownloadStartCSC(void);
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

/****************************************************************/
DWORD WINAPI CSC_DownloadStopCSC(void);
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

/****************************************************************/
DWORD WINAPI CSC_DesactiveCRC(BYTE Type, LPSTR Version);
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


/****************************************************************/
DWORD WINAPI CSC_VersionCSC(LPSTR Version);
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


/****************************************************************/
DWORD WINAPI CSC_VersionDLL(LPSTR Version);
/*****************************************************************
Return the DLL version

OUTPUTS
  Version	: The text DLL version

RETURNS
  The DLL version : release
*****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_SendReceive(DWORD Timeout,BYTE* BufIN,
							 DWORD LnIN,BYTE* BufOUT,LPDWORD LnOUT);
/*****************************************************************
Send a command frame to the CSC, and waits for the answer

INPUTS
	Timeout	: The command timeout value in milliseconds
	BufIN	: Command frame to send to the CSC
			  the frame is : <CMD><LEN><CLASS><IDENT><DATA><CRC>
	LnIN	: The frame size
	

OUTPUT
	BufOUT	: Contains the CSC answer frame
			  The frame is : <STA><LEN><CLASS><IDENT><DATA><CRC>
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


/****************************************************************/
DWORD WINAPI CSC_AddCRC(BYTE* Buf,LPDWORD Len);
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


/****************************************************************/
DWORD WINAPI CSC_GetCommand(BYTE Command,BYTE* BufOUT,LPDWORD LnOUT);
/*****************************************************************
Return the CSC module command frame

INPUTS
	Command	: The command name (CSC_SYS_SOFTWARE_VERSION,...)
	
OUTPUT
	BufOUT 	: Command frame
	LnOUT	: The bufOUT size

RETURNS
	RCSC_Fail
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CSC_SearchCard(sCARD_Search Search,
							BYTE Forget,BYTE TimeOut,
							LPBYTE COM,LPDWORD lpcbATR,BYTE* lpATR);
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

/****************************************************************/
DWORD WINAPI CSC_SearchCardExt(sCARD_SearchExt* search,DWORD search_mask,
							BYTE Forget,BYTE TimeOut,
							LPBYTE COM,LPDWORD lpcbATR,BYTE* lpATR);
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



/****************************************************************/
DWORD WINAPI CSC_CardConfig(BYTE SearchType);
/*****************************************************************
Configure the CSC in PSCL or contactless card mode

INPUTS
  SearchType	:
			- PSCL mode			: CSC_SEARCH_PSCL					
			- Contact less Card : CSC_SEARCH_CLESSCARD			

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Fail
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_CardStartSearch(void);
/*****************************************************************
Starts the search for a card. This function must be called once
to set the CSC module in a search mode;
Then the CSC_CardFound may be called repeatedly to see if a card
was detected.

CSC_CardConfig function must be called before.

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Timeout
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_CardStopSearch(void);
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


/****************************************************************/
DWORD WINAPI CSC_CardFound(BYTE* lpATR,LPDWORD lpcbATR);
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
	RCSC_BadATR
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_CardEnd(void);
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


/****************************************************************/
DWORD WINAPI CSC_AntennaOFF(void);
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


/****************************************************************/
DWORD WINAPI CSC_ISOCommand(BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,
												LPDWORD lpLnOUT);
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

/****************************************************************/
DWORD WINAPI CSC_ISOCommandExt(BYTE LnINLow, BYTE LnINHigh, BYTE* BufIN, 
								BYTE* Status, BYTE* LnOutLow, BYTE* LnOutHigh, BYTE* BufOUT);
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

/****************************************************************/
DWORD WINAPI CSC_TransparentCommandConfig(BYTE ISO,
										  BYTE addCRC,
										  BYTE checkCRC,
										  BYTE field,
										  BYTE* configISO,
										  BYTE* configAddCRC,
										  BYTE* configCheckCRC,
										  BYTE* configField);
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
																	 WORD* configTimeOut);
/*****************************************************************
Configures the settings of "CSC_TransparentCommandConfigExt"


INPUTS
	ISO :			0x00 : for getting the current config
					0x01 : for selecting ISOB
					0x02 : for selecting ISOA
					0x03 : for selecting Felica (only Gen5xx)
	addCRC :		0x01 : the CRC will be computed and added to the frame
					else : nothing to add, the frame is sent directly
	checkCRC :		0x01 : the CRC of the frame received needs to be checked
					else : nothing to check
	addParity :		0x01 : the Parity will be computed and added to the frame
					else : nothing to add, the frame is sent directly
	checkParity :	0x01 : the Parity of the frame received needs to be checked
					else : nothing to check
	numBitLastByte	:	Number of bits of the last byte that shall transmitted (1 byte)
	byPassISOA :	0x01 : ByPass ISOA
					else : True ISOA
	field :			0x01 : the field will be switched ON when sending the frame
					else : no modification of the field
	timeOut	:		TimeOut Allowed for answer 0 to 2000 ms (default 456 ms) (2 byte) 	
	
OUTPUT
	configISO :	0x01 : ISOB selected
				0x02 : ISOA selected
				0x03 : Felica selected
				0xFF : wrong protocol asked
	configAddCRC :		current configuration (same values as input)
	configCheckCRC :	current configuration (same values as input)
	configAddParity :	current configuration (same values as input)
	configCheckParity :	current configuration (same values as input)
	configNumBitLastByte :	current configuration (same values as input)
	configByPassISOA :	current configuration (same values as input)
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

/****************************************************************/
DWORD WINAPI CSC_TransparentCommand(BYTE* bufIn, DWORD lnIn,
									BYTE* status, DWORD* lnOut, BYTE* bufOut);
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


/****************************************************************/
DWORD WINAPI CSC_WriteSAMNumber(BYTE N_SAM, BYTE* status);
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


/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_WriteConfigEeprom(BYTE Index, BYTE Value, BYTE *Status);
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

/*****************************************************************/
__declspec( dllexport ) DWORD WINAPI CSC_ReadConfigEeprom(BYTE Index, BYTE *Status, BYTE *Value);
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

/****************************************************************/
DWORD WINAPI CSC_ISOCommandContact(BYTE* BufIN,DWORD LnIN,
								   BYTE Case,
								   BYTE* BufOUT,DWORD* lpLnOUT);
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



/****************************************************************/
DWORD WINAPI CSC_SelectSAM(BYTE N_SAM,BYTE Type);
/*****************************************************************
select the specified SAM.


OUTPUT
	N_SAM				Number of SAM to select.
	Type				Protocole used
RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CSC_ResetSAM(BYTE* lpATR,LPDWORD lpcbATR);
/*****************************************************************
Reset the SAM, and returns the ATR.


OUTPUT
	lpATR						Contains the ATR of the SAM
	lpcbATR						The ATR length

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CSC_ResetSAMExt(BYTE SamNum, BYTE SelectINN, BYTE SelectISO,
							 LPDWORD lpcbATR, BYTE* lpATR);
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
	lpcbATR		: The ATR length

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CSC_ISOCommandSAM(BYTE* BufIN,DWORD LnIN,BYTE* BufOUT,
													LPDWORD lpLnOUT);
/*****************************************************************
Sends an ISO command to the SAM, and returns the answer.


INPUTS
	BufIN	: The ISO Command to send to the SAM
	LnIN	: ISO command length
	
OUTPUT
	BufOUT	: Contains the answer
	lpLnOUT	: The answer size

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_ErrorSAM
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CSC_ISOCommandSAMExt(BYTE NumSAM, DWORD LgIN, BYTE* BufIN, BYTE Direction,
									LPDWORD LgOUT, BYTE* BufOUT);
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

/****************************************************************/
DWORD WINAPI CSC_SearchCSC(void);
/*****************************************************************
Search the CSC module, Open the PC communication port and the
CSC is reseted.

RETURNS
	RCSC_Ok
	RCSC_CSCNotFound
*****************************************************************/


/****************************************************************/
DWORD WINAPI CSC_Switch_Led_Buz(WORD Param);
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


/****************************************************************/
DWORD WINAPI CD97_AppendRecord(BYTE AccMode,BYTE SID,LPBYTE Rec,
								BYTE RecSize,sCARD_Status* Status);
/*****************************************************************
Add a record to a circular EF


INPUTS
	AccMode	 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID		 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Rec      : Data to write
	RecSize  : The size of data to write

OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CD97_ChangeKey(BYTE KeyIndex,BYTE NewVersion,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_ChangeKeyExt(BYTE KeyIndex, BYTE NewKeyVersion, BYTE TypeCmd, 
								BYTE KeyIndexEncipher, BYTE ALGTag, BYTE ALGSam, 
								BYTE NewKeyIndex, sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_ChangePIN(LPBYTE OldPIN,LPBYTE NewPIN,
											sCARD_Status* Status);
/*****************************************************************
Change the PIN code


INPUTS
	OldPIN		 : Old PIN Code ( 4 characters )
	NewPIN		 : New PIN Code ( 4 characters )

OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CD97_ChangePINExt(BYTE KeyNum, LPBYTE OldPIN, LPBYTE NewPIN, BYTE TypeCmd,
								BYTE KeyNumKIF, BYTE KVC, BYTE ALG, BYTE SamNum, sCARD_Status* Status);
/*****************************************************************
Change the PIN code


INPUTS
	KeyNum		: Key number 
					$00 : CD97, GTML and CT2000,
					$04 : GTML2 and CD21, 
					$09 : POPEYE
	OldPIN		: Old PIN Code (4 bytes)
	NewPIN		: New PIN Code (4 bytes)
	TypeCmd		: type Command (1 byte)
					$00 : short cmd
					$01 : long cmd
	KeyNumKIF	: SAM key number to use 
				  or KIF of the key
	KVC			: $00 (if NKEY passed in the previous parameter)
				  or KVC of the Key
	ALG			: Algorithm of the SAM used 
	SamNum		: SAM number 
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

/****************************************************************/
DWORD WINAPI CD97_Decrease(BYTE AccMode,BYTE SID,DWORD Value,
						   LPDWORD NewValue,sCARD_Status* Status);
/*****************************************************************
Decrease a counter file value

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID			 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Value		 : Value decreased

OUTPUT
	NewValue	 : Counter new value ( Out of sessions Mode )
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CD97_Increase(BYTE AccMode,BYTE SID,DWORD Value,
						   LPDWORD NewValue,sCARD_Status* Status);
/*****************************************************************
Increase a counter file value

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID			 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Value		 : Value increased

OUTPUT
	NewValue	 : Counter new value ( Out of sessions Mode )
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CD97_Invalidate(BYTE AccMode,sCARD_Status* Status);
/*****************************************************************
Invalidate the current DF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CD97_Rehabilitate(BYTE AccMode,sCARD_Status* Status);
/*****************************************************************
Rehabilitate the current DF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CD97_ReadRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
							 BYTE DataLen,LPBYTE Data,sCARD_Status* Status);
/*****************************************************************
Read a record from linear or circular file

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID			 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec		 : Record number
	DataLen      : Number of bytes to be read ( record length )

OUTPUT
	Data		 : Data read
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI CD97_SelectFile(BYTE SelectMode,LPBYTE IdPath,
							 BYTE IdPathLen,LPBYTE FCI,
							 sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_StatusFile(BYTE SelectMode,LPBYTE IdPath,
										BYTE IdPathLen,LPBYTE FCI,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_UpdateRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE DataLen,LPBYTE Data,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_WriteRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE DataLen,LPBYTE Data,
											sCARD_Status* Status);
/*****************************************************************
Write a record to a EF

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

/****************************************************************/
DWORD WINAPI CD97_VerifyPIN(LPBYTE PIN,sCARD_Status* Status);
/*****************************************************************
PIN verification

INPUTS
	PIN		 : PIN code ( 4 characters )

OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CD97_VerifyPINExt(BYTE Mode, LPBYTE PIN, BYTE TypeCmd, BYTE KeyNumKIF, 
								BYTE KVC, BYTE SamNum, sCARD_Status* Status);
/*****************************************************************
PIN verification

INPUTS
	Mode		: Mode
					$00 : consultation of counter of number of incorrect presentations		
					$01 : presentation of PIN
					$02 : presentation of PIN in transparent mode for contact communication
	PIN			: PIN code (4 bytes)
	TypeCmd		: Type Cmd
					$00 : short command (compatibility with the former one)
					$01 : long command
	KeyNumKIF	: SAM key number to use Or KIF of the key.
	KVC			: $00 if NKEY passed in the previous parameter or KVC of the Key
	SamNum		: SAM number 
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

/****************************************************************/
DWORD WINAPI CD97_Purchase(BYTE Type,LPBYTE DataLog,LPBYTE Disp,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_GetEPStatus(BYTE Type,LPDWORD EP,LPBYTE Log,
											sCARD_Status* Status);
/*****************************************************************
Purchase with the Electronic Purse ( EP )

INPUTS
	Type	 : Transaction Type :
						- Loading Transaction   (0x00)
						- Purchase Transaction  (0x01)
						- Purchase cancellation (0x02)

OUTPUT
	EP		 : Electronic Purse Value

	Log      : if Type = Loading Transaction (0x00)
						 Log = Loading Log Record ( 22 characters )
						 if Type = 0x01 or 0x02
						 Log = Payement Log Record ( 19 characters )

	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CD97_ReloadEP(LPBYTE ChargLog1,LPBYTE ChargLog2,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_OpenSession(BYTE Type,BYTE SID,BYTE NRec,
					sCARD_Session* Session,sCARD_Status* Status);
/*****************************************************************
Open the secured session

INPUTS
	Type    : Operation Type
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

/****************************************************************/
DWORD WINAPI CD97_OpenSessionExt(BYTE Type, sCARD_SecurParam Secur, BYTE RecNum, BYTE TypeCmd, 
								BYTE Mode, sCARD_Status* Status, sCARD_Session* Session, BYTE* KVC);
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

/****************************************************************/
DWORD WINAPI CD97_CloseSession(LPBYTE Result,LPDWORD cbResult,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CD97_CloseSessionExt(BYTE TypeCmd, BYTE TimeOut, sCARD_Status* Status, 
									LPDWORD LgResult, LPBYTE Result);
/*****************************************************************
Close the secured session

INPUT
	TypeCmd  : Type Cmd
				$00 : session will be ratified at the reception of the following command
				$80 : session is ratified immediately (except for CD97 and GTML)
				$4A : switches OFF the field if the card doesn’t answer
	TimeOut	 : if TYPE=$4A 

OUTPUT
	Status	 : Contains the card execution return status
	LgResult : The Result length
	Result	 : Order result

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CD97_CancelPurchase(BYTE Type,LPBYTE DataLog,
								LPBYTE Disp,sCARD_Status* Status);
/*****************************************************************
Cancel Purchase with the Electronic Purse ( EP )

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

/****************************************************************/
DWORD WINAPI CD97_AbortSecuredSession(sCARD_Status* Status);
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-

OUTPUT
	Status	: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI CD97_SelectISOApplication(BYTE SelectOption, BYTE Lg, LPBYTE Data, 
										sCARD_Status* Status, LPBYTE FCI);
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


/****************************************************************/
DWORD WINAPI GTML_AppendRecord(BYTE AccMode,BYTE SID,LPBYTE Rec,
								BYTE RecSize,sCARD_Status* Status);
/*****************************************************************
Add a record to a circular EF


INPUTS
	AccMode	 : Card Access Mode
	SID		 : Short ID Number
	Rec      : Data to write
	RecSize  : The size of data to write

OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_ChangePIN(LPBYTE OldPIN,LPBYTE NewPIN,
											sCARD_Status* Status);
/*****************************************************************
Change the PIN code


INPUTS
	OldPIN		 : Old PIN Code ( 4 characters )
	NewPIN		 : New PIN Code ( 4 characters )

OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_Decrease(BYTE AccMode,BYTE SID,DWORD Value,
							LPDWORD NewValue,sCARD_Status* Status);
/*****************************************************************
Decrease a counter file value

INPUTS
	AccMode		 : Card Access Mode
	SID			 : Small ID Number
	Value		 : Value decreased

OUTPUT
	NewValue	 : Counter new value ( Out of sessions Mode )
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_Increase(BYTE AccMode,BYTE SID,DWORD Value,
							LPDWORD NewValue,sCARD_Status* Status);
/*****************************************************************
Increase a counter file value

INPUTS
	AccMode		 : Card Access Mode
	SID			 : Small ID Number
	Value		 : Value increased

OUTPUT
	NewValue	 : Counter new value ( Out of sessions Mode )
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_Invalidate(BYTE AccMode,sCARD_Status* Status);
/*****************************************************************
Invalidate the current DF

INPUTS
	AccMode		 : Card Access Mode

OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_Rehabilitate(BYTE AccMode,sCARD_Status* Status);
/*****************************************************************
Rehabilitate the current DF

INPUTS
	AccMode		 : Card Access Mode

OUTPUT
	Status		 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_ReadRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
					BYTE DataLen,LPBYTE Data,sCARD_Status* Status);
/*****************************************************************
Read a record from linear or circular file

INPUTS
	AccMode	 : Card Access Mode
	SID		 : Small ID Number
	NuRec	 : Record number
	DataLen  : Number of bytes to be read ( record length )

OUTPUT
	Data	 : Data read
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_SelectFile(BYTE SelectMode,LPBYTE IdPath,
										BYTE IdPathLen,LPBYTE FCI,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI GTML_UpdateRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE DataLen,LPBYTE Data,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI GTML_WriteRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE DataLen,LPBYTE Data,
											sCARD_Status* Status);
/*****************************************************************
Write a record to a EF

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

/****************************************************************/
DWORD WINAPI GTML_VerifyPIN(LPBYTE PIN,sCARD_Status* Status);
/*****************************************************************
PIN verification

INPUTS
	PIN		 : PIN code ( 4 characters )

OUTPUT
	Status	 : Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI GTML_OpenSession(BYTE Type,BYTE SID,BYTE NRec,
					sCARD_Session* Session,sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI GTML_CloseSession(LPBYTE Result,LPDWORD cbResult,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI GTML_AbortSecuredSession(sCARD_Status* Status);
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


//** Generic *****************************************************

/****************************************************************/
DWORD WINAPI AppendRecord(sCARD_SecurParam Secur,
						  LPBYTE Rec,BYTE RecSize,
						  sCARD_Status* Status);
/*****************************************************************
Add a record to a circular EF


INPUTS
	SecurParam	: Contain the parameters for the secury
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

/****************************************************************/
DWORD WINAPI ChangeKey(BYTE KeyIndex, BYTE KeyIndexEncipher, BYTE NewKeyVersion, BYTE ALGTag,
					   BYTE ALGSam, BYTE NewKeyIndex, sCARD_Status* Status);
/*****************************************************************
Change the key / Personnalization


INPUTS
	KeyIndex			: Index of the key ( 01 - 03 )
	KeyIndexEncipher	: Index of the key to encipher the transfer
	NewVersion			: New version of the key ( <> 0 )
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


/****************************************************************/
DWORD WINAPI ChangePIN(sCARD_SecurParam SecurParam,
					   LPBYTE OldPIN,LPBYTE NewPIN,
					   sCARD_Status* Status);
/*****************************************************************
Change the PIN code


INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI VerifyPIN(sCARD_SecurParam Secur,
						LPBYTE PIN,
						sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI PINStatus(sCARD_Status* Status);
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


/****************************************************************/
DWORD WINAPI Increase(sCARD_SecurParam SecurParam,
					  BYTE ICount,DWORD Value,
					  LPDWORD NewValue,sCARD_Status* Status);
/*****************************************************************
Increase a counter file value

INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI Decrease(sCARD_SecurParam SecurParam,
					  BYTE ICount,DWORD Value,
					  LPDWORD NewValue,sCARD_Status* Status);
/*****************************************************************
Decrease a counter file value

INPUTS
	SecurParam	: Contain the parameters for the secury
					- AccMode :	Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
					- SID	  : Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
					- LID	  : Long ID
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC
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

/****************************************************************/
DWORD WINAPI DecreaseLG(sCARD_SecurParam Secur,
						BYTE ICount,LPBYTE Value,
						sCARD_Status* Status,
						LPDWORD NewValue);
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
	NewValue	: Counter new value ( Out of sessions Mode )(3 bytes, binary number signed)
	Status		: Contains the card execution return status

RETURNS
	RCSC_OpenCOMError
	RCSC_TXError
	RCSC_NoAnswer
	RCSC_Ok
*****************************************************************/

/****************************************************************/
DWORD WINAPI IncreaseLG(sCARD_SecurParam Secur,
						BYTE ICount,LPBYTE Value,
						sCARD_Status* Status,
						LPDWORD NewValue);
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


/****************************************************************/
DWORD WINAPI Invalidate(sCARD_SecurParam SecurParam,
						sCARD_Status* Status);
/*****************************************************************
Invalidate the current DF

INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI Rehabilitate(sCARD_SecurParam SecurParam,
						  sCARD_Status* Status);
/*****************************************************************
Rehabilitate the current DF

INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI ReadRecord(sCARD_SecurParam Secur,
						BYTE NuRec,BYTE DataLen,
						LPBYTE Data,sCARD_Status* Status);
/*****************************************************************
Read a record from linear or circular file

INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI SelectFile(BYTE SelectMode,LPBYTE IdPath,
						BYTE IdPathLen,LPBYTE FCI,
						sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI StatusFile(BYTE SelectMode,LPBYTE IdPath,
						BYTE IdPathLen,LPBYTE FCI,
						sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI UpdateRecord(sCARD_SecurParam Secur,
						  BYTE NuRec,BYTE DataLen,
						  LPBYTE Data,sCARD_Status* Status);
/*****************************************************************
Erase and write a record to a EF

INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI WriteRecord(sCARD_SecurParam Secur,
						 BYTE NuRec,BYTE DataLen,LPBYTE Data,
						 sCARD_Status* Status);
/*****************************************************************
Write a record to a EF

INPUTS
	SecurParam	: Contain the parameters for the secury
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


/****************************************************************/
DWORD WINAPI GetEPStatus_CD97(sCARD_SecurParam Secur,BYTE Type,
							  LPDWORD EP,LPBYTE Log,sCARD_Status* Status);
/*****************************************************************
Purchase with the Electronic Purse ( EP )

INPUTS
	SecurParam	: Contain the parameters for the secury
					- NKEY	  : Number of Key which use in the SAM (in future KIF)
					- RUF	  : Reserved for KVC

  Type			: Transaction Type :
					- Loading Transaction   (0x00)
					- Purchase Transaction  (0x01)
					- Purchase cancellation (0x02)

OUTPUT
	EP			: Electronic Purse Value

	Log			: if Type = Loading Transaction (0x00)
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

/****************************************************************/
DWORD WINAPI Purchase_CD97(BYTE Type,LPBYTE DataLog,LPBYTE Disp,
											sCARD_Status* Status);
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


/****************************************************************/
DWORD WINAPI CancelPurchase_CD97(BYTE Type,LPBYTE DataLog,
								LPBYTE Disp,sCARD_Status* Status);
/*****************************************************************
Cancel Purchase with the Electronic Purse ( EP )

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

/****************************************************************/
DWORD WINAPI ReloadEP_CD97(LPBYTE ChargLog1,LPBYTE ChargLog2,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI OpenSession(BYTE Type,
						 sCARD_SecurParam Secur,
						 BYTE NRec,
						 sCARD_Session* Session,
						 sCARD_Status* Status);
/*****************************************************************
Open the secured session

INPUTS
	Type		: Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	SecurParam	: Contain the parameters for the secury
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
/****************************************************************/
DWORD WINAPI OpenSessionExt(BYTE Type,
							sCARD_SecurParam Secur,
							BYTE NRec,BYTE* KVC,
							sCARD_Session* Session,
							sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI CloseSession(LPBYTE Result,LPDWORD cbResult,
											sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI AbortSecuredSession(sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI Lock_Unlock(BYTE Type,
						 sCARD_Status* Status);
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

/****************************************************************/
DWORD WINAPI MultiIncrease( sCARD_SecurParam Secur,
							BYTE NumberCpt,LPBYTE Data,
							LPBYTE NewData,
							sCARD_Status* Status);
/*****************************************************************
Increase a counter file value

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
	RCSC_Ok
*****************************************************************/


/****************************************************************/
DWORD WINAPI MultiDecrease( sCARD_SecurParam Secur,
							BYTE NumberCpt,LPBYTE Data,
							LPBYTE NewData,
							sCARD_Status* Status);
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
	RCSC_Ok
*****************************************************************/




/****************************************************************/
DWORD WINAPI CTx_Active (LPBYTE Data,BYTE* Status);
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

/****************************************************************/
DWORD WINAPI CTx_Read (	BYTE ADD, BYTE NB, LPBYTE Data,BYTE* Status);
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


/****************************************************************/
DWORD WINAPI CTx_Update (BYTE ADD, BYTE NB,
							LPBYTE DataToWrite,LPBYTE DataInCTS,
							LPBYTE Data, BYTE* Status);
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


/****************************************************************/
DWORD WINAPI CTx_Release (BYTE Param, BYTE* Status);
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


/****************************************************************/
DWORD WINAPI CheckCertificate (BYTE KeyType, BYTE Param,
									BYTE LngBuffer, LPBYTE Buffer,
									BYTE LngCertificat, LPBYTE Certificat,
									BYTE *Status );
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

/****************************************************************/
DWORD WINAPI GiveCertificate (BYTE KeyType, BYTE Param,
									BYTE LngBuffer, LPBYTE Buffer,
									BYTE LngCertificat, LPBYTE Certificat,
									BYTE *Status );
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



/*****************************************************************/
DWORD WINAPI CSC_ChangeRS485Address(BYTE CSCAddress485);
/*****************************************************************
Change the mode of protocol to CSC RS485 and set the Address value 

INPUTS
	CSCAddress485 : Address of the CSC on the RS485 Bus
	
OUTPUT

RETURNS
	RCSC_InputDataWrong		Bad Address Value go back to mode RS232
	RCSC_Ok					Good value
*****************************************************************/



/****************************************************************/
DWORD WINAPI CSC_ChangeDLLSpeed(DWORD DLLSpeed);
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


/****************************************************************/
DWORD WINAPI CSC_SetTimings(DWORD func_timeout,DWORD search_timeout,
							DWORD RFU);
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


/*****************************************************************/
DWORD WINAPI CSC_ChangeCSCSpeed(DWORD RS232Speed, 
								DWORD RS485Speed, DWORD TTLSpeed, BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI CSC_SelectCID(BYTE CID, BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI CSC_SelectDIV(BYTE Slot, BYTE Prot, BYTE *DIV, BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI CSC_EHP_PARAMS(BYTE MaxNbCard, BYTE Req, BYTE NbSlot, BYTE AFI, BYTE AutoSelDiv);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	Slot :	Slot of the SAM
	Prot :	0 for Innovatron, 1 for ISO7816
	DIV  :	4 bytes serial number used for alg diversification
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

/*****************************************************************/
DWORD WINAPI CSC_EHP_PARAMS_EXT(BYTE MaxNbCard, BYTE Req, BYTE NbSlot, BYTE AFI, BYTE AutoSelDiv, 
								BYTE Deselect, BYTE SelectAppli, BYTE Lg, LPBYTE Data, 
								WORD FelicaAFI, BYTE FelicaNbSlot);
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


/*****************************************************************/
DWORD WINAPI MIFARE_LoadReaderKeyIndex(BYTE KeyIndex, LPBYTE KeyVal, BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI MIFARE_ChangeKey(BYTE InitialKeyAorB, BYTE NumSector, 
							  BYTE InitialKeyIndex, BYTE FinalKeyAorB, 
							  LPBYTE NewKeyA, LPBYTE NewAccessBits, 
							  LPBYTE NewKeyB, LPBYTE MifareType, 
							  LPBYTE SerialNumber, BYTE *Status);
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

/*****************************************************************/
DWORD WINAPI MIFARE_Select(BYTE* SerialNumber,
						   BYTE  SerialNumberLn,
						   BYTE* Status,
						   BYTE* SerialNumberOut);
/*****************************************************************
Selects a MIFARE card with its unique ID. Enables to detect a card in case of collision.

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

/*****************************************************************/
DWORD WINAPI MIFARE_Detect(BYTE *Status, BYTE *Code, LPBYTE PiccSerialNumber);
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

/*****************************************************************/
DWORD WINAPI MIFARE_Authenticate(BYTE NumSector, BYTE KeyAorB, 
							  BYTE KeyIndex, LPBYTE MifareType, 
							  LPBYTE SerialNumber, BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI MIFARE_Halt(void);
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


/*****************************************************************/
DWORD WINAPI MIFARE_ReadBlock(BYTE NumBlock, 
							  LPBYTE DataRead, BYTE *Status);
/*****************************************************************
Read a block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 
  
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


/*****************************************************************/
DWORD WINAPI MIFARE_ReadSector(BYTE NumSector, BYTE KeyAorB, 
							  BYTE KeyIndex, LPBYTE MifareType, 
							  LPBYTE SerialNumber, LPBYTE DataRead, 
							  BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI MIFARE_WriteBlock(BYTE NumBlock, LPBYTE DataToWrite, 
							  LPBYTE DataVerif, BYTE *Status);
/*****************************************************************
Write a block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 
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


/*****************************************************************/
DWORD WINAPI MIFARE_DecrementValue(BYTE NumBlock, LPBYTE Substract, 
							  LPBYTE Verif, BYTE *Status);
/*****************************************************************
Decrement a Value block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 (must be previously configured as a value block)
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


/*****************************************************************/
DWORD WINAPI MIFARE_IncrementValue(BYTE NumBlock, LPBYTE Addition, 
							  LPBYTE Verif, BYTE *Status);
/*****************************************************************
Increment a Value block in a MIFARE card : For this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 (must be previously configured as a value block)
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


/*****************************************************************/
DWORD WINAPI MIFARE_BackUpRestoreValue(BYTE Origine, BYTE Destination, BYTE *Status);
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

/*****************************************************************/
DWORD WINAPI MIFARE_ReadMultipleBlock(BYTE BlockNum, BYTE NumBlock, BYTE *Status, LPBYTE DataRead);
/*****************************************************************
Read several blocks in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	BlockNum		:	Block number from 0 to 255 
	NumBlock		:	Number of Block "n"
  
OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation)
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

/*****************************************************************/
DWORD WINAPI MIFARE_SimpleWriteBlock(BYTE BlockNum, LPBYTE DataToWrite, BYTE *Status);
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

/*****************************************************************/
DWORD WINAPI MIFARE_ReadSectorData(BYTE KeyAorB, BYTE NumSector, BYTE KeyIndex, 
									BYTE *Status, BYTE *MifareType, LPBYTE SerialNumber, LPBYTE DataRead);
/*****************************************************************
Read a the data blocks Sector of the PICC

INPUTS
	KeyAorB			:	Choice of the key needed for authentication  
	NumSector		:	Sector to authenticate and read
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

/*****************************************************************/
DWORD WINAPI MIFARE_WriteSectorData(BYTE KeyAorB, BYTE NumSector, BYTE KeyIndex, LPBYTE DataToWrite,
									BYTE CardType, BYTE *Status);
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


/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_Authenticate(BYTE NumKey, BYTE VersionKey, BYTE KeyAorB,  
										BYTE NumBlock, BYTE LgDiversifier, BYTE BlockDiversifier,
										BYTE *StatusCard, WORD *StatusSam);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_ReAuthenticate(BYTE NumKey, BYTE VersionKey, BYTE KeyAorB,  
										  BYTE NumBlock, BYTE LgDiversifier, BYTE BlockDiversifier,
										  BYTE *StatusCard, WORD *StatusSam);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_ReadBlock(BYTE NumBlock, BYTE *StatusCard, WORD *StatusSam,
									 LPBYTE DataRead);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_WriteBlock(BYTE NumBlock, LPBYTE DataToWrite, 
								      BYTE *StatusCard, WORD *StatusSam, BYTE *StatusWrite);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_ChangeKey(BYTE NumKey, BYTE VersionKeyA, BYTE VersionKeyB,
									 LPBYTE DefaultAccess, BYTE NumBlock, BYTE LgDiversifier,
									 BYTE BlockDiversifier, BYTE *StatusCard, WORD *StatusSam, BYTE *StatusChangeKey);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_Increment(BYTE NumBlock, LPBYTE Increment,
									 BYTE *StatusCard, WORD *StatusSam, BYTE *StatusIncrement);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_Decrement(BYTE NumBlock, LPBYTE Decrement,
									 BYTE *StatusCard, WORD *StatusSam, BYTE *StatusDecrement);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_BackUpValue(BYTE Source, BYTE Destination,
									   BYTE *StatusCard, WORD *StatusSam, BYTE *StatusBackUp);
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

/*****************************************************************/
DWORD WINAPI MIFARE_SAMNXP_KillAuthentication(WORD *StatusSam);
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


/*****************************************************************/
DWORD WINAPI MFP_SL3_Authentication(BYTE SamKeyNum, BYTE SamKeyVersion, WORD KeyBlockNum,
									BYTE LgDiversifier, LPBYTE Diversifier, 
									BYTE *StatusCard, WORD *StatusSam);														
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

/*****************************************************************/
DWORD WINAPI MFP_SL3_ResetAuthentication(BYTE Mode, BYTE *StatusCard, WORD *StatusSam);														
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

/*****************************************************************/
DWORD WINAPI MFP_SL3_ReadBlock(BYTE Mode, WORD BlockNum, BYTE NumBlock,
								BYTE *StatusCard, WORD *StatusSam, LPBYTE DataRead);														
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


/*****************************************************************/
DWORD WINAPI MFP_SL3_WriteBlock(BYTE Mode, WORD BlockNum, BYTE NumBlock, LPBYTE DataToWrite, 
								BYTE *StatusCard, WORD *StatusSam);														
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


/*****************************************************************/
DWORD WINAPI MFP_SL3_ChangeKey(BYTE SamKeyNum, BYTE SamKeyVersion, WORD KeyBlockNum, 
								BYTE LgDiversifier, LPBYTE Diversifier, 
								BYTE *StatusCard, WORD *StatusSam);														
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


/*****************************************************************/
DWORD WINAPI MFP_SL3_VirtualCardSupport(BYTE SamKeyNumVCENC, BYTE SamKeyVersionVCENC,  
										BYTE SamKeyNumVCMAC, BYTE SamKeyVersionVCMAC, LPBYTE IID,
										BYTE *StatusCard, WORD *StatusSam, LPBYTE UID);														
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


/*****************************************************************/
DWORD WINAPI MFP_SL3_DeselectVirtualCard(BYTE *StatusCard);														
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


/*****************************************************************/
DWORD WINAPI DESFIRE_CreateApplication(LPBYTE AppID, BYTE Opt, BYTE KeyNum, WORD *Status);
/*****************************************************************
Create a new application in the card

INPUTS
	AppID			:	ID Number of the Appl in the card (3 byte)
	Opt				:	Options (1 byte)
						xxxx0001b Config changeable
						xxxx0010b Create/Delete operation are free (without master key)
						xxxx0100b Access to list directory is free (without master key)
						xxxx1000b master key setting can be changed
	KeyNum			:	Key Number usable for that new application

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

/*****************************************************************/
DWORD WINAPI DESFIRE_DeleteApplication(LPBYTE AppID, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_SelectApplication(LPBYTE AppID, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_FormatPICC(WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_GetApplicationIDs(BYTE NumID, BYTE *Lg, WORD *Status, LPBYTE IDs);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_GetVersion(WORD *Status, LPBYTE HardInfo, LPBYTE SoftInfo, 
								LPBYTE UID, LPBYTE Batch, BYTE *CW, BYTE *Year);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_GetFreeMem(WORD *Status, LPBYTE Size);
/*****************************************************************
Version of the card firmware

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

/****************************************************************/
DWORD DESFIRE_PrepareAuthentication (	BYTE AuthMode,
          								BYTE SAMKeyNumber,
          								BYTE SAMKeyVersion,
										WORD *Status);
/*****************************************************************
This function sets parameters used for authentication.
Parameters  :
I	BYTE	AuthMode		Authentication parameters (see SAM AV2 specification).
I	BYTE	SAMKeyNumber	Key number in the SAM.
I	BYTE	SAMKeyVersion	Key version of the specified key in the SAM.
O	WORD	*Status			Status (2 byte) : 0x9000 = OK
*****************************************************************/

/*****************************************************************/
DWORD WINAPI DESFIRE_Authenticate(BYTE KeyNum, WORD *Status);
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

/****************************************************************/
DWORD WINAPI DESFIRE_AuthenticateEV1 (	BYTE PICCKeyNumber,
								BYTE AuthMode,
								BYTE SAMKeyNumber,
								BYTE SAMKeyVersion,
								BYTE Type,
								BYTE LgDiversifier,
								BYTE *Diversifier,
								WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_CommitTransaction(WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_AbortTransaction(WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_ChangeKey(	BYTE CurKeyNo,
								BYTE CurKeyV,
								BYTE NewKeyNo,
								BYTE NewKeyV,
								BYTE KeyCompMeth,
								BYTE Cfg,
								BYTE Algo,
								BYTE LgDiversifier,
								BYTE *Diversifier,
								WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_ChangeKeySetting(BYTE KeySetting, WORD *Status);
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


/*****************************************************************/
DWORD WINAPI DESFIRE_GetKeySetting(WORD *Status, BYTE *KeySetting, BYTE *NumKey);
/*****************************************************************
Retreive the current application ID

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

/*****************************************************************/
DWORD WINAPI DESFIRE_GetKeyVersion(BYTE KeyNum, WORD *Status, BYTE *KeySetting);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_ChangeFileSetting(BYTE FileID, BYTE CommEncrypted, BYTE CommMode, 
										BYTE AccessRight, WORD *Status);
/*****************************************************************
Changes the file configuration on the card

INPUTS
	FileID			:	ID of the file whose communication mode and access rights settings shall be changed (1 byte)
	CommEncrypted	:	Encrypt the communication (1 byte)
	CommMode		:	new communication mode (1 byte)
	AccessRight	:	specify the access right setting for this file (1 byte)

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

/*****************************************************************/
DWORD WINAPI DESFIRE_ClearRecordFile(BYTE FileID, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_CreateBackUpDataFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
											LPBYTE FileSize, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_CreateCyclicRecordFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
											LPBYTE RecordSize, LPBYTE MaxNumRecord, WORD *Status);
/*****************************************************************
Creation of a Cyclic Data File

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

/*****************************************************************/
DWORD WINAPI DESFIRE_CreateLinearRecordFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
											LPBYTE RecordSize, LPBYTE MaxNumRecord, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_CreateStandardDataFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
											LPBYTE FileSize, WORD *Status);
/*****************************************************************
Creation of a Standard Data File

INPUTS
	FileID			:	ID of the file for which the new Linear record File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	FileSize		:	Size of the new linear File in bytes (3 byte)

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

/*****************************************************************/
DWORD WINAPI DESFIRE_CreateValueFile(BYTE FileID, BYTE CommMode, WORD AccessRight, LPBYTE Lower, 
									LPBYTE Upper, LPBYTE Initial, BYTE Limited, WORD *Status);
/*****************************************************************
Creation of a Value File

INPUTS
	FileID			:	ID of the file for which the new File is to be created (1 byte)
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

/*****************************************************************/
DWORD WINAPI DESFIRE_Credit(BYTE FileID, BYTE CommMode, LPBYTE Amount, WORD *Status);
/*****************************************************************
Credit a Value on a Value File

INPUTS
	FileID			:	ID of the file for which the new File is to be created (1 byte)
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

/*****************************************************************/
DWORD WINAPI DESFIRE_Debit(BYTE FileID, BYTE CommMode, LPBYTE Amount, WORD *Status);
/*****************************************************************
Debit a Value on a Value File

INPUTS
	FileID			:	ID of the file for which the new File is to be created (1 byte)
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

/*****************************************************************/
DWORD WINAPI DESFIRE_DeleteFile(BYTE FileID, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_GetFileID(BYTE MaxFileID, WORD *Status, BYTE *NbFound, LPBYTE FileId);
/*****************************************************************
Get File ID for the current application 

INPUTS
	MaxFileID		:	Max response expected  (1 byte)

OUTPUTS
	Status			:	Status of the operation (see CSC Interface documentation) (2 bytes)
	NbFound			:	Number of FileId found (1 byte)
	FileId			:	FileID array (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/

/*****************************************************************/
DWORD WINAPI DESFIRE_GetFileSetting(BYTE FileID, WORD *Status, BYTE *FileType, BYTE *CommMode, WORD *AccessRight);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_GetValue(BYTE FileID, BYTE CommMode, WORD *Status, LPBYTE Amount);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_LimitedCredit(BYTE FileID, BYTE CommMode, LPBYTE Amount, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_ReadData(BYTE FileID, BYTE CommMode, WORD FromOffset, WORD NumByteToRead, 
								WORD *Status, WORD *NumByteRead, LPBYTE DataRead);
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
	Data			:	Data read in the File (n bytes)

RETURNS
	RCSC_Ok					
	RCSC_OpenCOMError		
	RCSC_Timout				
	RCSC_Fail				
	RCSC_DataWrong		
	RCSC_Checksum		
*****************************************************************/

/*****************************************************************/
DWORD WINAPI DESFIRE_WriteData(BYTE FileID, BYTE CommMode, WORD FromOffset, WORD NumByteToWrite, LPBYTE DataToWrite, WORD *Status);
/*****************************************************************
Read Data standard File 

INPUTS
	FileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	CommMode		:	File communication mode (1 byte)
	FromOffset		:	Offset in the File (2 bytes)
	NumByteToRead	:	Nb byte to write (2 bytes)
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

/*****************************************************************/
DWORD WINAPI DESFIRE_ReadRecord(BYTE FileID, BYTE CommMode, WORD FromRecord, WORD NumRecordToRead, 
								WORD RecordSize, WORD *Status, WORD *NumRecordRead, LPBYTE DataRead);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_WriteRecord(BYTE FileID, BYTE CommMode, WORD FromRecord, WORD NumRecordToWrite, 
								 LPBYTE DataToWrite, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_SamGetVersion(BYTE *Lg, WORD *Status, LPBYTE SamVersion);
/*****************************************************************
Sam Firmware Info

INPUTS
	-

OUTPUTS
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

/*****************************************************************/
DWORD WINAPI DESFIRE_SamSelectApplication(LPBYTE DirFileAID, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_SamLoadInitVector(LPBYTE InitVector, WORD *Status);
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

/*****************************************************************/
DWORD WINAPI DESFIRE_SamGetKeyEntry(BYTE KeyNum, BYTE *Lg, WORD *Status, LPBYTE KeyEntry);
/*****************************************************************
Key entry Info

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

/*****************************************************************/
DWORD WINAPI DESFIRE_SamGetKucEntry(BYTE RefKucNum, BYTE *Lg, WORD *Status, LPBYTE KucEntry);
/*****************************************************************
Key Usage Counter Info

INPUTS
	RefKucNum:	Key Usage Counter Entry Reference Number (1 bytes)

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

/*****************************************************************/
DWORD WINAPI DESFIRE_SamDisableCrypto(WORD PROMAS, WORD *Status);
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


/*****************************************************************/
DWORD WINAPI SRX_Active(BYTE *Status, BYTE *ChipType, LPBYTE UID);														
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

/*****************************************************************/
DWORD WINAPI SRX_ReadBlock(BYTE BlockNum, BYTE NumBlock, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead);														
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

/*****************************************************************/
DWORD WINAPI SRX_WriteBlock(BYTE BlockNum, BYTE NumBlock, LPBYTE DataToWrite, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead);														
/*****************************************************************
Read Blocks.

INPUTS
	BlockNum			:	Block Number to start reading (1 bytes)
	NumBlock			:	Number of block to read (1 bytes)
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

/*****************************************************************/
DWORD WINAPI SRX_Release(BYTE Param, BYTE *Status);												
/*****************************************************************
Read Blocks.

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

/*****************************************************************/
DWORD WINAPI SRX_Read(WORD Add, BYTE NumBytes, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead);														
/*****************************************************************
Read Bytes at a given address.

INPUTS
	Add					:	Address of the first reading -> LSB / MSB (2 bytes)
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

/*****************************************************************/
DWORD WINAPI SRX_Write(WORD Add, BYTE NumBytes, LPBYTE DataToWrite, BYTE ChipType, BYTE *Lg, BYTE *Status, LPBYTE DataRead);														
/*****************************************************************
Write and Verify Bytes at a given address.

INPUTS
	Add					:	Address of the first reading -> LSB / MSB (2 bytes)
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


/****************************************************************/
DWORD WINAPI CTx512B_List(BYTE RFU, BYTE* nbTickets,BYTE* serialNumbers,
						  BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512B_Select(BYTE* serialNumber,BYTE* serialNumberRead,
							BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512B_Read (BYTE ADD,BYTE NB,BYTE* dataRead,BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512B_Update(BYTE ADD, BYTE NB,BYTE* dataToWrite,
							BYTE* dataRead, BYTE* status);
/*****************************************************************
UPDATE CTX512B
deletion if necessary, update then checking (reading bytes written)

INPUTS
	ADD			: adress of the first byte to write (0 ... 63)
	NB			: Number of bytes to write (from 1 up to 64)
	dataToWrite	: Data to write
	dataInTicket: Data already read and stored in the CTx512B

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


/****************************************************************/
DWORD WINAPI CTx512B_Halt (BYTE param, BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_List(BYTE	RFU, BYTE* nbTickets,
						  BYTE* serialNumbers, BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_Select(BYTE* serialNumber,
							BYTE* serialNumberRead, BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_Read (BYTE ADD, BYTE NB, BYTE* dataRead,
						   BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_Update(BYTE ADD, BYTE NB, BYTE* dataToWrite,
							  BYTE* dataRead, BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_Halt (BYTE param, BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_Write(BYTE ADD, BYTE NB, BYTE* dataToWrite,
							  BYTE* dataRead, BYTE* status);
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


/****************************************************************/
DWORD WINAPI CTx512x_Authenticate(BYTE ADD,
								BYTE kif_kref,
								BYTE kvc_zero,
								BYTE* status,
								BYTE* dataSAMLength,
								BYTE* dataSAM);
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



/****************************************************************/
DWORD WINAPI CTx512x_WriteKey( BYTE kif_kref,
							BYTE kvc_zero,
							BYTE* status,
							BYTE* dataSAMLength,
							BYTE* dataSAM);
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

/****************************************************************/
BOOL WINAPI PortNameIsPresent(LPSTR ComName, BOOL All);
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

/****************************************************************/
BOOL WINAPI PortIsCDC(LPSTR ComName);
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

/****************************************************************/
BOOL WINAPI RecoverCDCPort (LPSTR ComName,DWORD dwDisconnectTimeout, DWORD dwReconnectTimeout);
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

/****************************************************************/
BOOL WINAPI CSC_SendCOM(BYTE* BufIN,DWORD LnIN);
/*****************************************************************
Send only data to the communication port

INPUTS
	BufIN							Frame to send to COM port
	LnIN							BufIN data length

RETURNS
  TRUE              Function success 
	FALSE             Function fails
*****************************************************************/

/****************************************************************/
INT WINAPI CSC_ReceiveCOM(DWORD TimeOut,DWORD Len,BYTE* BufOUT);
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
DWORD WINAPI CSC_SetSAMBaudratePPS( BYTE ProProt, BYTE ParamFD,WORD *Status);
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

/****************************************************************/
DWORD WINAPI EMVCo_UserInterface (BYTE SequenceNumber,LPBYTE Status);
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

/****************************************************************/
DWORD WINAPI EMVCo_Contactless (BYTE CommandNumber,
								LPBYTE Parameters,
								LPBYTE Status,
								LPBYTE Length,
								LPBYTE PICCData);
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

/****************************************************************/
DWORD WINAPI CalypsoRev3_GetMode (BYTE *Mode);
/*****************************************************************
Get the Calypso Rev3 mode flag. In Calypso Rev3 mode, the reader will try to manage the card as a Calypso rev3 card if the card is compliant.
Parameters:
O	BYTE*	Mode			$00: Calypso Rev3 mode disabled.
							$01: Calypso Rev3 mode enabled.
*****************************************************************/

/****************************************************************/
DWORD WINAPI CalypsoRev3_SetMode (BYTE Mode);
/*****************************************************************
Set the Calypso Rev3 mode flag. In Calypso Rev3 mode, the reader will try to manage the card as a Calypso rev3 card if the card is compliant.
Parameters:
I	BYTE	Mode			$00: Disable Calypso Rev3 mode.
							$01: Enable Calypso Rev3 mode.
*****************************************************************/

/****************************************************************/
DWORD MFUL_Identify (BYTE RFU, BYTE *Status);
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


/****************************************************************/
DWORD MFUL_Read (BYTE ByteAddress, BYTE Nb, BYTE *Status,
				 BYTE *LngData, BYTE *ReadData);
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

/****************************************************************/
DWORD MFUL_Write (BYTE ByteAddress, BYTE Nb,BYTE *DataToWrite, 
				  BYTE *Status, BYTE *LngData, BYTE *ReadData);
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

/****************************************************************/
DWORD MFULC_Authenticate (BYTE KeyNo, BYTE KeyV,
						  BYTE DIVLength, BYTE *DIVInput,
						  BYTE *Status, WORD *SAMStatus);
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

/****************************************************************/
DWORD MFULC_WriteKeyFromSAM  (BYTE KeyNo, BYTE KeyV, 
       						  BYTE DIVLength, BYTE *DIVInput,
							  BYTE *Status, WORD *SAMStatus);
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

/****************************************************************/
DWORD MFULEV1_PasswordAuthenticate (BYTE *Password, BYTE *Status, BYTE *PACK);
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

/****************************************************************/
DWORD MFULEV1_CreateDiversifiedPasswordandPACK (BYTE KeyNo, BYTE KeyV, 
       											BYTE DIVLength, BYTE *DIVInput,
												WORD *SAMStatus,
												BYTE *Password, BYTE *PACK);
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



/****************************************************************/
DWORD MFULEV1_ReadCounter ( BYTE CounterNb, BYTE *Status,
							DWORD *CounterValue);
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

/****************************************************************/
DWORD MFULEV1_IncrementCounter (BYTE CounterNb, 
								DWORD IncrementValue,
								BYTE *Status);
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

/****************************************************************/
DWORD MFULEV1_GetVersion ( BYTE *Status, BYTE *LngData, BYTE *Data);
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

/****************************************************************/
DWORD MFULEV1_CheckTearingEvent (BYTE CounterNb,
								 BYTE *Status,
								 BYTE *Valid);
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



#endif /* __ASKCSC_IN__ */


#ifdef __cplusplus
}
#endif


#endif /* __ASKCSC_H__ */
