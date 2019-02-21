/*****************************************************************
  Interface CSC Module Functions  ( csc_ord.h )

  P R O T O T Y P E S

  ANSI 'C' language, No specific plateform

  Copyright (C)2002-1999 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Thierry J. / Serge M. - ASK
*****************************************************************/


/*****************************************************************
  HISTORY :
$Log:   W:/Lecteurs/DLL Askcsc/Sources/archives/csc_ord.h-arc  $
 * 
 *    Rev 1.13   13 Jun 2005 15:04:10   gbrand
 * CSC CRC enable/disable
 * 
 *    Rev 1.12   06 Jun 2005 14:12:00   ccoure
 * MAJ pour gestion ou non du CRC
 * 
 *    Rev 1.11   Jan 28 2004 14:53:06   cjeann
 * * Ajout des commandes transparentes CSC_TransparentCommand et CSC_TransparentCommandConfig.
 * * Ajout des commandes de la classe CTx512x.
 * * Ajout de la commande 00_06_WriteSAMNumber.
 * * Ajout de la gestion des trames longues avec le passage de la taille max de la trame de 256 à 270 octets.
 * 
 *    Rev 1.10   Oct 03 2002 11:47:14   blepin
 * voir change history
 * 
 *    Rev 1.9   Sep 16 2002 15:45:46   blepin
 * Mise à jour de la datation de la DLL
 * 
 *    Rev 1.8   Sep 16 2002 15:11:40   blepin
 * Voir liste des modification
 * 
 *    Rev 1.7   Feb 08 2002 15:19:42   smanig
 * Tous fichiers modifiés pour ajout de la classe MIFARE
 * 
 *    Rev 1.5   May 11 2001 15:48:10   smanig
 * Ajout de la fonction d'appel ChangeSpeed
 * 
 *    Rev 1.4   Mar 30 2001 16:02:38   ccoure
 * Maj pour harmonisation du nom des commandes ticket


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
Ver 4.00.02.036		 02-02-05  SM   Add RS485,Speed and Mifare functions 
Ver 3.11.01.260		 01-09-21  SM   Not modified
Ver 3.10.01.064		 01-03-05  CCV  Add CTS functions 
Ver 3.01.00.329		 00-11-24  JLM  Add GEN 3XX Managment
Ver 2.01.00.116      00-04-25  THJ  GTML class
Ver 1.07.99.142      99-05-18  THJ  First Commercial Version
Ver 1.06.99.130      99-05-06  THJ  Add the DEBUG LOG
Ver 1.05.99.102      99-04-09  THJ  Add CD97 function
Ver 1.01.99.081      99-03-19  THJ  Created
*****************************************************************/

#ifndef __iCSC_ORD_H__
#define __iCSC_ORD_H__

/* Our Types ****************************************************/

typedef unsigned char   BYTE;	/*  8 bits */
typedef unsigned short  ushort;	/* 16 bits */
typedef unsigned long	ulong;	/* 32 bits */ 

/* Internal Constants *******************************************/
//#define kiCSCMaxTrame    256    /* Trame length max */
//#define kiCSCMaxTrame    310    /* Trame length max (256->270 for long frames)*/
#define kiCSCMaxTrame    600    /* Trame length max */

/* Status values Constants **************************************/
#define iCSC_OK         0x01    /* Function success */
#define iCSC_FAIL       0x00    /* Function fail */


/* Types ********************************************************/


/* iCSC_SetTagCommParam Structure */
typedef struct iCSC_STCPtag
{
BYTE ValidAddr;
BYTE PSCL_Timeout1;			/* Command Timeout (ms) */
BYTE PSCL_Timeout2;			/* Data Timeout (ms) */
BYTE PSCL_HangNumber;			/* number of hanging */
BYTE CLESS_Timeout1;			/* Command Timeout (ms) */
BYTE CLESS_Timeout2;			/* Data Timeout (ms) */
BYTE CLESS_HangNumber;			/* number of hanging */
}iCSC_STCP;


/* iCSC_LoadDataSAM Structure */
typedef struct iCSC_LDStag
{
BYTE Key[8];					/* Crypt Key */
BYTE Data[29];					/* Data to load */
BYTE Ref;						/* Data ref */
}iCSC_LDS;



/* Global Variables and buffers used to exchange frames with
the functions ***************************************************/

#ifdef __iCSC_ORD__
BYTE giCSCTrame[kiCSCMaxTrame];/* Buffer used to exchange */
//BYTE giCSCTrameLn;           /* Number of bytes in giCSCTrame */
int giCSCTrameLn;				/* Number of bytes in giCSCTrame */
BYTE giCSCStatus;              /* Status retreive by the function */
BYTE giCSCMode485;				/* Indicate if the CSC protocol is RS485 or RS232 mode */
BYTE giCSCNumber485;			/* Number of the CSC on the RS485 Bus */
BYTE giCRCNeeded;				/* indicate if the CRC is needed */
ulong ComSpeed;					/* Communication speed parameter for the DLL */
BYTE gSAM_Prot[5];				/* Memo of Sam Prot for each SAM slot */
BYTE gCurrentSAM;				/* Sam Slot Currently Selectionned */
ulong FuncTimeout;				/* Timeout for CSC_SendReceive in functions in askcsc.c*/
ulong SearchTimeout;				/* Timeout for CSC_SearchCard and CSC_SearchCardExt */
#else
extern BYTE giCSCTrame[kiCSCMaxTrame];
//extern BYTE giCSCTrameLn;
extern int giCSCTrameLn;
extern BYTE giCSCStatus;
extern BYTE giCSCMode485;	
extern BYTE giCSCNumber485;
extern BYTE giCRCNeeded;
extern ulong ComSpeed;	
extern BYTE gSAM_Prot[5];
extern BYTE gCurrentSAM;
extern ulong FuncTimeout;
extern ulong SearchTimeout;

#endif /* __iCSC_ORD__ */



/* Prototypes ***************************************************/


/****************************************************************/
void icsc_SetCRC(void);
/*****************************************************************
Compute and Set the CRC at the end of the buffer

INPUTS
  The buffer giCSCTrame must be initialized.
OUTPUTS
  The two last byte of the giCSCTrame buffer
  The giCSCTrameLn is incremented by 2
*****************************************************************/


/****************************************************************/
BYTE iCSC_TestCRC(void);
/*****************************************************************
Test the CRC of the buffer

INPUTS
  The buffer giCSCTrame must be initialized with the CRC
RETURNS
  iCSC_OK      Validate CRC
  iCSC_FAIL    CRC error
*****************************************************************/


/****************************************************************/
void iCSC_SoftwareVersion(void);
/*****************************************************************
Returns the CSC Software version
*****************************************************************/

/*****************************************************************/
void iCSC_SearchStop(BYTE type);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Type :	0 for INTERROGATION; 1 for DEFINITIVELY
OUTPUTS
	None 
  
*****************************************************************/

/****************************************************************/
void iCSC_EnterHuntPhase(BYTE Antenna,BYTE SearchType);
/*****************************************************************
Starts the search of a card

INPUTS
  Antenna    : Antenna Type ( CSC_SYS_ANTENNE_1, ... )
  SearchType : The card type ( CSC_SEARCH_PSCL or CSC_SEARCH_CLESSCARD )
*****************************************************************/

/****************************************************************/
void iCSC_EnterHuntPhase2(BYTE Antenna,
						  BYTE CONT,BYTE ISOA,BYTE ISOB,BYTE TICK,BYTE INNO,
						  BYTE Forget,BYTE TimeOut);
/*****************************************************************
Starts the search of a card

INPUTS
	Antenna	: Antenna Type ( CSC_SYS_ANTENNE_1, ... )
	CONT	: Contact Mode ratio (0-F)
	ISOB	: ISO B Protocol Mode ratio (0-F)
	ISOA	: ISO A Protocol Mode ratio (0-F)
	TICK	: Ticket Mode ratio (0-F)
	INNO	: Innovatron Protocol Mode ratio (0-F)
	Forget	: Parameter to forget the last tag serial number.
	TimeOut	: Time Out of the command (x10ms).

*****************************************************************/

/****************************************************************/
void iCSC_EnterHuntPhase3(BYTE Antenna,
						  BYTE CONT,BYTE ISOA,BYTE MIFARE,BYTE ISOB,
						  BYTE TICK,BYTE INNO,
						  BYTE MV4k, BYTE MV5k,
						  BYTE Forget,BYTE TimeOut);
/*****************************************************************
Starts the search of a card

INPUTS
	Antenna	: Antenna Type ( CSC_SYS_ANTENNE_1, ... )
	CONT	: Contact Mode ratio (0-F)
	ISOB	: ISO B Protocol Mode ratio (0-F)
	ISOA	: ISO A Protocol Mode ratio (0-F)
	MIFARE	: MIFARE Protocol mode ratio (0-F)
	TICK	: Ticket Mode ratio (0-F)
	INNO	: Innovatron Protocol Mode ratio (0-F)
	MV4k	: MV4k Protocol Mode ratio (0-3)
	MV4k	: MV5k Protocol Mode ratio (0-3)
	Forget	: Parameter to forget the last tag serial number.
	TimeOut	: Time Out of the command (x10ms).

  Note : the inputs ranges must have been previously formatted (0-F, etc...)
*****************************************************************/

/****************************************************************/
void iCSC_EnterHuntPhase4(BYTE Antenna,
						  BYTE MONO,
						  BYTE CONT,BYTE ISOA,BYTE MIFARE,BYTE ISOB,
						  BYTE TICK,BYTE INNO,
						  BYTE MV4k, BYTE MV5k,
						  BYTE Forget,BYTE TimeOut);
/*****************************************************************
Starts the search of a card

INPUTS
	Antenna	: Antenna Type ( CSC_SYS_ANTENNE_1, ... )
	MONO	: mono-search mode (0 or 1)
	CONT	: Contact Mode ratio (0-F)
	ISOB	: ISO B Protocol Mode ratio (0-F)
	ISOA	: ISO A Protocol Mode ratio (0-F)
	MIFARE	: MIFARE Protocol mode ratio (0-F)
	TICK	: Ticket Mode ratio (0-F)
	INNO	: Innovatron Protocol Mode ratio (0-F)
	MV4k	: MV4k Protocol Mode ratio (0-3)
	MV4k	: MV5k Protocol Mode ratio (0-3)
	Forget	: Parameter to forget the last tag serial number.
	TimeOut	: Time Out of the command (x10ms).

  Note : the inputs ranges must have been previously formatted (0-F, etc...)
*****************************************************************/

/****************************************************************/
void iCSC_EnterHuntPhase5(BYTE Antenna,
						  BYTE MONO, BYTE SRX,
						  BYTE CONT,BYTE ISOA,BYTE MIF,BYTE ISOB,
						  BYTE TICK,BYTE INNO,
						  BYTE MV4k, BYTE MV5k,
						  BYTE Forget,BYTE TimeOut);
/*****************************************************************
Starts the search of a card

INPUTS
	Antenna	: Antenna Type ( CSC_SYS_ANTENNE_1, ... )
	MONO	: mono-search mode (0 or 1)
	SRX		: SRx Family ratio (0-F)
	CONT	: Contact Mode ratio (0-F)
	ISOB	: ISO B Protocol Mode ratio (0-F)
	ISOA	: ISO A Protocol Mode ratio (0-F)
	MIFARE	: MIFARE Protocol mode ratio (0-F)
	TICK	: Ticket Mode ratio (0-F)
	INNO	: Innovatron Protocol Mode ratio (0-F)
	MV4k	: MV4k Protocol Mode ratio (0-3)
	MV4k	: MV5k Protocol Mode ratio (0-3)
	Forget	: Parameter to forget the last tag serial number.
	TimeOut	: Time Out of the command (x10ms).

  Note : the inputs ranges must have been previously formatted (0-F, etc...)
*****************************************************************/

/****************************************************************/
void iCSC_EndTagCommunication(BYTE DiscnxMode);
/*****************************************************************
End the communication with the card

INPUTS
  DiscnxMode : Disconnect Mode (CSC_SYS_DISC_REQ,CSC_SYS_NO_DISC_REQ)
*****************************************************************/


/****************************************************************/
void iCSC_SetAntennaTransparentMode(BYTE Antenna,BYTE SearchType,
                                    BYTE TranspMode);
/*****************************************************************
Set the Antenna Transparent mode parameters

INPUTS
  Antenna    : Antenna Type ( CSC_SYS_ANTENNE_1, ... )
  SearchType : The card type ( CSC_SEARCH_PSCL or CSC_SEARCH_CLESSCARD )
  TranspMode : Transparent Mode ( CSC_SYS_MODE_TRANSPARENT_1, ... )
*****************************************************************/


/****************************************************************/
void iCSC_SendToAntenna(BYTE *Data,BYTE DataLen);
/*****************************************************************
Send directly the Data to Antenna

INPUTS
  Data       : Data to send
  DataLen    : The size of data to send
*****************************************************************/

/****************************************************************/
void iCSC_SendToAntennaExt(BYTE pLnINLow, BYTE pLnINHigh, BYTE* pBufIN);
/*****************************************************************
Sends an ISO command Extended, and returns the answer.

INPUTS
	LnINLow		: ISO command length Low (1 Byte)
	LnINHigh	: ISO command length High (1 Byte)
	BufIN		: the ISO Command to send to the card (n Bytes)

*****************************************************************/

/****************************************************************/
void iCSC_TransparentCommandConfig(BYTE ISO, BYTE addCRC, BYTE checkCRC, BYTE field);
/*****************************************************************
configuration of the transparent commands

INPUTS
  ISO :		0x00 : for getting the current config
			0x01 : for selecting ISOB
			0x02 : for selecting ISOA
  addCRC :	0x01 : the CRC will be computed and added to the frame
			else : nothing to add, the frame is sent directly
  checkCRC :	0x01 : the CRC of the frame received needs to be checked
				else : to check
  field :		0x01 : the field will be switched ON when sending the frame
				else : no modification of the field
*****************************************************************/

/****************************************************************/
void iCSC_TransparentCommandConfigExt(BYTE ISO,
									 BYTE addCRC,
									 BYTE checkCRC,
									 BYTE addParity,
									 BYTE checkParity,
									 BYTE numBitLastByte,
									 BYTE byPassISOA,
									 BYTE field,
									 WORD timeOut);
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
	numBitLastByte :Number of bits of the last byte that shall transmitted (1 byte)
	byPassISOA :	0x01 : ByPass ISOA
					else : True ISOA
	field :			0x01 : the field will be switched ON when sending the frame
					else : no modification of the field
	timeOut	:		TimeOut Allowed for answer 0 to 2000 ms (default 456 ms) (2 byte) 	

*****************************************************************/

/****************************************************************/
void iCSC_TransparentCommand(BYTE frameLength, BYTE* frame);
/*****************************************************************
sends and receives the transparent command, as specified in
	iCSC_TransparentCommandConfig

INPUTS
  frameLength	: length of frame
  frame			: frame to send
*****************************************************************/

/****************************************************************/
void iCSC_GetCommStatus(void);
/*****************************************************************
Return the last command status
*****************************************************************/


/****************************************************************/
void iCSC_SetAPGENExtensions(BYTE SearchType,BYTE OccupParam,
                                    BYTE ATRMode);
/*****************************************************************
Set the Antenna Transparent mode parameters

INPUTS
  SearchType : The card type ( CSC_SEARCH_PSCL or CSC_SEARCH_CLESSCARD )
	OccupParam : Occupation Parameters ( 0 - 63 )
  ATRMode    : CSC_SYS_ATR : return ATR in REPGEN    CSC_SYS_NO_ATR : no ATR
*****************************************************************/

/****************************************************************/
void iCSC_SetTagCommParam(iCSC_STCP* Stcp);
/*****************************************************************
Set the Communication parameters

INPUTS
  Stcp       : Pointer to a iCSC_STCP structure to be filled in.
*****************************************************************/


/****************************************************************/
void iCSC_SwitchOffAntenna(BYTE Antenna);
/*****************************************************************
Stop the antenna

INPUTS
  Antenna    : Antenna Type ( CSC_SYS_ANTENNE_1, ... )
*****************************************************************/


/****************************************************************/
void iCSC_WriteSAMNumber(BYTE N_SAM);
/*****************************************************************
Write Sam Number

writes the default SAM number in the EEPROM for memory

INPUTS
	N_SAM : SAM number

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCSC_WriteConfigEeprom(BYTE pIndex, BYTE pValue);
/*****************************************************************
Writes in the EEPROM configuration

INPUTS
	pIndex			:	Index (1 byte)
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

	pValue			:	Value (1 byte)

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCSC_ReadConfigEeprom(BYTE pIndex);
/*****************************************************************
Writes in the EEPROM configuration

INPUTS
	pIndex			:	Index (1 byte)
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

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCSC_SelectSAM(BYTE N_SAM,BYTE Type);
/*****************************************************************
Select the Current SAM
*****************************************************************/


/****************************************************************/
void iCSC_ResetSAM(void);
/*****************************************************************
Initialization of the SAM module
*****************************************************************/

/****************************************************************/
void iCSC_ResetSAMExt(BYTE SamNum, BYTE SelectINN, BYTE SelectISO);
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

*****************************************************************/

/****************************************************************/
void iCSC_SendToSAM(BYTE *Data,BYTE DataLen);
/*****************************************************************
Send directly the Data to the SAM module

INPUTS
  Data       : Data to send
  DataLen    : The size of data to send
*****************************************************************/

/****************************************************************/
void iCSC_SendToSAMExt(BYTE pNumSAM, DWORD pLgBufIN, BYTE* pBufIN, BYTE pDirection);
/*****************************************************************
Sends an ISO command to the SAM, and returns the answer.


INPUTS
	pNumSAM								Sam Number 
											$00, $01, $02, $03, $04 as defined in "Reset Sam" cmd
	pLgBufIN								ISO command length
	pBufIN								the ISO Command to send to the SAM
	pDirection							Direction
											$01 : In
											$02 : Out
											$03 : In - Out

******************************************************************/

/****************************************************************/
void iCSC_ISOCommandContact(BYTE* BufIN,BYTE LnIN,BYTE Case);
/*****************************************************************
sends ISO command to the usually selected slot in the selected case
(IN, OUT, IN and OUT)

INPUTS
  BufIn      : Data to send
  LnIN	     : The size of data to send
  Case		 : APDU case :	01 : IN
							02 : OUT
							03 : IN and OUT
*****************************************************************/


/****************************************************************/
void iCSC_Switch_Led_Buzzer(ulong Param);
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
  
*****************************************************************/



/*****************************************************************
******************************************************************
CD97 Command ( Class 3 CSC orders )
******************************************************************
*****************************************************************/



/****************************************************************/
void iCD97_AppendRecord(BYTE AccMode,BYTE SID,BYTE *Data,
													BYTE DataLen);
/*****************************************************************
CD97 Command
Add a record to a circular EF

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		: SID Number ( CD97_SID_RT_JOURNAL, ...)
  Data      : Data to write
  DataLen   : The size of data to write
*****************************************************************/



/****************************************************************/
void iCD97_ChangeKey(BYTE KeyIndex,BYTE NewVersion);
/*****************************************************************
CD97 Command
Key modification

INPUTS
  KeyIndex  : Index of the key ( 0x01 - 0x03 )
  NewVersion: New version of the key ( <> 0x00 )
*****************************************************************/

/****************************************************************/
void iCD97_ChangeKeyExt(BYTE KeyIndex, BYTE NewKeyVersion, BYTE TypeCmd, 
						BYTE KeyIndexEncipher, BYTE ALGTag, BYTE ALGSam, BYTE NewKeyIndex);
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

*****************************************************************/


/****************************************************************/
void iCD97_ChangePIN(BYTE* OldPIN,BYTE* NewPIN);
/*****************************************************************
CD97 Command
PIN modification

INPUTS
  OldPIN	: Old PIN code ( 4 characters )
  NewPIN    : New PIN code ( 4 characters )
*****************************************************************/

/****************************************************************/
void iCD97_ChangePINExt(BYTE KeyNum, LPBYTE OldPIN, LPBYTE NewPIN, BYTE TypeCmd,
						BYTE KeyNumKIF, BYTE KVC, BYTE ALG, BYTE SamNum);
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

*****************************************************************/


/****************************************************************/
void iCD97_Decrease(BYTE AccMode,BYTE SID,ulong Value);
/*****************************************************************
CD97 Command
Decrease a counter file value

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		: Small ID Number ( CD97_SID_RT_JOURNAL, ...)
  Value		: Value decreased
*****************************************************************/



/****************************************************************/
void iCD97_Increase(BYTE AccMode,BYTE SID,ulong Value);
/*****************************************************************
CD97 Command
Increase a counter file value

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		: Small ID Number ( CD97_SID_RT_JOURNAL, ...)
  Value		: Value increased
*****************************************************************/



/****************************************************************/
void iCD97_Invalidate(BYTE AccMode);
/*****************************************************************
CD97 Command
Invalidate the current DF

INPUTS
  AccMode   : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

*****************************************************************/



/****************************************************************/
void iCD97_Rehabilitate(BYTE AccMode);
/*****************************************************************
CD97 Command
Rehabilitate the current DF

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

*****************************************************************/



/****************************************************************/
void iCD97_ReadRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
													BYTE DataLen);
/*****************************************************************
CD97 Command
Read a record from linear or circular file

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		: Small ID Number ( CD97_SID_RT_JOURNAL, ...)
  NuRec		: Record number
  DataLen   : Number of bytes to be read ( record length )

*****************************************************************/



/****************************************************************/
void iCD97_SelectFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen);
/*****************************************************************
CD97 Command
EF or DF select file

INPUTS
  SelectMode: Select Mode :
					CD97_SEL_MF	( Select the Master file )
					CD97_SEL_CURENT_EF ( Select the curent EF ID )
					CD97_SEL_PATH ( the path from MF ( exclude ) )

  IdPath    : ID number or path from MF ( exclude )
  IdPathLen : IdPath length

*****************************************************************/



/****************************************************************/
void iCD97_StatusFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen);
/*****************************************************************
CD97 Command
Same as iCD97_SelectFile but only give the file status without
select the file

INPUTS
  SelectMode: Select Mode :
					CD97_SEL_MF	( Select the Master file )
					CD97_SEL_CURENT_EF ( Select the curent EF ID )
					CD97_SEL_PATH ( the path from MF ( exclude ) )

  IdPath    : ID number or path from MF ( exclude )
  IdPathLen : IdPath length

*****************************************************************/



/****************************************************************/
void iCD97_UpdateRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE *Data,BYTE DataLen);
/*****************************************************************
CD97 Command
Erase and write a record to a EF

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		: SID Number ( CD97_SID_RT_JOURNAL, ...)
  NuRec		: Record number
  Data      : Data to write
  DataLen   : The size of data to write

*****************************************************************/



/****************************************************************/
void iCD97_WriteRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE *Data,BYTE DataLen);
/*****************************************************************
CD97 Command
Write a record to a EF

INPUTS
  AccMode	: Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		: SID Number ( CD97_SID_RT_JOURNAL, ...)
  NuRec		: Record number
  Data      : Data to write
  DataLen   : The size of data to write

*****************************************************************/



/****************************************************************/
void iCD97_VerifyPIN(BYTE* PIN);
/*****************************************************************
CD97 Command
PIN verification

INPUTS
	PIN				 : PIN code ( 4 characters )

*****************************************************************/

/****************************************************************/
void iCD97_VerifyPINExt(BYTE pMode, LPBYTE pPIN, BYTE pTypeCmd, BYTE pKeyNumKIF, BYTE pKVC, BYTE pSamNum);
/*****************************************************************
PIN verification

INPUTS
	pMode		: Mode
					$00 : consultation of counter of number of incorrect presentations		
					$01 : presentation of PIN
					$02 : presentation of PIN in transparent mode for contact communication
	pPIN			: PIN code (4 bytes)
	pTypeCmd		: Type Cmd
					$00 : short command (compatibility with the former one)
					$01 : long command
	pKeyNumKIF	: SAM key number to use Or KIF of the key.
	pKVC			: $00 if NKEY passed in the previous parameter or KVC of the Key
	pSamNum		: SAM number 
					$00 :	default SAM,
					$01, $02, $03 or $04 : logical number of the wanted SAM number

*****************************************************************/


/****************************************************************/
void iCD97_Purchase(BYTE Type,BYTE* DataLog,BYTE* Disp);
/*****************************************************************
CD97 Command
Purchase with the Electronic Purse ( EP )

INPUTS
  Type		: Purchase Type :
					- Purchase without display
					- Purchase with display
  DataLog   : EP Log record ( 7 bytes )
  Disp		: Display Message

*****************************************************************/



/****************************************************************/
void iCD97_GetEPStatus(BYTE Type);
/*****************************************************************
CD97 Command
Purchase with the Electronic Purse ( EP )

INPUTS
  Type		: Transaction Type :
					- Loading Transaction   ( 0x00 )
					- Purchase Transaction  ( 0x01 )
					- Purchase cancellation ( 0x02 )

*****************************************************************/



/****************************************************************/
void iCD97_ReloadEP(BYTE* ChargLog1,BYTE* ChargLog2);
/*****************************************************************
CD97 Command
Reload Electronic Purse

INPUTS
  ChargLog1	: Loading Log record ( 5 characters )
			  ( Date, Money batch, Equipment type )

  ChargLog2	: Loading Log record, offset [0x08..0x13]
			  ( 5 characters ) ( Amount, Time )

*****************************************************************/



/****************************************************************/
void iCD97_CancelPurchase(BYTE Type,BYTE* DataLog,BYTE* Disp);
/*****************************************************************
CD97 Command
Cancel Purchase with the Electronic Purse ( EP )

INPUTS
  Type		: Purchase Type :
					- Purchase without display ( 0x00 )
					- Purchase with display	( 0x01 )
  DataLog	: EP Log record ( 7 bytes )
  Disp		: Display Message

*****************************************************************/



/****************************************************************/
void iCD97_OpenSecuredSession(BYTE Type,BYTE SID,BYTE NREC);
/*****************************************************************
CD97 Command
Open the Secured Session


INPUTS
	Type	: Operation type
					- Personnalization  ( 0x00 )
					- Reloading ( 0x01 )
	SID		: SID Number ( CD97_SID_RT_JOURNAL, ...)
	NREC	: Record number

*****************************************************************/

/****************************************************************/
void iCD97_OpenSecuredSessionExt(BYTE pType, BYTE pSID, BYTE pRecNum, BYTE pTypeCmd, BYTE pKEYNumKIF, BYTE pKVC, BYTE pMode);
/*****************************************************************
Open the secured session

INPUTS
	pType		: Operation Type
					- Personnalization (0x00)
					- Reloading        (0x01)
					- Validation       (0x02)
	pSID		: Short ID Number ( ex. : CD97_SID_RT_JOURNAL, ...)
	pRecNum		: Record number
	pTypeCmd	: Type Cmd
					$00 : short command (compatibility with the former one for CD97 and GTML)
					$01 : long command
	pKEYNumKIF	: Number of Key which use in the SAM (in future KIF)
	pKVC		: Reserved for KVC
	pMode		: Mode of operation 
					$00 : simple mode 
					$01 : extended mode

*****************************************************************/

/****************************************************************/
void iCD97_CloseSecuredSession(void);
/*****************************************************************
Close the Secured Session
*****************************************************************/

/****************************************************************/
void iCD97_CloseSecuredSessionExt(BYTE pTypeCmd, BYTE pTimeOut);
/*****************************************************************
Close the secured session

INPUT
	pTypeCmd  : Type Cmd
				$00 : session will be ratified at the reception of the following command
				$80 : session is ratified immediately (except for CD97 and GTML)
				$4A : switches OFF the field if the card doesn’t answer
	pTimeOut	 : if TYPE=$4A 

*****************************************************************/

/****************************************************************/
void iCD97_AbortSecuredSession(void);
/*****************************************************************
Abort the Secured Session
*****************************************************************/

/****************************************************************/
void iCD97_SelectISOApplication(BYTE pSelectOption, BYTE pLg, LPBYTE pData);
/*****************************************************************
Select application using Select File ISO command

INPUTS
	pSelectOption :	Select Option (1 byte)
					00 : first application or select by name if LNG <> 0.
					01 : select last application (LNG should be 0)
					02 : select next application (LNG should be 0)
					03 : select previoust application (LNG should be 0)

	pLg			 :	length of data "n" (1 byte)
					0 if Select Option <> 0, otherwise <= 16
	pData		 : Application Name (n bytes)

*****************************************************************/


/****************************************************************/
void iCD97_ToGTML(void);
/*****************************************************************
Change the class for a GTML card
*****************************************************************/


/*****************************************************************
Variable Mapping Card : Generic Command ( Class 5 CSC orders )
*****************************************************************/

/****************************************************************/
void iGEN_AppendRecord(BYTE AccMode,BYTE SID,ulong LID,
									 BYTE NKEY,BYTE RUF,
									 BYTE *Data,BYTE DataLen);
/*****************************************************************
Generic Command
Add a record to a circular EF

INPUTS
  AccMode	 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
  SID		 : Short ID ( CD97_SID_RT_JOURNAL, ...)
  LID		 : Long ID
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC
  Data       : Data to write
  DataLen    : The size of data to write

*****************************************************************/

/****************************************************************/
void iChangeKey(BYTE pKeyIndex, BYTE pKeyIndexEncipher, BYTE pNewKeyVersion, 
				BYTE pALGTag, BYTE pALGSam, BYTE pNewKeyIndex);
/*****************************************************************
Change the key / Personnalization

INPUTS
	pKeyIndex			: Index of the key ( 01 - 03 )
	pKeyIndexEncipher	: Index of the key to encipher the transfer
	pNewVersion			: New version of the key ( <> 0 )
	pALGTag				: Algo key card to recopy
	pALGSam				: Algo of the Sam used
	pNewKeyIndex			: index of the new key in the card in the DF

*****************************************************************/

/****************************************************************/
void iGEN_ChangePIN(BYTE* OldPIN,BYTE* NewPIN,
								  BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
PIN modification

INPUTS
  OldPIN	 : Old PIN code ( 4 characters )
  NewPIN	 : New PIN code ( 4 characters )
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/



/****************************************************************/
void iGEN_Decrease(BYTE AccMode,BYTE SID,ulong LID,
								 BYTE ICount,ulong Value,
								 BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Decrease a counter file value

INPUTS
  AccMode	 : Card Access Mode ( ACCESS_MODE_DEFAULT, ...)
  SID		 : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  LID		 : Long ID
  Value		 : Value decreased
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/



/****************************************************************/
void iGEN_Increase(BYTE AccMode,BYTE SID,ulong LID,
								 BYTE ICount,ulong Value,
								 BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Increase a counter file value

INPUTS
  AccMode	 : Card Access Mode ( ACCESS_MODE_DEFAULT, ...)
  SID		 : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  LID		 : Long ID
  Value		 : Value decreased
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/

/****************************************************************/
void iGEN_DecreaseLG(BYTE pAccMode,BYTE pSID,WORD pLID,
					BYTE pICount,LPBYTE pValue,
					BYTE pNKEY,BYTE pRUF);
/*****************************************************************
It is a command for CD97 card only.
Decreases the value contained in a counter file and writes the 5 free data.
Records the associated data.

INPUTS
  pAccMode	 : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  pSID		 : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  pLID		 : Long ID
  pICount	 : Index of the Counter in the file (SID)
  pValue		 : Value decreased
  pNKEY		 : Number of Key which use in the SAM (in future KIF)
  pRUF		 : Reserved for KVC

*****************************************************************/

/****************************************************************/
void iGEN_IncreaseLG(BYTE pAccMode,BYTE pSID,WORD pLID,
					BYTE pICount,LPBYTE pValue,
					BYTE pNKEY,BYTE pRUF);
/*****************************************************************
It is a command for CD97 card only.
Decreases the value contained in a counter file and writes the 5 free data.
Records the associated data.

INPUTS
  pAccMode	 : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  pSID		 : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  pLID		 : Long ID
  pICount	 : Index of the Counter in the file (SID)
  pValue	 : Value increased
  pNKEY		 : Number of Key which use in the SAM (in future KIF)
  pRUF		 : Reserved for KVC

*****************************************************************/


/****************************************************************/
void iGEN_Invalidate(BYTE AccMode,ulong LID,BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Invalidate the current DF

INPUTS
  AccMode	 : Card Access Mode ( GEN_ACCESS_MODE_PROTECTED, ...)
  LID		 : Long ID
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/


/****************************************************************/
void iGEN_Rehabilitate(BYTE AccMode,ulong LID,BYTE NKEY,BYTE RUF);
/*****************************************************************
CD97 Command
Rehabilitate the current DF

INPUTS
INPUTS
  AccMode	 : Card Access Mode ( GEN_ACCESS_MODE_PROTECTED, ...)
  LID		 : Long ID
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/



/****************************************************************/
void iGEN_ReadRecord(BYTE AccMode,BYTE SID,BYTE NuRec,BYTE DataLen,
											 ulong LID,BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Read a record from linear or circular file

INPUTS
  AccMode	: Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID		: Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NuRec		: Record number
  DataLen	: Number of bytes to be read ( record length )
  LID		: Long ID
  NKEY		: Number of Key which use in the SAM (in future KIF)
  RUF		: Reserved for KVC

*****************************************************************/



/****************************************************************/
void iGEN_SelectFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen);
/*****************************************************************
Generic Command
EF or DF select file

INPUTS
  SelectMode : Select Mode :
					GEN_SEL_MF	( Select the Master file )
					GEN_SEL_CURENT_EF ( Select the curent EF ID )
					GEN_SEL_PATH ( the path from MF ( exclude ) )

  IdPath     : ID number or path from MF ( exclude )
  IdPathLen  : IdPath length

*****************************************************************/



/****************************************************************/
void iGEN_StatusFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen);
/*****************************************************************
Generic Command
Same as iCD97_SelectFile but only give the file status without
select the file

INPUTS
  SelectMode : Select Mode :
					GEN_SEL_MF	( Select the Master file )
					GEN_SEL_CURENT_EF ( Select the curent EF ID )
					GEN_SEL_PATH ( the path from MF ( exclude ) )

  IdPath     : ID number or path from MF ( exclude )
  IdPathLen  : IdPath length

*****************************************************************/



/****************************************************************/
void iGEN_UpdateRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
									 BYTE *Data,BYTE DataLen,
									 ulong LID,BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Erase and write a record to a EF

INPUTS
  AccMode	: Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID		: SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NuRec		: Record number
  Data		: Data to write
  DataLen	: The size of data to write
  LID		: Long ID
  NKEY		: Number of Key which use in the SAM (in future KIF)
  RUF		: Reserved for KVC


*****************************************************************/


/****************************************************************/
void iGEN_WriteRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
									BYTE *Data,BYTE DataLen,
									ulong LID,BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Write a record to a EF

INPUTS
  AccMode	: Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID		: SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NuRec		: Record number
  Data		: Data to write
  DataLen	: The size of data to write
  LID		: Long ID
  NKEY		: Number of Key which use in the SAM (in future KIF)
  RUF		: Reserved for KVC

*****************************************************************/



/****************************************************************/
void iGEN_VerifyPIN(BYTE* PIN,BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
PIN verification

INPUTS
  PIN	  : PIN code ( 4 characters )
  NKEY	  : Number of Key which use in the SAM (in future KIF)
			If NKEY=0 => presentation in clear mode
  RUF	  : Reserved for KVC

*****************************************************************/

/****************************************************************/
void iGEN_PINStatus();
/*****************************************************************
Generic Command
checks PIN presentation status

INPUTS
	none

*****************************************************************/


/****************************************************************/
void iGEN_Purchase(BYTE Type,BYTE* DataLog,BYTE* Disp);
/*****************************************************************
Generic Command
Purchase with the Electronic Purse ( EP )

INPUTS
	Type	: Purchase Type :
					- Purchase without display
					- Purchase with display
	DataLog : EP Log record ( 7 bytes )
	Disp	: Display Message

*****************************************************************/



/****************************************************************/
void iGEN_GetEPStatus(BYTE Type,BYTE NKEY,BYTE RUF);
/*****************************************************************
Generic Command
Purchase with the Electronic Purse ( EP )

INPUTS
  Type		: Transaction Type :
					- Loading Transaction   ( 0x00 )
					- Purchase Transaction  ( 0x01 )
					- Purchase cancellation ( 0x02 )
  NKEY		: Number of Key which use in the SAM (in future KIF)
  RUF		: Reserved for KVC

*****************************************************************/



/****************************************************************/
void iGEN_ReloadEP(BYTE* ChargLog1,BYTE* ChargLog2);
/*****************************************************************
Generic Command
Reload Electronic Purse

INPUTS
  ChargLog1 : Loading Log record ( 5 characters )
			  ( Date, Money batch, Equipment type )

  ChargLog2 : Loading Log record, offset [0x08..0x13]
		      ( 5 characters ) ( Amount, Time )

*****************************************************************/



/****************************************************************/
void iGEN_CancelPurchase(BYTE Type,BYTE* DataLog,BYTE* Disp);
/*****************************************************************
Generic Command
Cancel Purchase with the Electronic Purse ( EP )

INPUTS
  Type		: Purchase Type :
				- Purchase without display ( 0x00 )
				- Purchase with display	( 0x01 )
  DataLog	: EP Log record ( 7 bytes )
  Disp		: Display Message

*****************************************************************/



/****************************************************************/
void iGEN_OpenSecuredSession(BYTE Type,BYTE SID,BYTE NREC,
							 BYTE NKEY,BYTE RUF,BYTE Mode);
/*****************************************************************
Generic Command
Open the Secured Session


INPUTS
  Type		: Operation type
				- Personnalization  ( 0x00 )
				- Reloading ( 0x01 )
  SID		: SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NREC		: Record number
  NKEY		: Number of Key which use in the SAM (in future KIF)
  RUF		: Reserved for KVC
  MODE		: Working mode :
				- Simple  ( 0x00 )
				- Extended ( 0x01 )

*****************************************************************/


/****************************************************************/
void iGEN_CloseSecuredSession(void);
/*****************************************************************
Close the Secured Session
*****************************************************************/


/****************************************************************/
void iGEN_AbortSecuredSession();
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-
*****************************************************************/

/****************************************************************/
void iGEN_Lock_Unlock(BYTE Type);
/*****************************************************************
Generic Command
Lock Unlock the card


INPUTS
  Type	 : Operation type
				- Lock the card ( 0x00 )
				- Unlock the card ( 0x01 )
	
*****************************************************************/

/****************************************************************/
void iGEN_MultiDecrease(BYTE AccMode,BYTE SID,ulong LID,BYTE NKEY,BYTE RUF,
						BYTE NbCnt,BYTE *Data);
/*****************************************************************
Generic Command
Multiple decrease of a counter

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID	  : SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC
  NbCnt	  : Number of counters to decrease
  Data    : Values to decrease (Lng=NumberCpt*4).
			NumberCpt*Bloc :
				- Byte1		: Number of counter
				- Byte2-4	: Value to decrease


*****************************************************************/

/****************************************************************/
void iGEN_MultiIncrease(BYTE AccMode,BYTE SID,ulong LID,BYTE NKEY,BYTE RUF,
						BYTE NbCnt,BYTE *Data);
/*****************************************************************
Generic Command
Multiple increase of a counter

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID	  : SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC
  NbCnt	  : Number of counters to increase
  Data    : Values to increase (Lng=NumberCpt*4).
			NumberCpt*Bloc :
				- Byte1		: Number of counter
				- Byte2-4	: Value to increase


*****************************************************************/

/****************************************************************/
void iCTx_Active(void);
/*****************************************************************
Read CTx

INPUTS
	Nothing
*****************************************************************/


void iCTx_Read(BYTE ADD, BYTE NB);
/*****************************************************************
Read CTx

INPUTS
	ADD		: adress of the first read (0 ... 31)
	NB		: Number of bytes to be read (from 1 up to 32)


*****************************************************************/

/****************************************************************/
void iCTx_Update(BYTE ADD, BYTE NB, BYTE *Data, BYTE *DataInCTS);
/*****************************************************************
Update CTx

INPUTS
	ADD			: adress of the first byte to write (0 ... 31)
	NB			: Number of bytes to be written (from 1 up to 32)
	Data		: Data to write
	DataInCTS	: Data already read and store in CTS application

*****************************************************************/

/****************************************************************/
void iCTx_Release(BYTE Param);
/*****************************************************************
Release CTx

INPUTS
	Param
*****************************************************************/

/****************************************************************/
void iGEN_CheckCertificate(BYTE KeyType, BYTE Param, BYTE LngBuffer, BYTE *Buffer,
							BYTE LngCertificat, BYTE *Certificat);
/*****************************************************************
Check Certificate

INPUTS
	KeyType
	LngBuffer
	Buffer
	LngCertificat
	Certificat
*****************************************************************/

/****************************************************************/
void iGEN_GiveCertificate(BYTE KeyType, BYTE Param, BYTE LngBuffer, BYTE *Buffer,
							BYTE LngCertificat);
/*****************************************************************
Give Certificate

INPUTS
	KeyType
	Param	(RFU)
	LngBuffer
	Buffer
	LngCertificat
*****************************************************************/


/****************************************************************/
void iCSC_ChangeCSCSpeed(BYTE RS232Speed,BYTE RS485Speed, BYTE TTLSpeed);
/*****************************************************************
Format the change speed command 

INPUTS
  RS232Speed :	// RS232 Divider for Baud rate
  RS485Speed :	// RS485 Divider for Baud rate
  TTLSpeed :	// serial TTL Divider for Baud rate
  
*****************************************************************/

/****************************************************************/
BYTE iCSC_ConvertBaudRateInDivider(ulong BaudRate);
/*****************************************************************
convert Host-CSC communication BaudRate In Divider for ST9 device

INPUTS
  The Baud rate to be converted.
OUTPUTS
  None
RETURN
  0 if the input value isnot allowed
  The divider value 
*****************************************************************/

/*****************************************************************/
void iCSC_SelectCID(BYTE CID);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  CID :	Index from 1 to 15 of the ISO14443 Card communication channel
OUTPUTS
	None 
  
*****************************************************************/

/*****************************************************************/
void iCSC_SelectDIV(BYTE Slot, BYTE Prot, BYTE *DIV);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Slot :	Slot of the SAM
  Prot :	0 for Innovatron, 1 for ISO7816
  DIV :		4 bytes serial number used for alg diversification
OUTPUTS
	None 
  
*****************************************************************/

/*****************************************************************/
void iCSC_EHP_PARAMS(BYTE MaxNbCard, BYTE Req, BYTE NbSlot, BYTE AFI, BYTE AutoSelDiv);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Slot :	Slot of the SAM
  Prot :	0 for Innovatron, 1 for ISO7816
  DIV :		4 bytes serial number used for alg diversification
OUTPUTS
	None 
  
*****************************************************************/

/*****************************************************************/
void iCSC_EHP_PARAMS_EXT (BYTE pMaxNbCard, BYTE pReq, BYTE pNbSlot, BYTE pAFI, BYTE pAutoSelDiv, 
							BYTE pDeselect, BYTE pSelectAppli, BYTE pLg, LPBYTE pData, 
							WORD pFelicaAFI, BYTE pFelicaNbSlot);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	pMaxNbCard		: Max number of card to look for (1 byte)
	pReq 			: 0 for ReqB / 1 for WupB (1 byte)
	pNbSlot 		: 0 for not the time slot method (1 byte)
	pAFI  			: 0 for all ( default value ) (1 byte)
	pAutoSelDiv		: 1 if yes ( default value ) (1 byte)
	pDeselect		: 0 switch field off / 1 real deselection of the found cards (1 byte)
	pSelectAppli	: $000xxxx1 send select appli to card after detection (1 byte)
					  $000xxx1x force to $00 (instead of $94) the select appli "CLA" field
					  $000x1xxx add selected appli name in the EnterHuntPhase answer
    pLg				: Optional data Length "n" (1 byte)
	pData			: Optional name of the appli to select( default value is "1TIC" ) (n byte)
	pFelicaAFI		: Card function identifier ( default is all cards = $FFFF ) (2 byte)
	pFelicaNbSlot	: Slot Number for Felica Anticollision ( default value = 3 ) (1 byte)

OUTPUTS
	None 
  
*****************************************************************/


/*****************************************************************/
void iMIFARE_LoadReaderKeyIndex(BYTE KeyIndex, BYTE *KeyVal);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  KeyIndex :	Index from 0 to 31 of the key to load in the Reader
  KeyVal :		Value of the key (6 bytes LSB First)
OUTPUTS
	None 
  
*****************************************************************/

/*****************************************************************/
void iMIFARE_ChangeKey(BYTE InitialKeyAorB, BYTE NumSector, BYTE InitialKeyIndex, 
			BYTE FinalKeyAorB, BYTE *NewKeyA, BYTE *NewAccessBits, BYTE *NewKeyB);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	InitialKeyAorB	:	Choice of the key needed for authentication before key change operation
	NumSector		:	Sector on which the ChangeKey operation need to be performed
	InitialKeyIndex :	Index from 0 to 31 of the Reader key used for initial authentication
	FinalKeyAorB	:	Choice of the key needed for authentication after key change operation  
	NewKeyA			:	(6 Bytes) New value for the A Key (Be Carefull it must be coded MSB first)
	NewAccessBits	:	(4 Bytes) New value for Access bits area
	NewKeyB			:	(6 Bytes) New value for the B Key (Be Carefull it must be coded MSB first) 
  
OUTPUTS
	None 

*****************************************************************/

/****************************************************************/
void iMIFARE_Select(BYTE* SerialNumber, BYTE SerialNumberLn);
/*****************************************************************
MIFARE Command
Selects a mifare card with its unique serial number

INPUTS
	Serial Number : buffer containing the serial number of the card to detect.
	SerialNumberLn:	length of the serial number

*****************************************************************/

/*****************************************************************/
void iMIFARE_Detect();
/*****************************************************************
Detect the Mifare Card present in the antenna field  

INPUTS
	-  

OUTPUTS
	None 

*****************************************************************/

/*****************************************************************/
void iMIFARE_Authenticate(BYTE NumSector, BYTE KeyAorB, BYTE KeyIndex);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	NumSector		:	Sector to authenticate
	KeyAorB			:	Choice of the key needed for authentication  
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	None 

*****************************************************************/

/*****************************************************************/
void iMIFARE_Halt(void);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	None  
OUTPUTS
	None 

*****************************************************************/

/*****************************************************************/
void iMIFARE_ReadBlock(BYTE NumBlock);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	NumBlock		:	Block number from 0 to 63 
OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMIFARE_ReadSector( BYTE NumSector, BYTE KeyAorB, BYTE KeyIndex);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	NumSector		:	Sector to authenticate and read
	KeyAorB			:	Choice of the key needed for authentication  
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	none

*****************************************************************/


/*****************************************************************/
void iMIFARE_WriteBlock(BYTE NumBlock, BYTE *DataToWrite);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	NumBlock		:	Block number from 0 to 63 
	DataToWrite		:	(16 bytes) Data to write in the block (the whole block is written) 
  
OUTPUTS
	none

*****************************************************************/


/*****************************************************************/
void iMIFARE_DecrementValue(BYTE NumBlock, BYTE *Substract);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	NumBlock		:	Block number from 0 to 63 (must be previously configured as a value block)
	Substract		:	(4 bytes) value to substract to the counter 
  
OUTPUTS
	none

*****************************************************************/


/*****************************************************************/
void iMIFARE_IncrementValue(BYTE NumBlock, BYTE *Addition);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	NumBlock		:	Block number from 0 to 63 (must be previously configured as a value block)
	Addition		:	(4 bytes) value to Add to the counter 
  
OUTPUTS
	none

*****************************************************************/


/*****************************************************************/
void iMIFARE_BackUpRestoreValue(BYTE Origine, BYTE Destination);
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
	Origine			:	Block number from 0 to 63 (must be previously configured as a value block)
	Destination		:	Block number from 0 to 63 (must be previously configured as a value block)
  
OUTPUTS
	none

*****************************************************************/

/*****************************************************************/
void iMIFARE_ReadMultipleBlock(BYTE pBlockNum, BYTE pNumBlock);
/*****************************************************************
Read Multiple block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	pBlockNum		:	Block number from 0 to 255 
	pNumBlock		:	Number of Block "n"

OUTPUTS
	None 

*****************************************************************/

/*****************************************************************/
void iMIFARE_SimpleWriteBlock(BYTE pBlockNum, LPBYTE pDataToWrite);
/*****************************************************************
Writes an authenticated block

INPUTS
	pBlockNum			:	Block number from 0 to 255  (1 byte)
	pDataToWrite		:	Data to Write in the selected authenticated block (16 bytes)
  
OUTPUTS
	None 

*****************************************************************/

/*****************************************************************/
void iMIFARE_ReadSectorData(BYTE KeyAorB, BYTE NumSector, BYTE KeyIndex);
/*****************************************************************
Read a the data blocks Sector of the PICC

INPUTS
	KeyAorB			:	Choice of the key needed for authentication  
	NumSector		:	Sector to authenticate and read
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	none

*****************************************************************/

/*****************************************************************/
void iMIFARE_WriteSectorData(BYTE pKeyAorB, BYTE pNumSector, BYTE pKeyIndex, LPBYTE pDataToWrite, BYTE pCardType);
/*****************************************************************
Read a the data blocks Sector of the PICC

INPUTS
	pKeyAorB		:	Choice of the key needed for authentication  
	pNumSector		:	Sector to authenticate and read
	pKeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
	pDataToWrite		:	Data to write in the Sector (the whole sector is written)  (48 byte)
  
OUTPUTS
	none

*****************************************************************/


/*****************************************************************/
void iMIFARE_SAMNXP_Authenticate(BYTE pNumKey, BYTE pVersionKey, BYTE pKeyAorB, 
								 BYTE pNumBlock, BYTE pLgDiversifier, BYTE pBlockDiversifier);
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
	None 

*****************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_ReAuthenticate(BYTE pNumKey, BYTE pVersionKey, BYTE pKeyAorB, 
								   BYTE pNumBlock, BYTE pLgDiversifier, BYTE pBlockDiversifier);
/*****************************************************************
Realise the Re-authenticate of block already authenticated

INPUTS
	pNumKey				:	Block to authenticate (1 byte)
	pVersionKey			:	Version Key (1 byte)
	pKeyAorB			:	PICC Key (1 byte)
	pNumBlock			:	Number Block (1 byte)
	pLgDiversifier		:	Length Diversifier (1 byte)
	pBlockDiversifier	:	Block Diversifier (1 byte)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_ReadBlock(BYTE pNumBlock);
/*****************************************************************
Read a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_WriteBlock(BYTE pNumBlock, BYTE *pDataToWrite);
/*****************************************************************
Write a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)
	pDataToWrite		:	Data to Write in block (16 bytes)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_ChangeKey(BYTE pNumKey, BYTE pVersionKeyA, BYTE pVersionKeyB, 
							  BYTE *pDefaultAccess, BYTE pNumBlock, BYTE pLgDiversifier, BYTE pBlockDiversifier);
/*****************************************************************
Change a MIFARE Key in the card

INPUTS
	pNumKey				:	Number Key (1 byte)
	pVersionKeyA		:	Version Key A (1 byte)
	pVersionKeyB		:	Version Key B (1 byte)
	pDefaultAccess		:	Default Access (4 bytes)
	pNumBlock			:	Number Block (1 byte)
	pLgDiversifier		:	Lenght Diversiifer (1 byte)
	pBlockDiversifier	:	Block Diversifier (1 byte)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_Increment(BYTE pNumBlock, BYTE *pIncrement);
/*****************************************************************
Increment a Value block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)
	pIncrement			:	Increment Value to add (4 bytes)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_Decrement(BYTE pNumBlock, BYTE *pDecrement);
/*****************************************************************
Decrement a Value block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)
	pDecrement			:	Decrement Value to substract (4 bytes)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_BackUpValue(BYTE pSource, BYTE pDestination);
/*****************************************************************
Perform a copy of a value block to an other value block location.

INPUTS
	pSource					:	Number Block Source (1 byte)
	pDestination			:	Number Block Destination (1 byte)

OUTPUTS
	None 

******************************************************************/

/*****************************************************************/
void iMIFARE_SAMNXP_KillAuthentication();
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	None 

OUTPUTS
	None 

******************************************************************/


/*****************************************************************/
void iMFP_SL3_Authentication(BYTE pNumKey, BYTE pVersionKey, WORD pKeyBlockNum, 
							 BYTE pLgDiversifier, BYTE *pDiversifier);
/*****************************************************************
Realise the authentication of block

INPUTS
	pNumKey				:	Block to authenticate (1 byte)
	pVersionKey			:	Version Key (1 byte)
	pKeyBlockNum		:	Key Block Number (2 bytes)
	pLgDiversifier		:	Length Diversifier (1 byte)
	pDiversifier		:	Diversifier data (0 to 31 byte)

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMFP_SL3_ResetAuthentication(BYTE pMode);
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	pMode				:	Reset Mode (1 bytes)

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMFP_SL3_ReadBlock(BYTE pMode, WORD pBlockNum, BYTE pNumBlock);
/*****************************************************************
Read a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pMode				:	Read Mode (1 bytes)
	pBlockNum			:	Block Number to start reading (2 bytes)
	pNumBlock			:	Number of block to read (1 bytes)

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMFP_SL3_WriteBlock(BYTE pMode, WORD pBlockNum, BYTE pNumBlock, LPBYTE pDataToWrite);
/*****************************************************************
Write a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pMode				:	Read Mode (1 bytes)
	pBlockNum			:	Block Number to start reading (2 bytes)
	pNumBlock			:	Number of block to read (1 bytes)
	pDataToWrite		:	Data to Write in block (16 - 48 bytes)

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMFP_SL3_ChangeKey(BYTE pSamKeyNum, BYTE pSamKeyVersion, WORD pKeyBlockNum, 
						BYTE pLgDiversifier, LPBYTE pDiversifier);
/*****************************************************************
Change a MIFARE Key in the card

INPUTS
	pSamKeyNum			:	Sam Key Number (1 bytes)
	pSamKeyVersion		:	Sam Key Version (1 bytes)
	pKeyBlockNum		:	Key Block Number (2 bytes)
	pLgDiversifier		:	Length Diversifier (1 byte)
	pDiversifier		:	Diversifier data (0 to 31 byte)

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMFP_SL3_VirtualCardSupport(BYTE pSamKeyNumVCENC, BYTE pSamKeyVersionVCENC,  
								 BYTE pSamKeyNumVCMAC, BYTE pSamKeyVersionVCMAC, LPBYTE pIID);														
/*****************************************************************
Check Virtual Card is supported and retreive the UID

INPUTS
	pSamKeyNumVCENC		:	Sam Key Number for VC polling ENC (1 bytes)
	pSamKeyVersionVCENC	:	Sam Key Version for VC polling ENC (1 bytes)
	pSamKeyNumVCMAC		:	Sam Key Number for VC polling MAC (1 bytes)
	pSamKeyVersionVCMAC	:	Sam Key Version for VC polling MAC (1 bytes)
	pIID				:	Installation Identifier (16 byte)

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iMFP_SL3_DeselectVirtualCard();													
/*****************************************************************
Deselect the Virtual Card

INPUTS
	-

OUTPUTS
	None 

*****************************************************************/


/*****************************************************************/
void iDESFIRE_CreateApplication(LPBYTE pAppID, BYTE Opt, BYTE KeyNum);
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
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_DeleteApplication(LPBYTE pAppID);
/*****************************************************************
Deactivate application in the card

INPUTS
	pAppID			:	ID Number of the Appl in the card (3 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SelectApplication(LPBYTE pAppID);
/*****************************************************************
Select one Application for further access in the card

INPUTS
	pAppID			:	ID Number of the Appl in the card (3 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_FormatPICC();
/*****************************************************************
Format card File system

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetApplicationIDs(BYTE pNumID);
/*****************************************************************
Retreive the current application ID

INPUTS
	pNumID			:	Number of ID (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetVersion();
/*****************************************************************
Version of the card firmware

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetFreeMem();
/*****************************************************************
retrieve the size available on the card

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/****************************************************************/
void iDESFIRE_PrepareAuthentication (	BYTE AuthMode,
          								BYTE SAMKeyNumber,
          								BYTE SAMKeyVersion);
/*****************************************************************
Parameters  :
I	BYTE	AuthMode		Authentication parameters (see SAM AV2 specification).
I	BYTE	SAMKeyNumber	Key number in the SAM.
I	BYTE	SAMKeyVersion	Key version of the specified key in the SAM.
*****************************************************************/

/*****************************************************************/
void iDESFIRE_Authenticate(BYTE pKeyNum);
/*****************************************************************
Realise the authentication

INPUTS
	pKeyNum			:	Number of the access key which will be used for the authetication (1 byte)

OUTPUTS
	-

*****************************************************************/

void iDESFIRE_AuthenticateEV1( 	BYTE PICCKeyNumber,
								BYTE AuthMode,
								BYTE SAMKeyNumber,
								BYTE SAMKeyVersion,
								BYTE Type,
								BYTE LgDiversifier,
								BYTE *Diversifier);
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
*****************************************************************/

/*****************************************************************/
void iDESFIRE_CommitTransaction();
/*****************************************************************
Commits the transaction to end a transaction operation with changes

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_AbortTransaction();
/*****************************************************************
Aborts the current transaction to end a transaction operation with no changes

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_ChangeKey(	BYTE CurKeyNo,
							BYTE CurKeyV,
							BYTE NewKeyNo,
							BYTE NewKeyV,
							BYTE KeyCompMeth,
							BYTE Cfg,
							BYTE Algo,
							BYTE LgDiversifier,
							BYTE *Diversifier);
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
*****************************************************************/

/*****************************************************************/
void iDESFIRE_ChangeKeySetting(BYTE pKeySetting);
/*****************************************************************
Changes the key settings information  

INPUTS
	pKeySetting		:	new master key settings either for the currently selected application or for the whole PICC  (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetKeySetting();
/*****************************************************************
Gets the configuration information on the PIDD and the application master key configuration settings.

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetKeyVersion(BYTE pKeyNum);
/*****************************************************************
Gets Key Version.

INPUTS
	pKeyNum			:	Specify the number of the access key (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_ChangeFileSetting(BYTE pFileID, BYTE pCommEncrypted, BYTE pCommMode, BYTE pAccessRight);
/*****************************************************************
Changes the file configuration on the card

INPUTS
	pFileID			:	ID of the file whose communication mode and access rights settings shall be changed (1 byte)
	pCommEncrypted	:	Encrypt the communication (1 byte)
	pCommMode		:	new communication mode (1 byte)
	pAccessRight	:	specify the access right setting for this file (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_ClearRecordFile(BYTE pFileID);
/*****************************************************************
Clears the record files selected by the input param

INPUTS
	pFileID			:	ID of the file which shall be cleared (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_CreateBackUpDataFile(BYTE FileID, BYTE CommMode, WORD AccessRight, LPBYTE FileSize);
/*****************************************************************
Creation of a Backup Data File

INPUTS
	FileID			:	ID of the file for which the new Backup File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	FileSize		:	Size of the new Backup File in bytes (3 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_CreateCyclicRecordFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, 
									LPBYTE pRecordSize, LPBYTE pMaxNumRecord);
/*****************************************************************
Creation of a Cyclic Data File

INPUTS
	pFileID			:	ID of the file for which the new Linear record File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAccessRight		:	New File access rights settings (2 byte)
	pRecordSize		:	Size of the new linear File in bytes (3 byte)
	pMaxNumRecord	:	Number of the records for the new linear File (3 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_CreateLinearRecordFile(BYTE FileID, BYTE CommMode, WORD AccessRight, 
									 LPBYTE RecordSize, LPBYTE MaxNumRecord);
/*****************************************************************
Creation of a Linear Data File

INPUTS
	FileID			:	ID of the file for which the new Linear record File is to be created (1 byte)
	CommMode		:	File communication mode (1 byte)
	AccessRight		:	New File access rights settings (2 byte)
	RecordSize		:	Size of the new linear File in bytes (3 byte)
	MaxNumRecord	:	Number of the records for the new linear File (3 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_CreateStandardDataFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, LPBYTE pFileSize);
/*****************************************************************
Creation of a Standard Data File

INPUTS
	pFileID			:	ID of the file for which the new Linear record File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAccessRight	:	New File access rights settings (2 byte)
	pFileSize		:	Size of the new linear File in bytes (3 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_CreateValueFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, LPBYTE pLower, 
							LPBYTE pUpper, LPBYTE pInitial, BYTE pLimited);
/*****************************************************************
Creation of a Value File

INPUTS
	pFileID				:	ID of the file for which the new File is to be created (1 byte)
	pCommMode			:	File communication mode (1 byte)
	pAccessRight		:	New File access rights settings (2 byte)
	pLower				:	Min amount for the value file (4 byte)
	pUpper				:	Max amount for the value file (4 byte)
	pInitial			:	Amount with which the value file will be created (4 byte)
	pLimited			:	Limited credit command is enabled for the new value file (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_Credit(BYTE pFileID, BYTE pCommMode, LPBYTE pAmount);
/*****************************************************************
Credit a Value on a Value File

INPUTS
	pFileID			:	ID of the file for which the new File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAmount			:	Amount to be credited in the value file (4 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_Debit(BYTE pFileID, BYTE pCommMode, LPBYTE pAmount);
/*****************************************************************
Debit a Value on a Value File

INPUTS
	pFileID			:	ID of the file for which the new File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAmount			:	Amount to be credited in the value file (4 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_DeleteFile(BYTE pFileID);
/*****************************************************************
Delete a File 

INPUTS
	pFileID			:	ID of the file for which the new File is to be deleted (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetFileID(BYTE pMaxFileID);
/*****************************************************************
Get File ID for the current application 

INPUTS
	pMaxFileID		:	Max response expected  (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetFileSetting(BYTE pFileID);
/*****************************************************************
Get File Settings for the current application 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_GetValue(BYTE pFileID, BYTE pCommMode);
/*****************************************************************
Get File Settings for the current application 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	pCommMode		:	File communication mode (1 byte)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_LimitedCredit(BYTE pFileID, BYTE pCommMode, LPBYTE pAmount);
/*****************************************************************
Limited Credit 

INPUTS
	pFileID			:	ID of the file for which the credit is to increase (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAmount			:	Max Amount that can be added to the File value (4 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_ReadData(BYTE pFileID, BYTE pCommMode, WORD pFromOffset, WORD pNumByteToRead);
/*****************************************************************
Read Data standard File 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pFromOffset		:	Offset in the File (2 bytes)
	pNumByteToRead	:	Nb byte to read (2 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_WriteData(BYTE pFileID, BYTE pCommMode, WORD pFromOffset, WORD pNumByteToWrite, LPBYTE pDataToWrite);
/*****************************************************************
Write Data standard File 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pFromOffset		:	Offset in the File (2 bytes)
	pNumByteToWrite	:	Nb byte to write (2 bytes)
	pDataToWrite	:	Data write in the File (n bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_ReadRecord(BYTE pFileID, BYTE pCommMode, WORD pFromRecord, WORD pNumRecordToRead, WORD pRecordSize);
/*****************************************************************
Read Data Record File 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pFromRecord		:	Record number from which Data are read (2 bytes)
	pNumRecordToRead:	Number of record to read (2 bytes)
	pRecordSize		:	Record size (2 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_WriteRecord(BYTE pFileID, BYTE pCommMode, WORD pFromRecord, WORD pNumRecordToWrite, LPBYTE pDataToWrite);
/*****************************************************************
Write Data Record File 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pFromRecord		:	Record number from which Data are written (2 bytes)
	pNumRecordToWrite:	Number of record to write (2 bytes)
	pDataToWrite	:	Data To Write (n bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamGetVersion();
/*****************************************************************
Sam Firmware Info

INPUTS
	-

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamSelectApplication(LPBYTE pDirFileAID);
/*****************************************************************
Select an application in the SAM

INPUTS
	pDirFileAID:	Directory File AID (3 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamLoadInitVector(LPBYTE pInitVector);
/*****************************************************************
Load an init vector in the SAM for 3DES seeding

INPUTS
	pInitVector:	Crypto seed (8 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamGetKeyEntry(BYTE pKeyNum);
/*****************************************************************
Key entry Info

INPUTS
	KeyNum:	Key Entry Number (1 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamGetKucEntry(BYTE pRefKucNum);
/*****************************************************************
Key Usage Counter Info

INPUTS
	pRefKucNum:	Key Usage Counter Entry Reference Number (1 bytes)

OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamDisableCrypto(WORD pPROMAS);
/*****************************************************************
Disable the crypto of certain function on the SAM/PICC

INPUTS
	pPROMAS			:	Programming bit Mask (2 bytes)

OUTPUTS
	-

*****************************************************************/


/*****************************************************************/
void iSRX_Active();
/*****************************************************************
Activate and select a SR, SRI, SRT or SRIX ticket and send back the chip type and the 64-bit UID.

INPUTS
	-
	
OUTPUTS
	-

*****************************************************************/

/*****************************************************************/
void iSRX_ReadBlock(BYTE pBlockNum, BYTE pNumBlock);
/*****************************************************************
Read Blocks.

INPUTS
	pBlockNum			:	Block Number to start reading (1 bytes)
	pNumBlock			:	Number of block to read (1 bytes)

OUTPUTS
	-
*****************************************************************/

/*****************************************************************/
void iSRX_WriteBlock(BYTE pBlockNum, BYTE pNumBlock, LPBYTE pDataToWrite, BYTE pChipType);
/*****************************************************************
Read Blocks.

INPUTS
	pBlockNum			:	Block Number to start reading (1 bytes)
	pNumBlock			:	Number of block to read (1 bytes)
	pDataToWrite		:	Data to Write (n bytes)
	pChipType			:	Type Chip (1 bytes)

OUTPUTS
	-
*****************************************************************/

/*****************************************************************/
void iSRX_Release(BYTE pParam);
/*****************************************************************
Deactivate SRx ticket.

INPUTS
	Param				:	Param deactivation of the ticket (1 bytes)

OUTPUTS
	-	
*****************************************************************/

/*****************************************************************/
void iSRX_Read(WORD pAdd, BYTE pNumBytes);
/*****************************************************************
Read Blocks.

INPUTS
	pAdd				:	Address of the first reading -> LSB / MSB (2 bytes)
	pNumBytes			:	Number of bytes to read (1 bytes)

OUTPUTS
	-
*****************************************************************/

/*****************************************************************/
void iSRX_Write(WORD pAdd, BYTE pNumBytes, LPBYTE pDataToWrite);
/*****************************************************************
Read Blocks.

INPUTS
	pAdd				:	Address of the first reading -> LSB / MSB (2 bytes)
	pNumBytes			:	Number of bytes to read (1 bytes)
	DataToWrite			:	Data to Write

OUTPUTS
	-
*****************************************************************/


/****************************************************************/
void iCTX_512B_List(BYTE RFU);
/*****************************************************************
LIST CTX512B
Performs anticollision and answers serial numbers of all the chips
present in the antenna field

INPUTS
	RFU : default 0x00
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTX_512B_Select(BYTE* serialNumber);
/*****************************************************************
SELECT CTX512B
Selects a ticket with its serial number

INPUTS
	serialNumber : pointer to the buffer containing the serial
					number (2 bytes)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512B_Read(BYTE ADD, BYTE NB);
/*****************************************************************
READ CTX512B
Reads a number of bytes (NB) from a given address (ADD)

INPUTS
	ADD		: adress of the first byte (0 ... 63)
	NB		: Number of bytes to be read (from 1 up to 64)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512B_Update(BYTE ADD, BYTE NB, BYTE *data);
/*****************************************************************
UPDATE CTX512B
deletion if necessary, update then checking (reading bytes written)

INPUTS
	ADD			: adress of the first byte to write (0 ... 31)
	NB			: Number of bytes to be written (from 1 up to 64)
	data		: Data to write

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512B_Halt(BYTE Param);
/*****************************************************************
HALT CTX512B

INPUTS
	Param	0x00 : desactivates ticket using 'desactivate' instruction
			(others RFU)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTX_512X_List(BYTE RFU);
/*****************************************************************
LIST CTX512X
Performs anticollision and answers serial numbers of all the chips
present in the antenna field

INPUTS
	RFU	:	default=0x00, RFU
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTX_512X_Select(BYTE* serialNumber);
/*****************************************************************
SELECT CTX512X
Selects a CTx512B with its serial number

INPUTS
	serialNumber : pointer to the buffer containing the serial
					number (2 bytes)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512X_Read(BYTE ADD, BYTE NB);
/*****************************************************************
READ CTX512X
Reads a number of bytes (NB) from a given address (ADD)

INPUTS
	ADD		: adress of the first byte (0 ... 63)
	NB		: Number of bytes to be read (from 1 up to 64)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512X_Update(BYTE ADD, BYTE NB, BYTE *data);
/*****************************************************************
UPDATE CTX512X
deletion if necessary, update then checking (reading bytes written)

INPUTS
	ADD			: adress of the first byte to write (0 ... 31)
	NB			: Number of bytes to be written (from 1 up to 64)
	data		: Data to write

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512X_Halt(BYTE Param);
/*****************************************************************
HALT CTX512X

INPUTS
	Param	0x00 : desactivates ticket using 'desactivate' instruction
			(others RFU)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512X_Write(BYTE ADD, BYTE NB, BYTE *data);
/*****************************************************************
WRITE CTX512X
performs a write operation (sets all the bits at 0 to 1, but not the reverse)

INPUTS
	ADD			: adress of the first byte to write (0 ... 31)
	NB			: Number of bytes to be written (from 1 up to 64)
	data		: Data to write

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512X_Authenticate(BYTE address, BYTE kif_kref, BYTE kvc_zero);
/*****************************************************************
AUTHENTICATE CTX512X

INPUTS
	address		: address of the area to authenticate
	kif_kref	: specifies the KIF or the key reference
					(if key reference used, kvc_zero must be set to 0x00)
	kvc_zero	: specifies the KVC if the KIF has been specified in kif_kref
					(if the KIF has not been specified in kif_kref, must be set to 0x00)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCTx_512X_WriteKey(BYTE kif_kref, BYTE kvc_zero);
/*****************************************************************
writes the key in the CTM512B

INPUTS
	kif_kref	: specifies the KIF or the key reference
					(if key reference used, kvc_zero must be set to 0x00)
	kvc_zero	: specifies the KVC if the KIF has been specified in kif_kref
					(if the KIF has not been specified in kif_kref, must be set to 0x00)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/

/****************************************************************/
void iCSC_SetSAMBaudratePPS( BYTE ProProt, BYTE ParamFD);
/*****************************************************************
Parameters:
I	BYTE	ProProt		Proposed protocol (0 for T=0; 1 for T=1)
I	BYTE	ParamFD		FiDi parameter
*****************************************************************/

/****************************************************************/
void iEMVCo_UserInterface (BYTE SequenceNumber);
/*****************************************************************
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
*****************************************************************/

/****************************************************************/
void iEMVCo_Contactless (BYTE CommandNumber,
								LPBYTE Parameters);
/*****************************************************************
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
*****************************************************************/


/****************************************************************/
void iCalypsoRev3_GetMode ();
/*****************************************************************
*****************************************************************/

/****************************************************************/
void iCalypsoRev3_SetMode (BYTE Mode);
/*****************************************************************
Parameters:
I	BYTE	Mode			$00: Disable Calypso Rev3 mode.
							$01: Enable Calypso Rev3 mode.
*****************************************************************/

/****************************************************************/
void iMFUL_Identify (BYTE RFU);
/*****************************************************************
I	BYTE	RFU			RFU, should be set to 0.
*****************************************************************/

/****************************************************************/
void iMFUL_Read (BYTE ByteAddress, BYTE Nb);
/*****************************************************************
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
*****************************************************************/

/****************************************************************/
void iMFUL_Write (BYTE ByteAddress, BYTE Nb,BYTE *DataToWrite);
/*****************************************************************
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
*****************************************************************/

/****************************************************************/
void iMFULC_Authenticate (BYTE KeyNo, BYTE KeyV,
						  BYTE DIVLength, BYTE *DIVInput);
/*****************************************************************
Parameters :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
*****************************************************************/

/****************************************************************/
void iMFULC_WriteKeyFromSAM  (BYTE KeyNo, BYTE KeyV, 
       						  BYTE DIVLength, BYTE *DIVInput);
/*****************************************************************
Parameters  :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
*****************************************************************/

/****************************************************************/
void iMFULEV1_PasswordAuthenticate (BYTE *Password);
/*****************************************************************
Parameters  :
I	BYTE	*Password	password value for authentication (4 bytes)
*****************************************************************/

/****************************************************************/
void iMFULEV1_CreateDiversifiedPasswordandPACK (BYTE KeyNo, BYTE KeyV, 
       											BYTE DIVLength, BYTE *DIVInput);
/*****************************************************************
Parameters  :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
*****************************************************************/

/****************************************************************/
void iMFULEV1_ReadCounter ( BYTE CounterNb);
/*****************************************************************
Parameters  :
I	BYTE	CounterNb		counter number from $00 to $02
*****************************************************************/

/****************************************************************/
void iMFULEV1_IncrementCounter (BYTE CounterNb, 
								DWORD IncrementValue);
/*****************************************************************
Parameters  :
I	BYTE	CounterNb		counter number from $00 to $02
I	DWORD	IncrementValue	increment value from $000000 to $FFFFFF
*****************************************************************/

/****************************************************************/
void iMFULEV1_GetVersion ();
/*****************************************************************
*****************************************************************/

/****************************************************************/
void iMFULEV1_CheckTearingEvent (BYTE CounterNb);
/*****************************************************************
Parameters  :
I	BYTE	CounterNb	counter number from $00 to $02
*****************************************************************/

#endif /* __iCSC_ORD_H__ */
