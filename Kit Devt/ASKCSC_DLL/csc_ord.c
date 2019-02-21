/*****************************************************************
  Interface CSC Module Functions  ( csc_ord.c )

  ANSI 'C' language, No specific plateform

  Copyright (C)2002-1999 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Thierry J. - ASK
*****************************************************************/


/*****************************************************************
  HISTORY :
$Log:   W:/Lecteurs/DLL Askcsc/Sources/archives/csc_ord.c-arc  $
 * 
 *    Rev 1.14   13 Jun 2005 15:04:10   gbrand
 * CSC CRC enable/disable
 * 
 *    Rev 1.13   09 Jun 2005 16:15:02   ccoure
 * MAJ pour suppression de l'octet 0x00 en fin de trame si pas de CRC
 * 
 *    Rev 1.12   06 Jun 2005 14:11:10   ccoure
 * MAJ pour ajout ou non de CRC
 * 
 *    Rev 1.11   Jan 28 2004 14:51:56   cjeann
 * * Ajout des commandes transparentes CSC_TransparentCommand et CSC_TransparentCommandConfig.
 * * Ajout des commandes de la classe CTx512x.
 * * Ajout de la commande 00_06_WriteSAMNumber.
 * * Ajout de la gestion des trames longues.
 * 
 *    Rev 1.10   Oct 03 2002 11:47:06   blepin
 * voir change history
 * 
 *    Rev 1.9   Sep 16 2002 15:45:46   blepin
 * Mise à jour de la datation de la DLL
 * 
 *    Rev 1.8   Sep 16 2002 15:11:38   blepin
 * Voir liste des modification
 * 
 *    Rev 1.7   Feb 08 2002 15:19:42   smanig
 * Tous fichiers modifiés pour ajout de la classe MIFARE
 * 
 *    Rev 1.5   May 11 2001 15:49:38   smanig
 * Ajout des fonctions ChangeSpeed et ConvertBaudRate
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
Ver 4.00.00.036		 02-02-05  SM	Verification and corrections of new MIFARE functions
Ver 3.11.01.260		 01-09-17  SM   Modification for RS485 + lenght correction for SelectSam 
Ver 3.10.01.064		 01-03-05  CCV  Add CTS functions 
Ver 3.01.00.329		 00-11-24  JLM  Add GEN 3XX Managment
Ver	2.01.00.126		 00-05-05  JLM  Remove GTML_ChangeKey function
Ver 2.01.00.116      00-04-25  THJ  GTML class
Ver 1.90.99.301      99-10-22  THJ  Correct Increase and Decrease Bug
Ver 1.07.99.142      99-05-18  THJ  First Commercial Version
Ver 1.06.99.130      99-05-06  THJ  Add the DEBUG LOG
Ver 1.05.99.102      99-04-09  THJ  Add CD97 function
Ver 1.01.99.081      99-03-19  THJ  Created
*****************************************************************/

/* Includes for constants, external variables and structures ****/
#include <windows.h>    // TRUE/FALSE
#include "csc_def.h"    // CSC definition file

#define __iCSC_ORD__
#include "csc_ord.h"    // Interface CSC Module Fonctions prototypes


/* Constants and table to compute CRC ***************************/
#define kiCSC_CRCINIT   0x0F47   // CRC Initialization value

const ushort kiCSC_CRCTABLE[256]=
{
   0xF078,0xE1F1,0xD36A,0xC2E3,0xB65C,0xA7D5,0x954E,0x84C7,
   0x7C30,0x6DB9,0x5F22,0x4EAB,0x3A14,0x2B9D,0x1906,0x088F,
   0xE0F9,0xF170,0xC3EB,0xD262,0xA6DD,0xB754,0x85CF,0x9446,
   0x6CB1,0x7D38,0x4FA3,0x5E2A,0x2A95,0x3B1C,0x0987,0x180E,
   0xD17A,0xC0F3,0xF268,0xE3E1,0x975E,0x86D7,0xB44C,0xA5C5,
   0x5D32,0x4CBB,0x7E20,0x6FA9,0x1B16,0x0A9F,0x3804,0x298D,
   0xC1FB,0xD072,0xE2E9,0xF360,0x87DF,0x9656,0xA4CD,0xB544,
   0x4DB3,0x5C3A,0x6EA1,0x7F28,0x0B97,0x1A1E,0x2885,0x390C,
   0xB27C,0xA3F5,0x916E,0x80E7,0xF458,0xE5D1,0xD74A,0xC6C3,
   0x3E34,0x2FBD,0x1D26,0x0CAF,0x7810,0x6999,0x5B02,0x4A8B,
   0xA2FD,0xB374,0x81EF,0x9066,0xE4D9,0xF550,0xC7CB,0xD642,
   0x2EB5,0x3F3C,0x0DA7,0x1C2E,0x6891,0x7918,0x4B83,0x5A0A,
   0x937E,0x82F7,0xB06C,0xA1E5,0xD55A,0xC4D3,0xF648,0xE7C1,
   0x1F36,0x0EBF,0x3C24,0x2DAD,0x5912,0x489B,0x7A00,0x6B89,
   0x83FF,0x9276,0xA0ED,0xB164,0xC5DB,0xD452,0xE6C9,0xF740,
   0x0FB7,0x1E3E,0x2CA5,0x3D2C,0x4993,0x581A,0x6A81,0x7B08,
   0x7470,0x65F9,0x5762,0x46EB,0x3254,0x23DD,0x1146,0x00CF,
   0xF838,0xE9B1,0xDB2A,0xCAA3,0xBE1C,0xAF95,0x9D0E,0x8C87,
   0x64F1,0x7578,0x47E3,0x566A,0x22D5,0x335C,0x01C7,0x104E,
   0xE8B9,0xF930,0xCBAB,0xDA22,0xAE9D,0xBF14,0x8D8F,0x9C06,
   0x5572,0x44FB,0x7660,0x67E9,0x1356,0x02DF,0x3044,0x21CD,
   0xD93A,0xC8B3,0xFA28,0xEBA1,0x9F1E,0x8E97,0xBC0C,0xAD85,
   0x45F3,0x547A,0x66E1,0x7768,0x03D7,0x125E,0x20C5,0x314C,
   0xC9BB,0xD832,0xEAA9,0xFB20,0x8F9F,0x9E16,0xAC8D,0xBD04,
   0x3674,0x27FD,0x1566,0x04EF,0x7050,0x61D9,0x5342,0x42CB,
   0xBA3C,0xABB5,0x992E,0x88A7,0xFC18,0xED91,0xDF0A,0xCE83,
   0x26F5,0x377C,0x05E7,0x146E,0x60D1,0x7158,0x43C3,0x524A,
   0xAABD,0xBB34,0x89AF,0x9826,0xEC99,0xFD10,0xCF8B,0xDE02,
   0x1776,0x06FF,0x3464,0x25ED,0x5152,0x40DB,0x7240,0x63C9,
   0x9B3E,0x8AB7,0xB82C,0xA9A5,0xDD1A,0xCC93,0xFE08,0xEF81,
   0x07F7,0x167E,0x24E5,0x356C,0x41D3,0x505A,0x62C1,0x7348,
   0x8BBF,0x9A36,0xA8AD,0xB924,0xCD9B,0xDC12,0xEE89,0xFF00
};


/* Internal Functions *******************************************/

/****************************************************************/
void icsc_SetCRC(void)
/*****************************************************************
Compute and Set the CRC at the end of the buffer

INPUTS
  The buffer giCSCTrame must be initialized.
OUTPUTS
  The two last byte of the giCSCTrame buffer
  The giCSCTrameLn is incremented by 2
*****************************************************************/
{
ushort CRCVal;
int i, j;

	if (giCSCMode485 == TRUE)
	{
		j= giCSCTrameLn;
		for (i=0; i<=giCSCTrameLn; i++, j--) giCSCTrame[j+1] = giCSCTrame[j]; //buffer is shifted 1 byte on the right
		giCSCTrame[0] = giCSCNumber485;
		giCSCTrameLn++;
	}


CRCVal=0;
for(i=0;i<giCSCTrameLn;i++)
  CRCVal=kiCSC_CRCTABLE[(CRCVal^=(giCSCTrame[i]&0xFF))&0xFF]^(CRCVal>>8);
giCSCTrame[giCSCTrameLn  ]=CRCVal%256;
giCSCTrame[giCSCTrameLn+1]=CRCVal/256;
giCSCTrameLn+=2;
}


/* Interface Functions *******************************************
All function bellow return the value in the exchange
buffer 'giCSCTrame' and the effective buffer length in 'giCSCTrameLn'
The return status is in 'giCSCStatus'
*****************************************************************/

/****************************************************************/
BYTE iCSC_TestCRC(void)
/*****************************************************************
Test the CRC of the buffer

INPUTS
  The buffer giCSCTrame must be initialized with the CRC
RETURNS
  iCSC_OK      Validate CRC
  iCSC_FAIL    CRC error
*****************************************************************/
{
	ushort CRCVal;
	int lg;
	int i;

	CRCVal=0;
	if (giCSCTrameLn>1)
	if(giCSCTrame[0]==0x41)	// DF : Trame etendue 0x41 -> lg = LgLow + 256*LgHigh
	{
		lg=giCSCTrameLn;
	}
	else if (giCSCTrame[1+(giCSCMode485?1:0)]!=0xFF)
	{
		if ((lg=giCSCTrame[1+(giCSCMode485?1:0)]+5+(giCSCMode485?1:0))>giCSCTrameLn)
			return iCSC_FAIL;        // if checksum error function fail
	}
	else
		if ((lg=giCSCTrame[2+(giCSCMode485?1:0)]+6+(giCSCMode485?1:0)+0xFF)>giCSCTrameLn)
			return iCSC_FAIL;        // if checksum error function fail

	for(i=0;i<lg;i++)
	  CRCVal=kiCSC_CRCTABLE[(CRCVal^=(giCSCTrame[i]&0xFF))&0xFF]^(CRCVal>>8);
	if(CRCVal!=kiCSC_CRCINIT)
			return iCSC_FAIL;        // if checksum error function fail
	return iCSC_OK;                  // else function success
}



/****************************************************************/
void iCSC_SoftwareVersion(void)
/*****************************************************************
Returns the CSC Software version
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command

if (giCRCNeeded == TRUE){
	giCSCTrame[1]=0x02;  
	giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
	giCSCTrame[3]=CSC_SYS_SOFTWARE_VERSION;
	giCSCTrame[4]=0x00;                         // End of Command
	giCSCTrameLn=5;
	// Compute and Set the CRC at the end of the buffer
	icsc_SetCRC();
}

else{
	giCSCTrame[1]=0x03;                             // Length
	giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
	giCSCTrame[3]=CSC_SYS_SOFTWARE_VERSION;
	giCSCTrame[4]=0xFF;								// CRC not needed
/*	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
*/
	giCSCTrameLn=5;
}


// Compute and Set the CRC at the end of the buffer
giCSCStatus=iCSC_OK;
}


/*****************************************************************/
void iCSC_SearchStop(BYTE Type)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Type :	0 for INTERROGATION; 1 for DEFINITIVELY
OUTPUTS
	None 
  
*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_SYSTEM;					// SYSTEM class
giCSCTrame[j++]=CSC_SYS_SEARCH_STOP;			// SYSTEM Command
giCSCTrame[j++]=Type;							// Data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;								// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght

	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;									// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght

}


giCSCStatus=iCSC_OK;

}


/****************************************************************/
void iCSC_EnterHuntPhase(BYTE Antenna,BYTE SearchType)
/*****************************************************************
Starts the search of a card

INPUTS
  Antenna    : Antenna Type ( CSC_SYS_ANTENNE_1, ... )
  SearchType : The card type ( CSC_SEARCH_PSCL or CSC_SEARCH_CLESSCARD )
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x07;                             // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_ENTER_HUNT_PHASE;
giCSCTrame[4]=Antenna;                          // Antenna Type
giCSCTrame[5]=0x00;                             // RFU
if(SearchType==CSC_SEARCH_PSCL)
 {
 giCSCTrame[6]=0x01;                             // GDW8 Modulation
 giCSCTrame[8]=0x00;                             // BPSK Modulation
 }
else
 {
 giCSCTrame[6]=0x00;                             // GDW8 Modulation
 giCSCTrame[8]=0x01;                             // BPSK Modulation
 }
giCSCTrame[7]=0x00;                             // ASK Modulation ( RFU )

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[9]=0x00;                             // End of Command
	giCSCTrameLn=10;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=9;	
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_EnterHuntPhase2(BYTE Antenna,
						  BYTE CONT,BYTE ISOA,BYTE ISOB,BYTE TICK,BYTE INNO,
						  BYTE Forget,BYTE TimeOut)
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
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=10;							    // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_ENTER_HUNT_PHASE;
giCSCTrame[4]=Antenna;                          // Antenna Type
giCSCTrame[5]=CONT;								// Contact Mode ratio (0-F)
giCSCTrame[6]=ISOB;								// ISO B Protocol Mode ratio (0-F)
giCSCTrame[7]=ISOA;								// ISO A Protocol Mode ratio (0-F)
giCSCTrame[8]=(TICK<<4|INNO);					// 4MSB = Ticket Mode ratio (0-F)
												// 4LSB = Innovatron Protocol Mode ratio (0-F)
if (giCSCMode485 == TRUE)
	giCSCTrame[9]=0x02;								// Extended mode with immediate response
else
	giCSCTrame[9]=0x01;								// Extended mode

giCSCTrame[10]=Forget;                          // Parameter to forget the last tag serial number
giCSCTrame[11]=TimeOut;                         // Time Out of the command (x10ms)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[12]=0x00;                            // End of Command
	giCSCTrameLn=13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=12;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_EnterHuntPhase3(BYTE Antenna,
						  BYTE CONT,BYTE ISOA,BYTE MIFARE,BYTE ISOB,
						  BYTE TICK,BYTE INNO,
						  BYTE MV4k, BYTE MV5k,
						  BYTE Forget,BYTE TimeOut)
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
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=10;							    // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_ENTER_HUNT_PHASE;
giCSCTrame[4]=Antenna;                          // Antenna Type
giCSCTrame[5]=CONT;								// Contact Mode ratio (0-F)
giCSCTrame[6]=((MV5k<<6|MV4k<<4) | ISOB);		// ISO B Protocol Mode ratio (0-F), 4 lsb bits
												// MV4k Protocol Mode ratio (0-3), bits 4,5
 												// MV5k Protocol Mode ratio (0-3), bits 6,7
giCSCTrame[7]=(ISOA<<4 | MIFARE);				// MIFARE Protocol Mode ratio (0-F), 4 lsb bits
												// ISO A Protocol Mode ratio (0-F), 4 msb bits
giCSCTrame[8]=(TICK<<4|INNO);					// 4MSB = Ticket Mode ratio (0-F)
												// 4LSB = Innovatron Protocol Mode ratio (0-F)
if (giCSCMode485 == TRUE)
	giCSCTrame[9]=0x02;								// Extended mode with immediate response
else
	giCSCTrame[9]=0x01;								// Extended mode

giCSCTrame[10]=Forget;                          // Parameter to forget the last tag serial number
giCSCTrame[11]=TimeOut;                         // Time Out of the command (x10ms)
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[12]=0x00;                            // End of Command
	giCSCTrameLn=13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=12;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_EnterHuntPhase4(BYTE Antenna,
						  BYTE MONO,
						  BYTE CONT,BYTE ISOA,BYTE MIFARE,BYTE ISOB,
						  BYTE TICK,BYTE INNO,
						  BYTE MV4k, BYTE MV5k,
						  BYTE Forget,BYTE TimeOut)
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
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=10;							    // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_ENTER_HUNT_PHASE;
giCSCTrame[4]=(MONO<<6) | Antenna;              // mono-search mode (high nibble) and Antenna Type (low nibble)
giCSCTrame[5]=CONT;								// Contact Mode ratio (0-F)
giCSCTrame[6]=((MV5k<<6|MV4k<<4) | ISOB);		// ISO B Protocol Mode ratio (0-F), 4 lsb bits
												// MV4k Protocol Mode ratio (0-3), bits 4,5
 												// MV5k Protocol Mode ratio (0-3), bits 6,7
giCSCTrame[7]=(ISOA<<4 | MIFARE);				// MIFARE Protocol Mode ratio (0-F), 4 lsb bits
												// ISO A Protocol Mode ratio (0-F), 4 msb bits
giCSCTrame[8]=(TICK<<4|INNO);					// 4MSB = Ticket Mode ratio (0-F)
												// 4LSB = Innovatron Protocol Mode ratio (0-F)
if (giCSCMode485 == TRUE)
	giCSCTrame[9]=0x02;								// Extended mode with immediate response
else
	giCSCTrame[9]=0x01;								// Extended mode

giCSCTrame[10]=Forget;                          // Parameter to forget the last tag serial number
giCSCTrame[11]=TimeOut;                         // Time Out of the command (x10ms)
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[12]=0x00;                            // End of Command
	giCSCTrameLn=13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=12;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_EnterHuntPhase5(BYTE Antenna,
						  BYTE MONO, BYTE SRX,
						  BYTE CONT,BYTE ISOA,BYTE MIFARE,BYTE ISOB,
						  BYTE TICK,BYTE INNO,
						  BYTE MV4k, BYTE MV5k,
						  BYTE Forget,BYTE TimeOut)
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
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=10;							    // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_ENTER_HUNT_PHASE;
giCSCTrame[4]=(MONO<<6) | Antenna;              // mono-search mode (high nibble) and Antenna Type (low nibble)
giCSCTrame[5]=(SRX<<4) | CONT;					// SRx Family (0-F), 4 msb bits
												// Contact Mode ratio (0-F), 4 lsb bits
giCSCTrame[6]=((MV5k<<6|MV4k<<4) | ISOB);		// ISO B Protocol Mode ratio (0-F), 4 lsb bits
												// MV4k Protocol Mode ratio (0-3), bits 4,5
 												// MV5k Protocol Mode ratio (0-3), bits 6,7
giCSCTrame[7]=(ISOA<<4 | MIFARE);				// MIFARE Protocol Mode ratio (0-F), 4 lsb bits
												// ISO A Protocol Mode ratio (0-F), 4 msb bits
giCSCTrame[8]=(TICK<<4|INNO);					// 4MSB = Ticket Mode ratio (0-F)
												// 4LSB = Innovatron Protocol Mode ratio (0-F)
if (giCSCMode485 == TRUE)
	giCSCTrame[9]=0x02;								// Extended mode with immediate response
else
	giCSCTrame[9]=0x01;								// Extended mode

giCSCTrame[10]=Forget;                          // Parameter to forget the last tag serial number
giCSCTrame[11]=TimeOut;                         // Time Out of the command (x10ms)
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[12]=0x00;                            // End of Command
	giCSCTrameLn=13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=12;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_EndTagCommunication(BYTE DiscnxMode)
/*****************************************************************
End the communication with the card

INPUTS
  DiscnxMode : Disconnect Mode (CSC_SYS_DISC_REQ,CSC_SYS_NO_DISC_REQ)
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x03;                             // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_END_TAG_COMMUNICATION;
giCSCTrame[4]=DiscnxMode;                       // Disconnect Mode
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;                             // End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_SetAntennaTransparentMode(BYTE Antenna,BYTE SearchType,
                                    BYTE TranspMode)
/*****************************************************************
Set the Antenna Transparent mode parameters

INPUTS
  Antenna    : Antenna Type ( CSC_SYS_ANTENNE_1, ... )
  SearchType : The card type ( CSC_SEARCH_PSCL or CSC_SEARCH_CLESSCARD )
  TranspMode : Transparent Mode ( CSC_SYS_MODE_TRANSPARENT_1, ... )
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x05;                             // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SET_ANTENNA_TRANSPARENT_MODE;
giCSCTrame[4]=SearchType;
giCSCTrame[5]=Antenna;                          // Antenna number
giCSCTrame[6]=TranspMode;                       // Transparent Mode

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;                             // End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_SendToAntenna(BYTE *Data,BYTE DataLen)
/*****************************************************************
Send directly the Data to Antenna

INPUTS
  Data       : Data to send
  DataLen    : The size of data to send
*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+4;                        // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SEND_TO_ANTENNA;
giCSCTrame[4]=DataLen+1;                        // length
giCSCTrame[5]=DataLen+1;                        // length again
for(i=0; i < DataLen; i++)
  giCSCTrame[i+6]= *(Data+i);                   // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+6]=0x00;                     // End of Command
	giCSCTrameLn=DataLen+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+6;
}

giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_SendToAntennaExt(BYTE pLnINLow, BYTE pLnINHigh, BYTE* pBufIN)
/*****************************************************************
Sends an ISO command Extended, and returns the answer.

INPUTS
	pLnINLow		: ISO command length Low (1 Byte)
	pLnINHigh		: ISO command length High (1 Byte)
	pBufIN			: the ISO Command to send to the card (n Bytes)

*****************************************************************/
{
	int i, j = 0;
	int DataLen = 0;

	DataLen = pLnINLow + (256*pLnINHigh);			// Length Data

	giCSCTrame[j++]=CSC_CMD_EXEC_EXT;				// EXEC Command
	giCSCTrame[j++]=0;								// Length Low
	giCSCTrame[j++]=0;								// Length High
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_SYS_SEND_TO_ANTENNA_EXT;
	giCSCTrame[j++]=pLnINLow;						// length low
	giCSCTrame[j++]=pLnINHigh;						// length high
	for(i=0; i < DataLen; i++, j++)
	  giCSCTrame[j]= *(pBufIN+i);					// memcopy of data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = (BYTE)((giCSCTrameLn-4) & 0xFF);						// Update Command lenght Low
		giCSCTrame[2] = (BYTE)(((giCSCTrameLn-4) & 0xFF00)>>8);					// Update Command lenght High
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_TransparentCommandConfig(BYTE ISO, BYTE addCRC, BYTE checkCRC, BYTE field)
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
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=6;								// Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_TRANSP_COMMAND_CONFIG;		// ins
giCSCTrame[4]=ISO;		                        // length
giCSCTrame[5]=addCRC;							// addCRC
giCSCTrame[6]=checkCRC;							// checkCRC
giCSCTrame[7]=field;							// field
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[8]=0x00;								// End of Command
	giCSCTrameLn=9;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=8;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_TransparentCommandConfigExt(BYTE ISO,
									 BYTE addCRC,
									 BYTE checkCRC,
									 BYTE addParity,
									 BYTE checkParity,
									 BYTE numBitLastByte,
									 BYTE byPassISOA,
									 BYTE field,
									 WORD timeOut)
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
	numBitLastByte :Number of bits of the last byte that shall transmitted 0 to 7 (1 byte)
	byPassISOA :	0x01 : ByPass ISOA
					else : True ISOA
	field :			0x01 : the field will be switched ON when sending the frame
					else : no modification of the field
	timeOut	:		TimeOut Allowed for answer 0 to 2000 ms (default 456 ms) (2 byte) 	

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=6;								// Length
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_TRANSP_COMMAND_CONFIG;		// ins
	giCSCTrame[j++]=ISO;		                    // length
	giCSCTrame[j++]=(addCRC&0x01) |
				  ((addParity&0x01)<<3) |
				  ((numBitLastByte&0x07)<<4) |
				  ((byPassISOA&0x01)<<7);			// addCRC+addParity+numBitLastByte+byPassISOA
	giCSCTrame[j++]=(checkCRC&0x01) |
				  ((checkParity&0x01)<<3);			// checkCRC+checkParity
	giCSCTrame[j++]=field;							// field
	giCSCTrame[j++]=(BYTE)((timeOut&0xFF00)>>8);	// TimeOut High
	giCSCTrame[j++]=(BYTE)(timeOut&0xFF);			// TimeOut Low

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_TransparentCommand(BYTE frameLength, BYTE* frame)
/*****************************************************************
sends and receives the transparent command, as specified in
	iCSC_TransparentCommandConfig

INPUTS
  frameLength	: length of frame
  frame			: frame to send
*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=frameLength + 2;					// Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_TRANSP_COMMAND_SEND;			// ins

for (i = 0; i<frameLength ; i++)
{
	giCSCTrame[i+4] = frame[i];					// data to send
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[frameLength + 4]=0x00;                     // End of Command
	giCSCTrameLn=frameLength + 5;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=frameLength + 4;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCSC_GetCommStatus(void)
/*****************************************************************
Return the last command status
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x02;						        // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_GET_COMMUNICATION_STATUS;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[4]=0x00;                             // End of Command
	giCSCTrameLn=5;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=4;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_SetAPGENExtensions(BYTE SearchType,BYTE OccupParam,
                                    BYTE ATRMode)
/*****************************************************************
Set the Antenna Transparent mode parameters

INPUTS
  SearchType : The card type ( CSC_SEARCH_PSCL or CSC_SEARCH_CLESSCARD )
	OccupParam : Occupation Parameters ( 0 - 63 )
  ATRMode    : CSC_SYS_ATR : return ATR in REPGEN    CSC_SYS_NO_ATR : no ATR
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x05;                             // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SET_APGEN_EXTENSION;
giCSCTrame[4]=SearchType;
giCSCTrame[5]=OccupParam;                       // Occupation Parameters
giCSCTrame[6]=ATRMode;                          // Transparent Mode
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;                             // End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCSC_SetTagCommParam(iCSC_STCP* Stcp)
/*****************************************************************
Set the Communication parameters


INPUTS
  Stcp       : Pointer to a iCSC_STCP structure to be filled in.
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x14;                             // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SET_TAG_COMMUNICATION_PARAMETERS;
giCSCTrame[4]=Stcp->ValidAddr;					// ???
giCSCTrame[5]=0x00;								// TP1 ( Command timeout delay )
giCSCTrame[6]=0x00;								// TP1 ( Data timeout delay )
giCSCTrame[7]=0x00;								// TP1 ( Number of hangs )
giCSCTrame[8]=0x00;								// TP1 ( RFU )

giCSCTrame[9]=Stcp->PSCL_Timeout1;				// TP2
giCSCTrame[10]=Stcp->PSCL_Timeout2;				// TP2
giCSCTrame[11]=Stcp->PSCL_HangNumber;			// TP2
giCSCTrame[12]=0x00;							// TP2

giCSCTrame[13]=0x00;							// TP3
giCSCTrame[14]=0x00;							// TP3
giCSCTrame[15]=0x00;							// TP3
giCSCTrame[16]=0x00;							// TP3

giCSCTrame[17]=Stcp->CLESS_Timeout1;			// TP4
giCSCTrame[18]=Stcp->CLESS_Timeout2;			// TP4
giCSCTrame[19]=Stcp->CLESS_HangNumber;			// TP4
giCSCTrame[20]=0x00;							// TP4

giCSCTrame[21]=0x01;							// Card Reset managment 6.78/13.56 Mhz

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[22]=0x00;                            // End of Command
	giCSCTrameLn=23;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=22;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCSC_SwitchOffAntenna(BYTE Antenna)
/*****************************************************************
Stop the antenna

INPUTS
  Antenna    : Antenna Type ( CSC_SYS_ANTENNE_1, ... )
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x03;                             // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SWITCH_OFF_ANTENNA;
giCSCTrame[4]=Antenna;                          // Antenna Type
// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;                             // End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_WriteSAMNumber(BYTE N_SAM)
/*****************************************************************
Write Sam Number

writes the default SAM number in the EEPROM for memory

INPUTS
	N_SAM : SAM number

OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x03;								// Length
giCSCTrame[2]=CSC_CLA_DOWNLOAD;                 // class
giCSCTrame[3]=CSC_WRITE_SAM_NUMBER;				// INS
giCSCTrame[4]=N_SAM;                            // Number of SAM

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;                             // End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_WriteConfigEeprom(BYTE pIndex, BYTE pValue)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=0;								// Length
	giCSCTrame[j++]=CSC_CLA_DOWNLOAD;               // class
	giCSCTrame[j++]=CSC_WRITE_CONFIG_EEPROM;		// INS
	giCSCTrame[j++]=pIndex;                         // Data
	giCSCTrame[j++]=pValue;                         // Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/****************************************************************/
void iCSC_ReadConfigEeprom(BYTE pIndex)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=0;								// Length
	giCSCTrame[j++]=CSC_CLA_DOWNLOAD;               // class
	giCSCTrame[j++]=CSC_READ_CONFIG_EEPROM;			// INS
	giCSCTrame[j++]=pIndex;                         // Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/****************************************************************/
void iCSC_SelectSAM(BYTE N_SAM,BYTE Type)
/*****************************************************************
Select the current SAM
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x04;								// Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SELECT_SAM;
giCSCTrame[4]=N_SAM;                            // Number of SAM
giCSCTrame[5]=Type;                             // Type of Protocol

gCurrentSAM = N_SAM;
gSAM_Prot[gCurrentSAM] = Type;


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;                             // End of Command
	giCSCTrameLn=7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;

}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCSC_ResetSAM(void)
/*****************************************************************
Initialization of the SAM module
The choice of the protocole is the last one choosen in the 
SelectSAM command (Initial value is Innovatron CSC)
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x05;								// Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_RESET_SAM;
giCSCTrame[4]=0x00;                             // Internal current SAM

giCSCTrame[5]=(gSAM_Prot[gCurrentSAM] ==SAM_PROT_HSP_INNOVATRON)? 1 : 0;			 
giCSCTrame[6]=(gSAM_Prot[gCurrentSAM] ==SAM_PROT_HSP_INNOVATRON)? 0 : 1;			 


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;                             // End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_ResetSAMExt(BYTE SamNum, BYTE SelectINN, BYTE SelectISO)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					// EXEC Command
	giCSCTrame[j++]=0;								// Length
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_SYS_RESET_SAM;
	giCSCTrame[j++]=SamNum;							// Data
	giCSCTrame[j++]=SelectINN;						// Data
	giCSCTrame[j++]=SelectISO;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_SendToSAM(BYTE *Data,BYTE DataLen)
/*****************************************************************
Send directly the Data to the SAM module

INPUTS
  Data       : Data to send
  DataLen    : The size of data to send
*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+4;                        // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SEND_TO_SAM;
giCSCTrame[4]=0x00;								// Use internal SAM
if (DataLen > Data[4]+5)
	giCSCTrame[5]=Data[4]+5+1;                  // length of In command in ISO (sens is not comprized in command)
else if (DataLen == Data[4]+5)
	giCSCTrame[5]=DataLen+1;                    // length of command in Innovatron protocol
else 
	giCSCTrame[5]=5+1;							// length of Out command in ISO (sens is not comprized in command)

for(i=0; i < giCSCTrame[5]+1; i++)
  giCSCTrame[i+6]= *(Data+i);                   // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+6]=0x00;                     // End of Command
	giCSCTrameLn=DataLen+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+6;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_SendToSAMExt(BYTE pNumSAM, DWORD pLgBufIN, BYTE* pBufIN, BYTE pDirection)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=0;								// Length
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_SYS_SEND_TO_SAM;
	giCSCTrame[j++]=pNumSAM;						// n°SAM
	giCSCTrame[j++]=(BYTE)pLgBufIN+1;				// length of In command in ISO + length
	for(i=0; i < (BYTE)pLgBufIN; i++, j++)
	  giCSCTrame[j]= *(pBufIN+i);                   // memcopy of data
	giCSCTrame[j++]=pDirection;						// direction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCSC_ISOCommandContact(BYTE* BufIN,BYTE LnIN,BYTE Case)
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
{
int i;

/* use of the 'send to SAM' command with the parameters :
	SAM number = 0x00 = selected SAM
	Case = user-selected case
*/

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=LnIN+5;	                        // Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SEND_TO_SAM;
giCSCTrame[4]=0x00;								// Use selected SAM slot in selected mode
giCSCTrame[5]=LnIN+1;							// length = data length + 1 (length included)
for(i=0; i < LnIN; i++)
  giCSCTrame[i+6]= BufIN[i];                    // memcopy of data

giCSCTrame[LnIN+6]=Case;						// APDU case

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[LnIN+7]=0x00;						// End of Command
	giCSCTrameLn=LnIN+8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=LnIN+7;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCSC_Switch_Led_Buzzer(ulong Param)
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
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x04;								// Length
giCSCTrame[2]=CSC_CLA_SYSTEM;                   // System class
giCSCTrame[3]=CSC_SYS_SWITCH_SIGNALS;
giCSCTrame[4]=(BYTE)(Param>>8);                  // Parameters for CPU LED
giCSCTrame[5]=(BYTE)Param;                     // Parameters for Antenna 
												// LED / Buzzer

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;                             // End of Command
	giCSCTrameLn=7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;
}
giCSCStatus=iCSC_OK;
}




/*****************************************************************
CD97 Command ( Class 3 CSC orders )
*****************************************************************/


/****************************************************************/
void iCD97_AppendRecord(BYTE AccMode,BYTE SID,BYTE *Data,
													BYTE DataLen)
/*****************************************************************
CD97 Command
Add a record to a circular EF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID				 : SID Number ( CD97_SID_RT_JOURNAL, ...)
  Data       : Data to write
  DataLen    : The size of data to write

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+5;                        // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_APPEND_RECORD;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number

giCSCTrame[6]=DataLen;                          // data length
for(i=0; i < DataLen; i++)
  giCSCTrame[i+7]= *(Data+i);                   // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+7]=0x00;                     // End of Command
	giCSCTrameLn=DataLen+8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+7;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_ChangeKey(BYTE KeyIndex,BYTE NewVersion)
/*****************************************************************
CD97 Command
Key modification

INPUTS
	KeyIndex	 : Index of the key ( 0x01 - 0x03 )
	NewVersion : New version of the key ( <> 0x00 )

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_CHANGE_KEY;

giCSCTrame[4]=KeyIndex;							// Index of the key
giCSCTrame[5]=NewVersion;						// New Version of the key

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// End of Command
	giCSCTrameLn=7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCD97_ChangeKeyExt(BYTE pKeyIndex, BYTE pNewKeyVersion, BYTE pTypeCmd, 
						BYTE pKeyIndexEncipher, BYTE pALGTag, BYTE pALGSam, BYTE pNewKeyIndex)
/*****************************************************************
Change the key / Personnalization


INPUTS
	pKeyIndex			: Index of the key ( 01 - 03 ) (1 byte)
	pNewKeyVersion		: New version of the key ( <> 0 ) (1 byte)
	pTypeCmd				: type Command (1 byte)
							$00 : short cmd
							$01 : long cmd
	pKeyIndexEncipher	: Index of the key to encipher the transfer (1 byte)
	pALGTag				: Algo key card to recopy (1 byte)
	pALGSam				: Algo of the Sam used (1 byte)
	pNewKeyIndex			: index of the new key in the card in the DF (1 byte)

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=0;								// Length
	giCSCTrame[j++]=CSC_CLA_GEN;					// Generic class
	giCSCTrame[j++]=CSC_CD97_CHANGE_KEY;
	giCSCTrame[j++]=pKeyIndex;						// Data
	giCSCTrame[j++]=pNewKeyVersion;					// Data
	giCSCTrame[j++]=pTypeCmd;						// Data
	giCSCTrame[j++]=pKeyIndexEncipher;				// Data
	giCSCTrame[j++]=pALGTag;						// Data
	giCSCTrame[j++]=pALGSam;						// Data
	giCSCTrame[j++]=pNewKeyIndex;					// Data


	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCD97_ChangePIN(BYTE* OldPIN,BYTE* NewPIN)
/*****************************************************************
CD97 Command
PIN modification

INPUTS
	OldPIN		 : Old PIN code ( 4 characters )
	NewPIN     : New PIN code ( 4 characters )

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_CHANGE_KEY;

giCSCTrame[4]=0x04;								// Pin modification 
												// ( the current DF = 3F00 )

giCSCTrame[5]=0x00;								// RFU

for(i=0; i < 4; i++)
  giCSCTrame[i+6]= *(OldPIN+i);                 // memcopy of OldPIN

for(i=0; i < 4; i++)
  giCSCTrame[i+10]= *(NewPIN+i);                // memcopy of NewPIN

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCD97_ChangePINExt(BYTE pKeyNum, LPBYTE pOldPIN, LPBYTE pNewPIN, BYTE pTypeCmd,
						BYTE pKeyNumKIF, BYTE pKVC, BYTE pALG, BYTE pSamNum)
/*****************************************************************
Change the PIN code


INPUTS
	pKeyNum		: Key number (1 byte)
					$00 : CD97, GTML and CT2000,
					$04 : GTML2 and CD21, 
					$09 : POPEYE
	pOldPIN		: Old PIN Code (4 bytes)
	pNewPIN		: New PIN Code (4 bytes)
	pTypeCmd		: type Command (1 byte)
					$00 : short cmd
					$01 : long cmd
	pKeyNumKIF	: SAM key number to use (1 byte)
				  or KIF of the key
	pKVC			: $00 (if NKEY passed in the previous parameter)(1 byte)
				  or KVC of the Key
	pALG			: Algorithm of the SAM used (1 byte)
	pSamNum		: SAM number (1 byte)
					$00 : default SAM,
					$01, $02, $03 or $04 : logical number of the wanted SAM number

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;						// EXEC Command
	giCSCTrame[j++]=0;									// Length
	giCSCTrame[j++]=CSC_CLA_CD97;						// CD97 class
	giCSCTrame[j++]=CSC_CD97_CHANGE_KEY;
	giCSCTrame[j++]=0x04;								// Pin modification // ( the current DF = 3F00 )
	giCSCTrame[j++]=pKeyNum;							// Data
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pOldPIN+i);						// memcopy of OldPIN
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pNewPIN+i);						// memcopy of NewPIN
	giCSCTrame[j++]=pTypeCmd;							// Data
	giCSCTrame[j++]=pKeyNumKIF;							// Data
	giCSCTrame[j++]=pKVC;								// Data
	giCSCTrame[j++]=pALG;								// Data
	giCSCTrame[j++]=pSamNum;							// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_Decrease(BYTE AccMode,BYTE SID,ulong Value)
/*****************************************************************
CD97 Command
Decrease a counter file value

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID				 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Value			 : Value decreased

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_DECREASE;

giCSCTrame[4]=AccMode;							// Card Access Mode
giCSCTrame[5]=SID;								// Small ID file number

giCSCTrame[6]=(BYTE)((Value/65536)&0xFF);		// value ( bits 23 - 16 )
giCSCTrame[7]=(BYTE)((Value/256)&0xFF);		// value ( bits 15 -  8 )
giCSCTrame[8]=(BYTE)(Value&0xFF);				// value ( bits  7 -  0 )

for(i=0; i < 5; i++)
  giCSCTrame[i+9]= 0x00;						// Free data ( 5 bytes )

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCD97_Increase(BYTE AccMode,BYTE SID,ulong Value)
/*****************************************************************
CD97 Command
Increase a counter file value

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID				 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	Value			 : Value increased

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_INCREASE;

giCSCTrame[4]=AccMode;							// Card Access Mode
giCSCTrame[5]=SID;								// Small ID file number

giCSCTrame[6]=(BYTE)((Value/65536)&0xFF);		// value ( bits 23 - 16 )
giCSCTrame[7]=(BYTE)((Value/256)&0xFF);		// value ( bits 15 -  8 )
giCSCTrame[8]=(BYTE)(Value&0xFF);				// value ( bits  7 -  0 )

for(i=0; i < 5; i++)
  giCSCTrame[i+9]= 0x00;						// Free data ( 5 bytes )


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_Invalidate(BYTE AccMode)
/*****************************************************************
CD97 Command
Invalidate the current DF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_INVALIDATE;

giCSCTrame[4]=AccMode;							// Card Access Mode

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_Rehabilitate(BYTE AccMode)
/*****************************************************************
CD97 Command
Rehabilitate the current DF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_REHABILITATE;

giCSCTrame[4]=AccMode;							// Card Access Mode

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCD97_ReadRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
													BYTE DataLen)
/*****************************************************************
CD97 Command
Read a record from linear or circular file

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID				 : Small ID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec			 : Record number
	DataLen    : Number of bytes to be read ( record length )

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=6;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_READ_RECORD;

giCSCTrame[4]=AccMode;							// Card Access Mode
giCSCTrame[5]=SID;								// Small ID file number
giCSCTrame[6]=NuRec;							// Record Number
giCSCTrame[7]=DataLen;							// Number of bytes to be read 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[8]=0x00;								// End of Command
	giCSCTrameLn=9;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=8;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCD97_SelectFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen)
/*****************************************************************
CD97 Command
EF or DF select file

INPUTS
	SelectMode : Select Mode :

					CD97_SEL_MF	( Select the Master file )
					CD97_SEL_CURENT_EF ( Select the curent EF ID )
					CD97_SEL_PATH ( the path from MF ( exclude ) )

	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=IdPathLen+4;                      // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_SELECT_FILE;

giCSCTrame[4]=SelectMode;						// Select mode

giCSCTrame[5]=IdPathLen;                        // IdPath length
for(i=0; i < IdPathLen; i++)
  giCSCTrame[i+6]= *(IdPath+i);                 // memcopy of data


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[IdPathLen+6]=0x00;				// End of Command
	giCSCTrameLn=IdPathLen+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=IdPathLen+6;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_StatusFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen)
/*****************************************************************
CD97 Command
Same as iCD97_SelectFile but only give the file status without
select the file

INPUTS
	SelectMode : Select Mode :

					CD97_SEL_MF	( Select the Master file )
					CD97_SEL_CURENT_EF ( Select the curent EF ID )
					CD97_SEL_PATH ( the path from MF ( exclude ) )

	IdPath     : ID number or path from MF ( exclude )
	IdPathLen  : IdPath length

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=IdPathLen+4;                      // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_STATUS;

giCSCTrame[4]=SelectMode;						// Select mode

giCSCTrame[5]=IdPathLen;                        // IdPath length
for(i=0; i < IdPathLen; i++)
  giCSCTrame[i+6]= *(IdPath+i);                 // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[IdPathLen+6]=0x00;					// End of Command
	giCSCTrameLn=IdPathLen+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=IdPathLen+6;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_UpdateRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE *Data,BYTE DataLen)
/*****************************************************************
CD97 Command
Erase and write a record to a EF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID				 : SID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec			 : Record number
  Data       : Data to write
  DataLen    : The size of data to write

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+6;                        // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_UPDATE_RECORD;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number
giCSCTrame[6]=NuRec;							// Record Number

giCSCTrame[7]=DataLen;                          // data length
for(i=0; i < DataLen; i++)
  giCSCTrame[i+8]= *(Data+i);                   // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+8]=0x00;                     // End of Command
	giCSCTrameLn=DataLen+9;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+8;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCD97_WriteRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
										BYTE *Data,BYTE DataLen)
/*****************************************************************
CD97 Command
Write a record to a EF

INPUTS
	AccMode		 : Card Access Mode ( CD97_ACCESS_MODE_DEFAULT, ...)
	SID				 : SID Number ( CD97_SID_RT_JOURNAL, ...)
	NuRec			 : Record number
  Data       : Data to write
  DataLen    : The size of data to write

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+6;                        // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_WRITE_RECORD;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number
giCSCTrame[6]=NuRec;							// Record Number

giCSCTrame[7]=DataLen;                          // data length
for(i=0; i < DataLen; i++)
  giCSCTrame[i+8]= *(Data+i);                   // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+8]=0x00;                     // End of Command
	giCSCTrameLn=DataLen+9;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+8;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCD97_VerifyPIN(BYTE* PIN)
/*****************************************************************
CD97 Command
PIN verification

INPUTS
	PIN				 : PIN code ( 4 characters )

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=7;				                // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_VERIFY_PIN;

giCSCTrame[4]=0x01;								// PIN Presentation

for(i=0; i < 4; i++)
  giCSCTrame[i+5]= *(PIN+i);                    // memcopy of PIN

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[9]=0x00;								// End of Command
	giCSCTrameLn=10;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=9;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCD97_VerifyPINExt(BYTE pMode, LPBYTE pPIN, BYTE pTypeCmd, BYTE pKeyNumKIF, BYTE pKVC, BYTE pSamNum)
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
{
	int i , j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=7;				                // Length
	giCSCTrame[j++]=CSC_CLA_CD97;					// CD97 class
	giCSCTrame[j++]=CSC_CD97_VERIFY_PIN;
	giCSCTrame[j++]=pMode;							// Data
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pPIN+i);						// memcopy of PIN
	giCSCTrame[j++]=pTypeCmd;						// Data
	giCSCTrame[j++]=pKeyNumKIF;						// Data
	giCSCTrame[j++]=pKVC;							// Data
	giCSCTrame[j++]=pSamNum;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCD97_Purchase(BYTE Type,BYTE* DataLog,BYTE* Disp)
/*****************************************************************
CD97 Command
Purchase with the Electronic Purse ( EP )

INPUTS
	Type				 : Purchase Type :
									- Purchase without display ( 0x00 )
									- Purchase with display		 ( 0x01 )
	DataLog      : EP Log record ( 7 bytes )
	Disp				 : Display Message

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command

giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_PURCHASE;

giCSCTrame[4]=Type;								// Purchase Type

for(i=0; i < 7; i++)
  giCSCTrame[i+5]= *(DataLog+i);                // memcopy of DataLog

if(Type==0)										// without Display Message
{
	giCSCTrame[1]=10;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[12]=0x00;					// End of Command
		giCSCTrameLn=13;
	}
	else{
		giCSCTrameLn=12;
	}
}
else											// with Display Message
{
	for(i=0; i < 6; i++)
		giCSCTrame[i+12]= *(Disp+i);			// memcopy of Disp
	giCSCTrame[1]=16;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[18]=0x00;					// End of Command
		giCSCTrameLn=19;
	}
	else{
		giCSCTrameLn=18;
	}
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE)		icsc_SetCRC();
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_GetEPStatus(BYTE Type)
/*****************************************************************
CD97 Command
Purchase with the Electronic Purse ( EP )

INPUTS
	Type				 : Transaction Type :
									- Loading Transaction   ( 0x00 )
									- Purchase Transaction  ( 0x01 )
									- Purchase cancellation ( 0x02 )

*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;			                    // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_GET_EP_STATUS;

giCSCTrame[4]=Type;								// Purchase Type

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}





/****************************************************************/
void iCD97_ReloadEP(BYTE* ChargLog1,BYTE* ChargLog2)
/*****************************************************************
CD97 Command
Reload Electronic Purse

INPUTS
	ChargLog1		 : Loading Log record ( 5 characters )
								 ( Date, Money batch, Equipment type )

	ChargLog2		 : Loading Log record, offset [0x08..0x13]
								 ( 5 characters ) ( Amount, Time )

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;					            // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_RELOAD_EP;

for(i=0; i < 5; i++)
  giCSCTrame[i+4]= *(ChargLog1+i);              // memcopy of ChargLog1

for(i=0; i < 5; i++)
  giCSCTrame[i+9]= *(ChargLog2+i);              // memcopy of ChargLog2

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_CancelPurchase(BYTE Type,BYTE* DataLog,BYTE* Disp)
/*****************************************************************
CD97 Command
Cancel Purchase with the Electronic Purse ( EP )

INPUTS
	Type				 : Purchase Type :
									- Purchase without display ( 0x00 )
									- Purchase with display		 ( 0x01 )
	DataLog      : EP Log record ( 7 bytes )
	Disp				 : Display Message

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command

giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_CANCEL_PURCHASE;

giCSCTrame[4]=Type;								// Purchase Type

for(i=0; i < 7; i++)
  giCSCTrame[i+5]= *(DataLog+i);                // memcopy of DataLog

if(Type==0)	 // without Display Message
{
	giCSCTrame[1]=10;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[12]=0x00;					// End of Command
		giCSCTrameLn=13;
	}
	else{
		giCSCTrameLn=12;
	}
}
else				 // with Display Message
	{
	for(i=0; i < 6; i++)
		giCSCTrame[i+12]= *(Disp+i);			// memcopy of Disp
	giCSCTrame[1]=16;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[18]=0x00;					// End of Command
		giCSCTrameLn=19;
	}
	else{
		giCSCTrameLn=18;
	}
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE)		icsc_SetCRC();
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iCD97_OpenSecuredSession(BYTE Type,BYTE SID,BYTE NREC)
/*****************************************************************
CD97 Command
Open the Secured Session


INPUTS
	Type			 : Operation type
								- Personnalization  ( 0x00 )
								- Reloading         ( 0x01 )
	SID				 : SID Number ( CD97_SID_RT_JOURNAL, ...)
	NREC			 : Record number

*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=5;					            // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_OPEN_SECURED_SESSION;

giCSCTrame[4]=Type;								// Operation type
giCSCTrame[5]=SID;								// Small ID File
giCSCTrame[6]=NREC;								// Record number

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;							// End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCD97_OpenSecuredSessionExt(BYTE pType, BYTE pSID, BYTE pRecNum, BYTE pTypeCmd, BYTE pKEYNumKIF, BYTE pKVC, BYTE pMode)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;						// EXEC Command
	giCSCTrame[j++]=0;									// Length
	giCSCTrame[j++]=CSC_CLA_CD97;						// CD97 class
	giCSCTrame[j++]=CSC_CD97_OPEN_SECURED_SESSION;
	giCSCTrame[j++]=pType;								// Data
	giCSCTrame[j++]=pSID;								// Data
	giCSCTrame[j++]=pRecNum;							// Data
	giCSCTrame[j++]=pTypeCmd;							// Data
	giCSCTrame[j++]=pKEYNumKIF;							// Data
	giCSCTrame[j++]=pKVC;								// Data
	giCSCTrame[j++]=pMode;								// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCD97_CloseSecuredSession(void)
/*****************************************************************
Close the Secured Session
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x02;						        // Length
giCSCTrame[2]=CSC_CLA_CD97;						// CD97 class
giCSCTrame[3]=CSC_CD97_CLOSE_SECURED_SESSION;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[4]=0x00;                             // End of Command
	giCSCTrameLn=5;
	icsc_SetCRC();
}
else{
	giCSCTrame[4]=0x00;                             // End of Command
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCD97_CloseSecuredSessionExt(BYTE pTypeCmd, BYTE pTimeOut)
/*****************************************************************
Close the secured session

INPUT
	pTypeCmd  : Type Cmd
				$00 : session will be ratified at the reception of the following command
				$80 : session is ratified immediately (except for CD97 and GTML)
				$4A : switches OFF the field if the card doesn’t answer
	pTimeOut	 : if TYPE=$4A 

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;						// EXEC Command
	giCSCTrame[j++]=0;									// Length
	giCSCTrame[j++]=CSC_CLA_CD97;						// CD97 class
	giCSCTrame[j++]=CSC_CD97_CLOSE_SECURED_SESSION;
	giCSCTrame[j++]=pTypeCmd;							// Data
	giCSCTrame[j++]=pTimeOut;							// Data


	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iCD97_AbortSecuredSession(void)
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=0x02;						    // Length
	giCSCTrame[j++]=CSC_CLA_CD97;                   // System class
	giCSCTrame[j++]=CSC_CD97_ABORT_SECURED_SESSION;

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCD97_SelectISOApplication(BYTE pSelectOption, BYTE pLg, LPBYTE pData)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;						// EXEC Command
	giCSCTrame[j++]=0x02;						        // Length
	giCSCTrame[j++]=CSC_CLA_CD97;						// System class
	giCSCTrame[j++]=CSC_CD97_SELECT_ISO_APPLICATION;
	giCSCTrame[j++]=pSelectOption;						// Data
	giCSCTrame[j++]=pLg;								// Data
	for(i=0; i < pLg; i++, j++)
	  giCSCTrame[j]= *(pData+i);						// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/*****************************************************************
GTML Command ( Class 2 CSC orders )
*****************************************************************/

/****************************************************************/
void iCD97_ToGTML(void)
/*****************************************************************
Change the class for a GTML card
*****************************************************************/
{
if(giCSCTrameLn>=5)
	{
	giCSCTrame[2]=CSC_CLA_GTML;					// GTML class
	giCSCTrameLn-=2;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE)		icsc_SetCRC();
	giCSCStatus=iCSC_OK;
	}
}




/*****************************************************************
Variable Mapping Card : Generic Command ( Class 5 CSC orders )
*****************************************************************/

/****************************************************************/
void iGEN_AppendRecord(BYTE AccMode,BYTE SID,ulong LID,
									 BYTE NKEY,BYTE RUF,
									 BYTE *Data,BYTE DataLen)
/*****************************************************************
Generic Command
Add a record to a circular EF

INPUTS
  AccMode	 : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID		 : Short ID ( ex. CD97_SID_RT_JOURNAL, ...)
  LID		 : Long ID
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC
  Data       : Data to write
  DataLen    : The size of data to write

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+9;                        // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_APPEND_RECORD;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number

giCSCTrame[6]=DataLen;                          // data length
for(i=0; i < DataLen; i++)
  giCSCTrame[i+7]= *(Data+i);                   // memcopy of data

giCSCTrame[DataLen+7]=(BYTE)((LID/256)&0xFF);	// LID ( bits 15 -  8 )
giCSCTrame[DataLen+8]=(BYTE)(LID&0xFF);		// LID ( bits  7 -  0 )
giCSCTrame[DataLen+9]=NKEY;						// SAM Key Number or KIF (in future)
giCSCTrame[DataLen+10]=RUF;						// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+11]=0x00;                    // End of Command
	giCSCTrameLn=DataLen+12;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+11;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iChangeKey(BYTE pKeyIndex, BYTE pKeyIndexEncipher, BYTE pNewKeyVersion, 
				BYTE pALGTag, BYTE pALGSam, BYTE pNewKeyIndex)
/*****************************************************************
Change the key / Personnalization

INPUTS
	pKeyIndex			: Index of the key ( 01 - 03 )
	pKeyIndexEncipher	: Index of the key to encipher the transfer
	pNewKeyVersion		: New version of the key ( <> 0 )
	pALGTag				: Algo key card to recopy
	pALGSam				: Algo of the Sam used
	pNewKeyIndex		: index of the new key in the card in the DF

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command
	giCSCTrame[j++]=0;								// Length
	giCSCTrame[j++]=CSC_CLA_GEN;					// Generic class
	giCSCTrame[j++]=CSC_GEN_CHANGE_KEY;
	giCSCTrame[j++]=0x05;
	giCSCTrame[j++]=pKeyIndex;						// Data
	giCSCTrame[j++]=pKeyIndexEncipher;				// Data
	giCSCTrame[j++]=pNewKeyVersion;					// Data
	giCSCTrame[j++]=pALGTag;						// Data
	giCSCTrame[j++]=pALGSam;						// Data
	giCSCTrame[j++]=pNewKeyIndex;					// Data


	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_ChangePIN(BYTE* OldPIN,BYTE* NewPIN,
								  BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
PIN modification

INPUTS
  OldPIN	 : Old PIN code ( 4 characters )
  NewPIN     : New PIN code ( 4 characters )
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=14;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_CHANGE_PIN;

giCSCTrame[4]=0x04;								// Pin modification 
												// ( the current DF = 3F00 )

giCSCTrame[5]=0x00;								// RFU

for(i=0; i < 4; i++)
  giCSCTrame[i+6]= *(OldPIN+i);                 // memcopy of OldPIN

for(i=0; i < 4; i++)
  giCSCTrame[i+10]= *(NewPIN+i);                // memcopy of NewPIN

giCSCTrame[14]=NKEY;							// SAM Key Number or KIF (in future)
giCSCTrame[15]=RUF;								// KVC (in future)


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[16]=0x00;							// End of Command
	giCSCTrameLn=17;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=16;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_Decrease(BYTE AccMode,BYTE SID,ulong LID,
								 BYTE ICount,ulong Value,
								 BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Decrease a counter file value

INPUTS
  AccMode	 : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID		 : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  LID		 : Long ID
  ICount	 : Index of the Counter in the file (SID)
  Value		 : Value decreased
  NKEY		 : Number of Key which use in the SAM (in future KIF)
  RUF		 : Reserved for KVC

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_DECREASE;

giCSCTrame[4]=AccMode;							// Card Access Mode
giCSCTrame[5]=SID;								// Small ID file number

giCSCTrame[6]=(BYTE)((Value/65536)&0xFF);		// value ( bits 23 - 16 )
giCSCTrame[7]=(BYTE)((Value/256)&0xFF);			// value ( bits 15 -  8 )
giCSCTrame[8]=(BYTE)(Value&0xFF);				// value ( bits  7 -  0 )

giCSCTrame[9]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[10]=(BYTE)(LID&0xFF);				// LID ( bits  7 -  0 )

giCSCTrame[11]=ICount;							// Counter Index

giCSCTrame[12]=NKEY;							// SAM Key Number or KIF (in future)
giCSCTrame[13]=RUF;								// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iGEN_Increase(BYTE AccMode,BYTE SID,ulong LID,
								 BYTE ICount,ulong Value,
								 BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Increase a counter file value

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID	  : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  LID	  : Long ID
  ICount  : Index of the Counter in the file (SID)
  Value	  : Value decreased
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_INCREASE;

giCSCTrame[4]=AccMode;							// Card Access Mode
giCSCTrame[5]=SID;								// Small ID file number

giCSCTrame[6]=(BYTE)((Value/65536)&0xFF);		// value ( bits 23 - 16 )
giCSCTrame[7]=(BYTE)((Value/256)&0xFF);			// value ( bits 15 -  8 )
giCSCTrame[8]=(BYTE)(Value&0xFF);				// value ( bits  7 -  0 )

giCSCTrame[9]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[10]=(BYTE)(LID&0xFF);				// LID ( bits  7 -  0 )

giCSCTrame[11]=ICount;							// Counter Index

giCSCTrame[12]=NKEY;							// SAM Key Number or KIF (in future)
giCSCTrame[13]=RUF;								// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_DecreaseLG(BYTE pAccMode,BYTE pSID,WORD pLID,
					BYTE pICount,LPBYTE pValue,
					BYTE pNKEY,BYTE pRUF)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;						// EXEC Command
	giCSCTrame[j++]=12;									// Length
	giCSCTrame[j++]=CSC_CLA_GEN;						// Generic class
	giCSCTrame[j++]=CSC_GEN_DECREASELG;

	giCSCTrame[j++]=pAccMode;							// Card Access Mode
	giCSCTrame[j++]=pSID;								// Small ID file number

	for(i=0; i < 8; i++, j++)
		 giCSCTrame[j]= *(pValue+i);					// memcopy of parameter 

	giCSCTrame[j++]=(BYTE)((pLID&0xFF00)>>8);			// LID ( bits 15 -  8 )
	giCSCTrame[j++]=(BYTE)(pLID&0xFF);					// LID ( bits  7 -  0 )

	giCSCTrame[j++]=pICount;							// Counter Index

	giCSCTrame[j++]=pNKEY;								// SAM Key Number or KIF (in future)
	giCSCTrame[j++]=pRUF;								// KVC (in future)

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_IncreaseLG(BYTE pAccMode,BYTE pSID,WORD pLID,
					BYTE pICount,LPBYTE pValue,
					BYTE pNKEY,BYTE pRUF)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;						// EXEC Command
	giCSCTrame[j++]=12;									// Length
	giCSCTrame[j++]=CSC_CLA_GEN;						// Generic class
	giCSCTrame[j++]=CSC_GEN_INCREASELG;

	giCSCTrame[j++]=pAccMode;							// Card Access Mode
	giCSCTrame[j++]=pSID;								// Small ID file number

	for(i=0; i < 8; i++, j++)
		 giCSCTrame[j]= *(pValue+i);					// memcopy of parameter 

	giCSCTrame[j++]=(BYTE)((pLID&0xFF00)>>8);			// LID ( bits 15 -  8 )
	giCSCTrame[j++]=(BYTE)(pLID&0xFF);					// LID ( bits  7 -  0 )

	giCSCTrame[j++]=pICount;							// Counter Index

	giCSCTrame[j++]=pNKEY;								// SAM Key Number or KIF (in future)
	giCSCTrame[j++]=pRUF;								// KVC (in future)

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iGEN_Invalidate(BYTE AccMode,ulong LID,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Invalidate the current DF

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_PROTECTED, ...)
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=7;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_INVALIDATE;

giCSCTrame[4]=AccMode;							// Card Access Mode

giCSCTrame[5]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[6]=(BYTE)(LID&0xFF);					// LID ( bits  7 -  0 )

giCSCTrame[7]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[8]=RUF;								// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[9]=0x00;							// End of Command
	giCSCTrameLn=10;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=9;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_Rehabilitate(BYTE AccMode,ulong LID,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Rehabilitate the current DF

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_PROTECTED, ...)
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=7;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_REHABILITATE;

giCSCTrame[4]=AccMode;							// Card Access Mode

giCSCTrame[5]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[6]=(BYTE)(LID&0xFF);					// LID ( bits  7 -  0 )

giCSCTrame[7]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[8]=RUF;								// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[9]=0x00;								// End of Command
	giCSCTrameLn=10;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=9;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_ReadRecord(BYTE AccMode,BYTE SID,BYTE NuRec,BYTE DataLen,
											 ulong LID,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Read a record from linear or circular file

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID	  : Small ID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NuRec	  : Record number
  DataLen : Number of bytes to be read ( record length )
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC

*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=10;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic Class
giCSCTrame[3]=CSC_GEN_READ_RECORD;

giCSCTrame[4]=AccMode;							// Card Access Mode
giCSCTrame[5]=SID;								// Small ID file number

giCSCTrame[6]=NuRec;							// Record Number
giCSCTrame[7]=DataLen;							// Number of bytes to be read 

giCSCTrame[8]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[9]=(BYTE)(LID&0xFF);					// LID ( bits  7 -  0 )

giCSCTrame[10]=NKEY;							// SAM Key Number or KIF (in future)
giCSCTrame[11]=RUF;								// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[12]=0x00;							// End of Command
	giCSCTrameLn=13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=12;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_SelectFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=IdPathLen+4;                      // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_SELECT_FILE;

giCSCTrame[4]=SelectMode;						// Select mode

giCSCTrame[5]=IdPathLen;                        // IdPath length
for(i=0; i < IdPathLen; i++)
  giCSCTrame[i+6]= *(IdPath+i);                 // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[IdPathLen+6]=0x00;					// End of Command
	giCSCTrameLn=IdPathLen+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=IdPathLen+6;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_StatusFile(BYTE SelectMode,BYTE* IdPath,BYTE IdPathLen)
/*****************************************************************
Generic Command
Same as iGEN_SelectFile but only give the file status without
select the file

INPUTS
  SelectMode : Select Mode :
					GEN_SEL_MF	( Select the Master file )
					GEN_SEL_CURENT_EF ( Select the curent EF ID )
					GEN_SEL_PATH ( the path from MF ( exclude ) )

  IdPath     : ID number or path from MF ( exclude )
  IdPathLen  : IdPath length

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=IdPathLen+4;                      // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_STATUS;

giCSCTrame[4]=SelectMode;						// Select mode

giCSCTrame[5]=IdPathLen;                        // IdPath length
for(i=0; i < IdPathLen; i++)
  giCSCTrame[i+6]= *(IdPath+i);                 // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[IdPathLen+6]=0x00;					// End of Command
	giCSCTrameLn=IdPathLen+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=IdPathLen+6;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_UpdateRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
									 BYTE *Data,BYTE DataLen,
									 ulong LID,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Erase and write a record to a EF

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID	  : SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NuRec	  : Record number
  Data    : Data to write
  DataLen : The size of data to write
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC


*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+10;                       // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_UPDATE_RECORD;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number
giCSCTrame[6]=NuRec;							// Record Number

giCSCTrame[7]=DataLen;                          // data length
for(i=0; i < DataLen; i++)
  giCSCTrame[i+8]= *(Data+i);                   // memcopy of data


giCSCTrame[DataLen+8]=(BYTE)((LID/256)&0xFF);	// LID ( bits 15 -  8 )
giCSCTrame[DataLen+9]=(BYTE)(LID&0xFF);			// LID ( bits  7 -  0 )

giCSCTrame[DataLen+10]=NKEY;					// SAM Key Number or KIF (in future)
giCSCTrame[DataLen+11]=RUF;						// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+12]=0x00;                    // End of Command
	giCSCTrameLn=DataLen+13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+12;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_WriteRecord(BYTE AccMode,BYTE SID,BYTE NuRec,
									BYTE *Data,BYTE DataLen,
									ulong LID,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Write a record to a EF

INPUTS
  AccMode : Card Access Mode ( GEN_ACCESS_MODE_DEFAULT, ...)
  SID	  : SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NuRec	  : Record number
  Data    : Data to write
  DataLen : The size of data to write
  LID	  : Long ID
  NKEY	  : Number of Key which use in the SAM (in future KIF)
  RUF	  : Reserved for KVC

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=DataLen+10;                       // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_WRITE_RECORD;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number
giCSCTrame[6]=NuRec;							// Record Number

giCSCTrame[7]=DataLen;                          // data length
for(i=0; i < DataLen; i++)
  giCSCTrame[i+8]= *(Data+i);                   // memcopy of data

giCSCTrame[DataLen+8]=(BYTE)((LID/256)&0xFF);	// LID ( bits 15 -  8 )
giCSCTrame[DataLen+9]=(BYTE)(LID&0xFF);			// LID ( bits  7 -  0 )

giCSCTrame[DataLen+10]=NKEY;					// SAM Key Number or KIF (in future)
giCSCTrame[DataLen+11]=RUF;						// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[DataLen+12]=0x00;                    // End of Command
	giCSCTrameLn=DataLen+13;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=DataLen+12;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iGEN_VerifyPIN(BYTE* PIN,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
PIN verification

INPUTS
  PIN	  : PIN code ( 4 characters )
  NKEY	  : Number of Key which use in the SAM (in future KIF)
			If NKEY=0 => presentation in clear mode
  RUF	  : Reserved for KVC

*****************************************************************/
{
int i;
BYTE	mode;									// presentation mode
												// of PIN code
if (NKEY==0x00)
{
	mode=0x02;		// presentation intransparent mode
}
else
{
	mode=0x01;		// presentation in crypted mode
}

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=9;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_VERIFY_PIN;

giCSCTrame[4]=mode;								// PIN Presentation mode

for(i=0; i < 4; i++)
  giCSCTrame[i+5]= *(PIN+i);                    // memcopy of PIN

giCSCTrame[9]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[10]=RUF;								// KVC (in future)


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[11]=0x00;							// End of Command
	giCSCTrameLn=12;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=11;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iGEN_PINStatus()
/*****************************************************************
Generic Command
checks PIN presentation status

INPUTS
	none

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=9;				                // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_VERIFY_PIN;

giCSCTrame[4]=0x00;								// consultation of incorrect presentations

for(i=0; i < 4; i++)
  giCSCTrame[i+5]= 0x00;	                    // no PIN (0x00 .... 0x00)

giCSCTrame[9]=0x00;								// no key
giCSCTrame[10]=0x00;							// KVC (in future)


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[11]=0x00;						// End of Command
	giCSCTrameLn=12;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=11;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_Purchase(BYTE Type,BYTE* DataLog,BYTE* Disp)
/*****************************************************************
Generic Command
Purchase with the Electronic Purse ( EP )

INPUTS
  Type     : Purchase Type :
					- Purchase without display ( 0x00 )
					- Purchase with display	( 0x01 )
  DataLog  : EP Log record ( 7 bytes )
  Disp	   : Display Message

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command

giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_PURCHASE;

giCSCTrame[4]=Type;								// Purchase Type

for(i=0; i < 7; i++)
  giCSCTrame[i+5]= *(DataLog+i);                // memcopy of DataLog

if(Type==0)										// without Display Message
{
	giCSCTrame[1]=10;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[12]=0x00;					// End of Command
		giCSCTrameLn=13;
	}
	else{
		giCSCTrameLn=12;
	}
}
else											// with Display Message
{
	for(i=0; i < 6; i++)
		giCSCTrame[i+12]= *(Disp+i);			// memcopy of Disp
	giCSCTrame[1]=16;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[18]=0x00;						// End of Command
		giCSCTrameLn=19;
	}
	else{
		giCSCTrameLn=18;
	}
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE)		icsc_SetCRC();
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_GetEPStatus(BYTE Type,BYTE NKEY,BYTE RUF)
/*****************************************************************
Generic Command
Purchase with the Electronic Purse ( EP )

INPUTS
  Type : Transaction Type :
				- Loading Transaction   ( 0x00 )
				- Purchase Transaction  ( 0x01 )
				- Purchase cancellation ( 0x02 )
  NKEY : Number of Key which use in the SAM (in future KIF)
  RUF  : Reserved for KVC

*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=5;			                    // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_GET_EP_STATUS;

giCSCTrame[4]=Type;								// Purchase Type

giCSCTrame[5]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[6]=RUF;								// KVC (in future)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;								// End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}
giCSCStatus=iCSC_OK;
}





/****************************************************************/
void iGEN_ReloadEP(BYTE* ChargLog1,BYTE* ChargLog2)
/*****************************************************************
Generic Command
Reload Electronic Purse

INPUTS
  ChargLog1 : Loading Log record ( 5 characters )
			  ( Date, Money batch, Equipment type )

  ChargLog2 : Loading Log record, offset [0x08..0x13]
		      ( 5 characters ) ( Amount, Time )

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=12;					            // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_RELOAD_EP;

for(i=0; i < 5; i++)
  giCSCTrame[i+4]= *(ChargLog1+i);              // memcopy of ChargLog1

for(i=0; i < 5; i++)
  giCSCTrame[i+9]= *(ChargLog2+i);              // memcopy of ChargLog2

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[14]=0x00;							// End of Command
	giCSCTrameLn=15;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=14;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_CancelPurchase(BYTE Type,BYTE* DataLog,BYTE* Disp)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command

giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_CANCEL_PURCHASE;

giCSCTrame[4]=Type;								// Purchase Type

for(i=0; i < 7; i++)
  giCSCTrame[i+5]= *(DataLog+i);                // memcopy of DataLog

if(Type==0)			// without Display Message
{
	giCSCTrame[1]=10;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[12]=0x00;						// End of Command
		giCSCTrameLn=13;
	}
	else{
		giCSCTrameLn=12;
	}
}
else				// with Display Message
	{
	for(i=0; i < 6; i++)
		giCSCTrame[i+12]= *(Disp+i);			// memcopy of Disp
	giCSCTrame[1]=16;			                // Length
	if (giCRCNeeded == TRUE){
		giCSCTrame[18]=0x00;						// End of Command
		giCSCTrameLn=19;
	}
	else{
		giCSCTrameLn=18;
	}
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE)		icsc_SetCRC();
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_OpenSecuredSession(BYTE Type,BYTE SID,BYTE NREC,
							 BYTE NKEY,BYTE RUF,BYTE Mode)
/*****************************************************************
Generic Command
Open the Secured Session


INPUTS
  Type	 : Operation type
				- Personnalization  ( 0x00 )
				- Reloading ( 0x01 )
				- Validation ( 0x02 )
  SID	 : SID Number ( ex. CD97_SID_RT_JOURNAL, ...)
  NREC	 : Record number
  NKEY	 : Number of Key which use in the SAM (in future KIF)
  RUF	 : Reserved for KVC
  MODE   : Working mode :
				- Simple  ( 0x00 )
				- Extended ( 0x01 )
	
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=8;					            // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_OPEN_SECURED_SESSION;

giCSCTrame[4]=Type;								// Operation type
giCSCTrame[5]=SID;								// Small ID File
giCSCTrame[6]=NREC;								// Record number

giCSCTrame[7]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[8]=RUF;								// KVC (in future)

giCSCTrame[9]=Mode;								// Working mode (according to the card)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[10]=0x00;							// End of Command
	giCSCTrameLn=11;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=10;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_CloseSecuredSession(void)
/*****************************************************************
Close the Secured Session
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x02;						        // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_CLOSE_SECURED_SESSION;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[4]=0x00;                             // End of Command
	giCSCTrameLn=5;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=4;
}
giCSCStatus=iCSC_OK;
}




/****************************************************************/
void iGEN_AbortSecuredSession()
/*****************************************************************
Stop the current certification session. This still allow to continue a dialogue with the badge and, in particular, open a new session

INPUTS
	-
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x02;						        // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_ABORT_SECURED_SESSION;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[4]=0x00;                             // End of Command
	giCSCTrameLn=5;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=4;
}
giCSCStatus=iCSC_OK;
}



/****************************************************************/
void iGEN_Lock_Unlock(BYTE Type)
/*****************************************************************
Generic Command
Lock Unlock the card


INPUTS
  Type	 : Operation type
				- Lock the card ( 0x00 )
				- Unlock the card ( 0x01 )
	
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;					            // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_LOCK_UNLOCK;

giCSCTrame[4]=Type;								// Operation type

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_MultiDecrease(BYTE AccMode,BYTE SID,ulong LID,BYTE NKEY,BYTE RUF,
						BYTE NbCnt,BYTE *Data)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=(NbCnt*4)+9;					    // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_DECREASE_MULTIPLE;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number
giCSCTrame[6]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[7]=(BYTE)(LID&0xFF);					// LID ( bits  7 -  0 )

giCSCTrame[8]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[9]=RUF;								// KVC (in future)

giCSCTrame[10]=NbCnt;							// Number of counter to decrease

for(i=0; i < (NbCnt*4); i++)
  giCSCTrame[i+11]= *(Data+i);                  // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[(NbCnt*4)+11]=0x00;                  // End of Command
	giCSCTrameLn=(NbCnt*4)+12;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=(NbCnt*4)+11;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_MultiIncrease(BYTE AccMode,BYTE SID,ulong LID,BYTE NKEY,BYTE RUF,
						BYTE NbCnt,BYTE *Data)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=(NbCnt*4)+9;					    // Length
giCSCTrame[2]=CSC_CLA_GEN;						// Generic class
giCSCTrame[3]=CSC_GEN_INCREASE_MULTIPLE;

giCSCTrame[4]=AccMode;							// Access mode
giCSCTrame[5]=SID;								// SID number
giCSCTrame[6]=(BYTE)((LID/256)&0xFF);			// LID ( bits 15 -  8 )
giCSCTrame[7]=(BYTE)(LID&0xFF);					// LID ( bits  7 -  0 )

giCSCTrame[8]=NKEY;								// SAM Key Number or KIF (in future)
giCSCTrame[9]=RUF;								// KVC (in future)

giCSCTrame[10]=NbCnt;							// Number of counter to increase

for(i=0; i < (NbCnt*4); i++)
  giCSCTrame[i+11]= *(Data+i);                  // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[(NbCnt*4)+11]=0x00;                  // End of Command
	giCSCTrameLn=(NbCnt*4)+12;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=(NbCnt*4)+11;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCTx_Active(void)
/*****************************************************************
Read CTS

INPUTS
	Nothing
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=2;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_ACTIVE;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[4]=0x00;								// End of Command
	giCSCTrameLn=5;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=4;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCTx_Read(BYTE ADD, BYTE NB)
/*****************************************************************
Read CTx

INPUTS
	ADD		: adress of the first read (0 ... 31)
	NB		: Number of bytes to be read (from 1 up to 32)
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_READ;

giCSCTrame[4]=ADD;								// adress of the first read
giCSCTrame[5]=NB;								// Number of bytes to be read

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// End of Command
	giCSCTrameLn=7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_Update(BYTE ADD, BYTE NB, BYTE *Data, BYTE *DataInCTS)
/*****************************************************************
Update CTS

INPUTS
	ADD			: adress of the first byte to write (0 ... 31)
	NB			: Number of bytes to be written (from 1 up to 32)
	Data		: Data to write
	DataInCTS	: Data already read and store in CTS application

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=2*NB+4;				            // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_UPDATE;

giCSCTrame[4]=ADD;								// adress of the first read
giCSCTrame[5]=NB;								// Number of bytes to be read

for(i=0; i < NB; i++)
  giCSCTrame[i+6]= *(Data+i);                   // memcopy of data

for(i=0; i < NB; i++)
  giCSCTrame[i+NB+6]= *(DataInCTS+i);           // memcopy of data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[NB+NB+6]=0x00;						// End of Command
	giCSCTrameLn=2*NB+7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=2*NB+6;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCTx_Release(BYTE Param)
/*****************************************************************
Release CTx

INPUTS
	Param
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_RELEASE;

giCSCTrame[4]=Param;

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_CheckCertificate(BYTE KeyType, BYTE Param, BYTE LngBuffer, BYTE *Buffer,
							BYTE LngCertificat, BYTE *Certificat)
/*****************************************************************
Check Certificate

INPUTS
	KeyType
	Param	(RFU)
	LngBuffer
	Buffer
	LngCertificat
	Certificat
*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=6+LngBuffer+LngCertificat;        // Length
giCSCTrame[2]=CSC_CLA_CERTIF;					// Certificat class
giCSCTrame[3]=CSC_CheckCertificat;

giCSCTrame[4]=KeyType;
giCSCTrame[5]=Param;
giCSCTrame[6]=LngBuffer;

for (i=0; i<LngBuffer; i++) 
	giCSCTrame[7+i]=Buffer[i];

giCSCTrame[7+LngBuffer]= LngCertificat;							
for (i=0; i<LngCertificat; i++) 
	giCSCTrame[8+LngBuffer+i]=Certificat[i];

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[8+LngBuffer+LngCertificat]=0x00;		// End of Command
	giCSCTrameLn=9+LngBuffer+LngCertificat;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=8+LngBuffer+LngCertificat;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iGEN_GiveCertificate(BYTE KeyType, BYTE Param, BYTE LngBuffer, BYTE *Buffer,
							BYTE LngCertificat)
/*****************************************************************
Give Certificate

INPUTS
	KeyType
	Param	(RFU)
	LngBuffer
	Buffer
	LngCertificat
*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=6+LngBuffer;						// Length
giCSCTrame[2]=CSC_CLA_CERTIF;					// Certificat class
giCSCTrame[3]=CSC_GiveCertificat;

giCSCTrame[4]=KeyType;
giCSCTrame[5]=Param;
giCSCTrame[6]=LngBuffer;

for (i=0; i<LngBuffer; i++) 
	giCSCTrame[7+i]=Buffer[i];

giCSCTrame[7+LngBuffer]= LngCertificat;							

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[8+LngBuffer]=0x00;					// End of Command
	giCSCTrameLn=9+LngBuffer;
	icsc_SetCRC();
}
else{
giCSCTrameLn=8+LngBuffer;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_ChangeCSCSpeed(BYTE RS232Speed,BYTE RS485Speed, BYTE TTLSpeed)
/*****************************************************************
Starts the search of a card

INPUTS
  RS232Speed :	// RS232 Divider for Baud rate
  RS485Speed :	// RS485 Divider for Baud rate
  TTLSpeed :	// serial TTL Divider for Baud rate
  
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=0x05;                             // Length
giCSCTrame[2]=CSC_CLA_DOWNLOAD;					// Download class
giCSCTrame[3]=CSC_DOW_CHANGE;					// Change Command
giCSCTrame[4]=RS232Speed;                       // RS232 Divider for Baud rate
giCSCTrame[5]=RS485Speed;                       // RS485 Divider for Baud rate
giCSCTrame[6]=TTLSpeed;                         // TTL   Divider for Baud rate

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;                             // End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
BYTE icsc_ConvertBaudRateInDivider(ulong BaudRate)
/*****************************************************************
convert Host-CSC communication BaudRate In Divider for ST9 device

INPUTS
  The Baud rate to be converted in divider.
OUTPUTS
  None
RETURN
  0 if the input value isnot allowed
  The divider value otherwise.
*****************************************************************/
{

	return((BYTE) (22118400/16/BaudRate) );
}


/*****************************************************************/
void iCSC_SelectCID(BYTE CID)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  CID :	Index from 1 to 15 of the ISO14443 Card communication channel
OUTPUTS
	None 
  
*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_SYSTEM;					// SYSTEM class
giCSCTrame[j++]=CSC_SYS_SELECT_CID;				// SYSTEM Command
giCSCTrame[j++]=CID;							// Data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;								// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;									// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iCSC_SelectDIV(BYTE Slot, BYTE Prot, BYTE *DIV)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Slot :	Slot of the SAM
  Prot :	0 for Innovatron, 1 for ISO7816
  DIV :		4 bytes serial number used for alg diversification
OUTPUTS
	None 
  
*****************************************************************/
{
int i;
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_SYSTEM;					// SYSTEM class
giCSCTrame[j++]=CSC_SYS_SELECT_DIV;				// SYSTEM Command
giCSCTrame[j++]=Slot;							// Data 
giCSCTrame[j++]=Prot;							// Data 
for(i=0; i < 4; i++, j++)
  giCSCTrame[j]= *(DIV+i);						// memcopy of parameter 


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;								// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;									// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iCSC_EHP_PARAMS(BYTE MaxNbCard, BYTE Req, BYTE NbSlot, BYTE AFI, BYTE AutoSelDiv)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  Slot :	Slot of the SAM
  Prot :	0 for Innovatron, 1 for ISO7816
  DIV :		4 bytes serial number used for alg diversification
OUTPUTS
	None 
  
*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_SYSTEM;					// SYSTEM class
giCSCTrame[j++]=CSC_SYS_EHP_PARAMS;				// SYSTEM Command
giCSCTrame[j++]=MaxNbCard;						// Data
giCSCTrame[j++]=Req;							// Data
giCSCTrame[j++]=NbSlot;							// Data
giCSCTrame[j++]=AFI;							// Data
giCSCTrame[j++]=AutoSelDiv;						// Data

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;								// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;									// lenght adjustment
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iCSC_EHP_PARAMS_EXT (BYTE pMaxNbCard, BYTE pReq, BYTE pNbSlot, BYTE pAFI, BYTE pAutoSelDiv, 
							BYTE pDeselect, BYTE pSelectAppli, BYTE pLg, LPBYTE pData, 
							WORD pFelicaAFI, BYTE pFelicaNbSlot)
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
{
	int i, j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   	// EXEC Command Code
	giCSCTrame[j++]=0;					            	// Length
	giCSCTrame[j++]=CSC_CLA_SYSTEM;						// SYSTEM class
	giCSCTrame[j++]=CSC_SYS_EHP_PARAMS;					// SYSTEM Command
	giCSCTrame[j++]=pMaxNbCard;							// Data
	giCSCTrame[j++]=pReq;								// Data
	giCSCTrame[j++]=pNbSlot;							// Data
	giCSCTrame[j++]=pAFI;								// Data
	giCSCTrame[j++]=pAutoSelDiv;						// Data
	giCSCTrame[j++]=pDeselect;							// Data
	giCSCTrame[j++]=pSelectAppli;						// Data
	giCSCTrame[j++]=pLg;								// Data
	for(i=0; i < pLg; i++, j++)
	  giCSCTrame[j]= *(pData+i);						// memcopy of parameter 
	giCSCTrame[j++]=(BYTE)((pFelicaAFI & 0xFF00)>>8);			// Data
	giCSCTrame[j++]=(BYTE)(pFelicaAFI & 0xFF);					// Data
	giCSCTrame[j++]=pFelicaNbSlot;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE){
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;								// lenght adjustment
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else{
		giCSCTrameLn=j;									// lenght adjustment
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_LoadReaderKeyIndex(BYTE KeyIndex, BYTE *KeyVal)
/*****************************************************************
Update the global buffer for the SendReceive command.

INPUTS
  KeyIndex :	Index from 0 to 31 of the key to load in the Reader
  KeyVal :		Value of the key (6 bytes LSB First)
OUTPUTS
	None 
  
*****************************************************************/
{
int i;
int j=0;

if (KeyIndex < 31)
{
      giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
      giCSCTrame[j++]=0;                                         // Length
      giCSCTrame[j++]=CSC_CLA_MIFARE;                            // MIFARE class
      giCSCTrame[j++]=CSC_INS_RC500;                             // MIFARE Command
      giCSCTrame[j++]=0x08;                                      // Lenght of the Sub Command
      giCSCTrame[j++]=CSC_MIFARE_LOADKEY;                  // MIFARE Sub Command
      giCSCTrame[j++]=KeyIndex;                                  // single byte parameter

      for(i=0; i < 6; i++, j++)
        giCSCTrame[j]= *(KeyVal+i);                        // memcopy of parameter 
}
else
{
      giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
      giCSCTrame[j++]=0;                                         // Length
      giCSCTrame[j++]=CSC_CLA_MIFARE;                            // MIFARE class
      giCSCTrame[j++]=CSC_INS_RC500;                             // MIFARE Command
      giCSCTrame[j++]=0x07;                                      // Lenght of the Sub Command
      giCSCTrame[j++]=0x0B;                                      // MIFARE Sub Command

      for(i=0; i < 6; i++, j++)
        giCSCTrame[j]= *(KeyVal+5-i);                            
}



// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
      giCSCTrame[j]=0x00;                                              // End of Command
      giCSCTrameLn=j+1;
      giCSCTrame[1] = giCSCTrameLn-3;                            // Update Command lenght
      icsc_SetCRC();
}
else{
      giCSCTrameLn=j;
      giCSCTrame[1] = giCSCTrameLn-2;                            // Update Command lenght
}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_ChangeKey(BYTE InitialKeyAorB, BYTE NumSector, BYTE InitialKeyIndex, 
			BYTE FinalKeyAorB, BYTE *NewKeyA, BYTE *NewAccessBits, BYTE *NewKeyB)
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
	None 

*****************************************************************/
{
int i;
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_CHANGEKEY;			// MIFARE instruction
giCSCTrame[j++]=0x14;							// parameter lenght
giCSCTrame[j++]=InitialKeyAorB;					// single byte parameter 
giCSCTrame[j++]=NumSector;						// single byte parameter 
giCSCTrame[j++]=InitialKeyIndex;				// single byte parameter 
for(i=0; i < 6; i++, j++)
  giCSCTrame[j]= *(NewKeyA+i);					// memcopy of parameter 
for(i=0; i < 4; i++, j++)
  giCSCTrame[j]= *(NewAccessBits+i);			// memcopy of parameter 
for(i=0; i < 6; i++, j++)
  giCSCTrame[j]= *(NewKeyB+i);					// memcopy of parameter 
giCSCTrame[j++]=FinalKeyAorB;					// single byte parameter 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}


/****************************************************************/
void iMIFARE_Select(BYTE* SerialNumber, BYTE SerialNumberLn)
/*****************************************************************
MIFARE Command
Selects a mifare card with its unique serial number

INPUTS
	Serial Number : buffer containing the serial number of the card to detect.
	SerialNumberLn:	length of the serial number

*****************************************************************/
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=6;				                // Length
giCSCTrame[2]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[3]=CSC_MIFARE_SELECT;				// INS = select

for(i=0; i < SerialNumberLn; i++)
  giCSCTrame[i+4]= SerialNumber[i];	            // copy serial number

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[8]=0x00;								// End of Command						
	giCSCTrameLn=5 + SerialNumberLn;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=4 + SerialNumberLn;
}
giCSCStatus=iCSC_OK;
}



/*****************************************************************/
void iMIFARE_Detect()
/*****************************************************************
Detect the Mifare Card present in the antenna field  

INPUTS
	-  

OUTPUTS
	None 

*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_DETECT;				// MIFARE instruction

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_Authenticate(BYTE NumSector, BYTE KeyAorB, BYTE KeyIndex)
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
	None 

*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_AUTHENTICATE;		// MIFARE instruction
giCSCTrame[j++]=0x03;							// parameter length  
giCSCTrame[j++]=KeyAorB;						// single byte parameter 
giCSCTrame[j++]=NumSector;						// single byte parameter 
giCSCTrame[j++]=KeyIndex;						// single byte parameter 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_Halt(void)
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	None  
OUTPUTS
	None 

*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_HALT;				// MIFARE instruction 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_ReadBlock(BYTE NumBlock)
/*****************************************************************
Read a block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 
OUTPUTS
	None 

*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_READBLOCK;			// MIFARE instruction 
giCSCTrame[j++]=0x01;							// parameter length
giCSCTrame[j++]=NumBlock;						// single byte parameter 

giCSCTrame[j]=0x00;								// End of Command
giCSCTrameLn=j+1;

giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_ReadSector(BYTE NumSector, BYTE KeyAorB, BYTE KeyIndex)
/*****************************************************************
Read a block in a MIFARE card : for this operation, the sector is authenticated and read
the authentication can be used for other following operation 
like increment, decrement, writeblock, .../...

INPUTS
	NumSector		:	Sector to authenticate and read
	KeyAorB			:	Choice of the key needed for authentication  
	KeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	none

*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_READSECTOR;			// MIFARE instruction
giCSCTrame[j++]=0x03;							// parameter length
giCSCTrame[j++]=KeyAorB;						// single byte parameter 
giCSCTrame[j++]=NumSector;						// single byte parameter 
giCSCTrame[j++]=KeyIndex;						// single byte parameter 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght

}
giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_WriteBlock(BYTE NumBlock, BYTE *DataToWrite)
/*****************************************************************
Write a block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 
	DataToWrite		:	(16 bytes) Data to write in the block (the whole block is written) 
  
OUTPUTS
	none
	
*****************************************************************/
{
int i;
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_WRITEBLOCK;				// MIFARE instruction
giCSCTrame[j++]=0x11;							// parameter length
giCSCTrame[j++]=NumBlock;						// single byte parameter

for(i=0; i < 16; i++, j++)
  giCSCTrame[j]= *(DataToWrite+i);				// memcopy of parameter 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_DecrementValue(BYTE NumBlock, BYTE *Substract)
/*****************************************************************
Decrement a Value block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 (must be previously configured as a value block)
	Substract		:	(4 bytes) value to substract to the counter 
  
OUTPUTS
	none
	
*****************************************************************/
{
int i;
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_DECREMENT;			// MIFARE instruction
giCSCTrame[j++]=0x05;							// parameter length
giCSCTrame[j++]=NumBlock;						// single byte parameter

for(i=0; i < 4; i++, j++)
  giCSCTrame[j]= *(Substract+i);				// memcopy of parameter 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}

giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_IncrementValue(BYTE NumBlock, BYTE *Addition)
/*****************************************************************
Increment a Value block in a MIFARE card : For this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	NumBlock		:	Block number from 0 to 63 (must be previously configured as a value block)
	Addition		:	(4 bytes) value to Add to the counter 
  
OUTPUTS
	none
	
*****************************************************************/
{
int i;
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_INCREMENT;			// MIFARE instruction
giCSCTrame[j++]=0x05;							// parameter length
giCSCTrame[j++]=NumBlock;						// single byte parameter

for(i=0; i < 4; i++, j++)
  giCSCTrame[j]= *(Addition+i);					// memcopy of parameter 

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}



/*****************************************************************/
void iMIFARE_BackUpRestoreValue(BYTE Origine, BYTE Destination)
/*****************************************************************
Perform a copy of a value block to an other value block location 
in a given sector of a MIFARE card : For this operation, the sector need to
be previously authenticated by an authenticate or read_sector command
The two blocks must be in the same sector

INPUTS
	Origine			:	Block number from 0 to 63 (must be previously configured as a value block)
	Destination		:	Block number from 0 to 63 (must be previously configured as a value block)
  
OUTPUTS
	none
	
*****************************************************************/
{
int j=0;

giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
giCSCTrame[j++]=0;					            // Length
giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
giCSCTrame[j++]=CSC_MIFARE_BACKUPRESTORE;		// MIFARE instruction
giCSCTrame[j++]=0x02;							// parameter length
giCSCTrame[j++]=Origine;						// single byte parameter
giCSCTrame[j++]=Destination;					// single byte parameter


// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;
	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
	icsc_SetCRC();
}
else{
	giCSCTrameLn=j;
	giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
}
giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_ReadMultipleBlock(BYTE pBlockNum, BYTE pNumBlock)
/*****************************************************************
Read Multiple block in a MIFARE card : for this operation, the sector need to
be previously authenticated by an authenticate or read_sector command

INPUTS
	pBlockNum		:	Block number from 0 to 255 
	pNumBlock		:	Number of Block "n"

OUTPUTS
	None 

*****************************************************************/
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
	giCSCTrame[j++]=CSC_MIFARE_READMULTIPLEBLOCK;	// MIFARE instruction 
	giCSCTrame[j++]=0x02;							// parameter length
	giCSCTrame[j++]=pBlockNum;						// single byte parameter 
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 

	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;

	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE){
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SimpleWriteBlock(BYTE pBlockNum, LPBYTE pDataToWrite)
/*****************************************************************
Writes an authenticated block

INPUTS
	pBlockNum			:	Block number from 0 to 255  (1 byte)
	pDataToWrite		:	Data to Write in the selected authenticated block (16 bytes)
  
OUTPUTS
	None 

*****************************************************************/
{
	int i, j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
	giCSCTrame[j++]=CSC_MIFARE_SIMPLEWRITEBLOCK;	// MIFARE instruction 
	giCSCTrame[j++]=0x11;							// parameter length
	giCSCTrame[j++]=pBlockNum;						// single byte parameter 
	for(i=0; i < 16; i++, j++)
		giCSCTrame[j]= *(pDataToWrite+i);			// memcopy of parameter 

	giCSCTrame[j]=0x00;								// End of Command
	giCSCTrameLn=j+1;

	giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE){
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_ReadSectorData(BYTE pKeyAorB, BYTE pNumSector, BYTE pKeyIndex)
/*****************************************************************
Read a the data blocks Sector of the PICC

INPUTS
	pKeyAorB			:	Choice of the key needed for authentication  
	pNumSector		:	Sector to authenticate and read
	pKeyIndex		:	Index from 0 to 31 of the Reader key used for authentication
  
OUTPUTS
	none

*****************************************************************/
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
	giCSCTrame[j++]=CSC_MIFARE_READSECTORDATA;		// MIFARE instruction
	giCSCTrame[j++]=0x03;							// parameter length
	giCSCTrame[j++]=pKeyAorB;						// single byte parameter 
	giCSCTrame[j++]=pNumSector;						// single byte parameter 
	giCSCTrame[j++]=pKeyIndex;						// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE){
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght

	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_WriteSectorData(BYTE pKeyAorB, BYTE pNumSector, BYTE pKeyIndex, LPBYTE pDataToWrite, BYTE pCardType)
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
{
	int i, j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE;					// MIFARE class
	giCSCTrame[j++]=CSC_MIFARE_WRITESECTORDATA;		// MIFARE instruction
	giCSCTrame[j++]=0x33;							// parameter length
	giCSCTrame[j++]=pKeyAorB;						// single byte parameter 
	giCSCTrame[j++]=pNumSector;						// single byte parameter 
	giCSCTrame[j++]=pKeyIndex;						// single byte parameter 
	if(pCardType == 0x08)			// MIFARE 1K
	{
		for(i=0; i < 48; i++, j++)	
			giCSCTrame[j]= *(pDataToWrite+i);		// memcopy of parameter 

		giCSCTrame[4]=0x33;							// MAJ parameter length
	}
	else							// MIFARE 4K
	{
		for(i=0; i < 240; i++, j++)	
			giCSCTrame[j]= *(pDataToWrite+i);		// memcopy of parameter 

		giCSCTrame[4]=0xF3;							// MAJ parameter length
	}

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE){
		giCSCTrame[j]=0x00;								// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;					// Update Command lenght
		icsc_SetCRC();
	}
	else{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;					// Update Command lenght

	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_SAMNXP_Authenticate(BYTE pNumKey, BYTE pVersionKey, BYTE pKeyAorB, 
								 BYTE pNumBlock, BYTE pLgDiversifier, BYTE pBlockDiversifier)
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
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_AUTHENTICATE;	// MIFARE instruction
	giCSCTrame[j++]=pNumKey;						// single byte parameter 
	giCSCTrame[j++]=pVersionKey;					// single byte parameter 
	giCSCTrame[j++]=pKeyAorB;						// single byte parameter 
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	giCSCTrame[j++]=pLgDiversifier;					// single byte parameter 
	giCSCTrame[j++]=pBlockDiversifier;				// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMIFARE_SAMNXP_ReAuthenticate(BYTE pNumKey, BYTE pVersionKey, BYTE pKeyAorB, 
								   BYTE pNumBlock, BYTE pLgDiversifier, BYTE pBlockDiversifier)
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
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_REAUTHENTICATE;// MIFARE instruction
	giCSCTrame[j++]=pNumKey;						// single byte parameter 
	giCSCTrame[j++]=pVersionKey;					// single byte parameter 
	giCSCTrame[j++]=pKeyAorB;						// single byte parameter 
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	giCSCTrame[j++]=pLgDiversifier;					// single byte parameter 
	giCSCTrame[j++]=pBlockDiversifier;				// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_ReadBlock(BYTE pNumBlock)
/*****************************************************************
Read a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)

OUTPUTS
	None 

******************************************************************/
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_READBLOCK;	// MIFARE instruction
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_WriteBlock(BYTE pNumBlock, BYTE *pDataToWrite)
/*****************************************************************
Write a block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)
	pDataToWrite		:	Data to Write in block (16 bytes)

OUTPUTS
	None 

******************************************************************/
{
	int i, j = 0;


	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_WRITEBLOCK;	// MIFARE instruction
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	for(i=0; i < 16; i++, j++)
	  giCSCTrame[j]= *(pDataToWrite+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_ChangeKey(BYTE pNumKey, BYTE pVersionKeyA, BYTE pVersionKeyB, 
							  BYTE *pDefaultAccess, BYTE pNumBlock, BYTE pLgDiversifier, BYTE pBlockDiversifier)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_CHANGEKEY;	// MIFARE instruction
	giCSCTrame[j++]=pNumKey;						// single byte parameter 
	giCSCTrame[j++]=pVersionKeyA;					// single byte parameter 
	giCSCTrame[j++]=pVersionKeyB;					// single byte parameter 
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pDefaultAccess+i);			// memcopy of parameter 
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	giCSCTrame[j++]=pLgDiversifier;					// single byte parameter 
	giCSCTrame[j++]=pBlockDiversifier;				// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_Increment(BYTE pNumBlock, BYTE *pIncrement)
/*****************************************************************
Increment a Value block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)
	pIncrement			:	Increment Value to add (4 bytes)

OUTPUTS
	None 

******************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_INCREMENT;	// MIFARE instruction
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pIncrement+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_Decrement(BYTE pNumBlock, BYTE *pDecrement)
/*****************************************************************
Decrement a Value block in a MIFARE card
For this operation, the block need to be previously authenticated by an authenticate cmd

INPUTS
	pNumBlock			:	Number Block (1 byte)
	pDecrement			:	Decrement Value to substract (4 bytes)

OUTPUTS
	None 

******************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_DECREMENT;	// MIFARE instruction
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pDecrement+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_BackUpValue(BYTE pSource, BYTE pDestination)
/*****************************************************************
Perform a copy of a value block to an other value block location.

INPUTS
	pSource					:	Number Block Source (1 byte)
	pDestination			:	Number Block Destination (1 byte)

OUTPUTS
	None 

******************************************************************/
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_BACKUP;		// MIFARE instruction
	giCSCTrame[j++]=pSource;						// single byte parameter 
	giCSCTrame[j++]=pDestination;					// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMIFARE_SAMNXP_KillAuthentication()
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	None 

OUTPUTS
	None 

******************************************************************/
{
	int j=0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MIFARE_SAMNXP;			// MIFARE SAM NXP class
	giCSCTrame[j++]=CSC_MIFARE_SAMNXP_KILLAUTHENT;	// MIFARE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iMFP_SL3_Authentication(BYTE pSamKeyNum, BYTE pSamKeyVersion, WORD pKeyBlockNum, 
							 BYTE pLgDiversifier, BYTE *pDiversifier)
/*****************************************************************
Realise the authentication of block

INPUTS
	pSamKeyNum				:	Sam Key Number (1 bytes)
	pSamKeyVersion			:	Sam Key Version (1 bytes)
	pKeyBlockNum			:	Key Block Number - HigherByte, LowerByte (2 bytes)
	pLgDiversifier			:	Length Diversifier (1 byte)
	pDiversifier			:	Diversifier data (0 to 31 byte)

OUTPUTS
	None 

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_AUTHENTICATE;		// MIFARE instruction
	giCSCTrame[j++]=pSamKeyNum;						// single byte parameter 
	giCSCTrame[j++]=pSamKeyVersion;					// single byte parameter 
	giCSCTrame[j++]=(BYTE)((pKeyBlockNum&0xFF00)>>8);		// single byte parameter 
	giCSCTrame[j++]=(BYTE)(pKeyBlockNum&0xFF);			// single byte parameter 
	giCSCTrame[j++]=pLgDiversifier;					// single byte parameter 
	for(i=0; i < pLgDiversifier; i++, j++)
	  giCSCTrame[j]= *(pDiversifier+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMFP_SL3_ResetAuthentication(BYTE pMode)
/*****************************************************************
Disable a MIFARE card to forbid authenticated operation.

INPUTS
	pMode				:	Reset Mode (1 bytes)

OUTPUTS
	None 

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_RESETAUTHENTICATE;	// MIFARE instruction
	giCSCTrame[j++]=pMode;							// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMFP_SL3_ReadBlock(BYTE pMode, WORD pBlockNum, BYTE pNumBlock)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_READBLOCK;			// MIFARE instruction
	giCSCTrame[j++]=pMode;							// single byte parameter 
	giCSCTrame[j++]=(BYTE)((pBlockNum&0xFF00)>>8);			// single byte parameter 
	giCSCTrame[j++]=(BYTE)(pBlockNum&0xFF);				// single byte parameter 
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMFP_SL3_WriteBlock(BYTE pMode, WORD pBlockNum, BYTE pNumBlock, LPBYTE pDataToWrite)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_WRITEBLOCK;			// MIFARE instruction
	giCSCTrame[j++]=pMode;							// single byte parameter 
	giCSCTrame[j++]=(BYTE)((pBlockNum&0xFF00)>>8);			// single byte parameter 
	giCSCTrame[j++]=(BYTE)(pBlockNum&0xFF);				// single byte parameter 
	giCSCTrame[j++]=pNumBlock;						// single byte parameter 
	for(i=0; i < (pNumBlock*16); i++, j++)
	  giCSCTrame[j]= *(pDataToWrite+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMFP_SL3_ChangeKey(BYTE pSamKeyNum, BYTE pSamKeyVersion, WORD pKeyBlockNum, 
						BYTE pLgDiversifier, LPBYTE pDiversifier)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_CHANGEKEY;			// MIFARE instruction
	giCSCTrame[j++]=pSamKeyNum;						// single byte parameter 
	giCSCTrame[j++]=pSamKeyVersion;					// single byte parameter 
	giCSCTrame[j++]=(BYTE)((pKeyBlockNum&0xFF00)>>8);		// single byte parameter 
	giCSCTrame[j++]=(BYTE)(pKeyBlockNum&0xFF);			// single byte parameter 
	giCSCTrame[j++]=pLgDiversifier;					// single byte parameter 
	for(i=0; i < pLgDiversifier; i++, j++)
	  giCSCTrame[j]= *(pDiversifier+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMFP_SL3_VirtualCardSupport(BYTE pSamKeyNumVCENC, BYTE pSamKeyVersionVCENC,  
								 BYTE pSamKeyNumVCMAC, BYTE pSamKeyVersionVCMAC, LPBYTE pIID)														
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_VIRTUALCARDSUPPORT;	// MIFARE instruction
	giCSCTrame[j++]=pSamKeyNumVCENC;				// single byte parameter 
	giCSCTrame[j++]=pSamKeyVersionVCENC;			// single byte parameter 
	giCSCTrame[j++]=pSamKeyNumVCMAC;				// single byte parameter 
	giCSCTrame[j++]=pSamKeyVersionVCMAC;			// single byte parameter 
	for(i=0; i < 16; i++, j++)
	  giCSCTrame[j]= *(pIID+i);						// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iMFP_SL3_DeselectVirtualCard()														
/*****************************************************************
Deselect the Virtual Card

INPUTS
	-

OUTPUTS
	None 

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_MFP_SL3;				// MIFARE PLUS SL3 class
	giCSCTrame[j++]=CSC_MFP_SL3_DESELECTVIRTUALCARD;// MIFARE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iDESFIRE_CreateApplication(LPBYTE pAppID, BYTE Opt, BYTE KeyNum)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREATEAPPLICATION;	// DESFIRE instruction
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pAppID+i);					// memcopy of parameter 
	giCSCTrame[j++]=Opt;							// Data
	giCSCTrame[j++]=KeyNum;							// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_DeleteApplication(LPBYTE pAppID)
/*****************************************************************
Deactivate application in the card

INPUTS
	pAppID			:	ID Number of the Appl in the card (3 byte)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_DELETEAPPLICATION;	// DESFIRE instruction
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pAppID+i);					// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_SelectApplication(LPBYTE pAppID)
/*****************************************************************
Select one Application for further access in the card

INPUTS
	pAppID			:	ID Number of the Appl in the card (3 byte)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SELECTAPPLICATION;	// DESFIRE instruction
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pAppID+i);					// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_FormatPICC()
/*****************************************************************
Format card File system

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_FORMATPICC;			// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetApplicationIDs(BYTE pNumID)
/*****************************************************************
Retreive the current application ID

INPUTS
	pNumID			:	Number of ID (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETAPPLICATIONIDS;	// DESFIRE instruction
	giCSCTrame[j++]=pNumID;							// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetVersion()
/*****************************************************************
Version of the card firmware

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETVERSION;			// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetFreeMem()
/*****************************************************************
retrieve the size available on the card

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETFREEMEM;			// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/****************************************************************/
void iDESFIRE_PrepareAuthentication (	BYTE AuthMode,
          								BYTE SAMKeyNumber,
          								BYTE SAMKeyVersion)
/*****************************************************************
I	BYTE	AuthMode		Authentication parameters (see SAM AV2 specification).
I	BYTE	SAMKeyNumber	Key number in the SAM.
I	BYTE	SAMKeyVersion	Key version of the specified key in the SAM.
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_PREPARE_AUTHENTICATION;		// DESFIRE instruction
	giCSCTrame[j++]=AuthMode;						
	giCSCTrame[j++]=SAMKeyNumber;						
	giCSCTrame[j++]=SAMKeyVersion;						

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}

/*****************************************************************/
void iDESFIRE_Authenticate(BYTE pKeyNum)
/*****************************************************************
Realise the authentication

INPUTS
	pKeyNum			:	Number of the access key which will be used for the authetication (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_AUTHENTICATION;		// DESFIRE instruction
	giCSCTrame[j++]=pKeyNum;						// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

void iDESFIRE_AuthenticateEV1( 	BYTE PICCKeyNumber,
								BYTE AuthMode,
								BYTE SAMKeyNumber,
								BYTE SAMKeyVersion,
								BYTE Type,
								BYTE LgDiversifier,
								BYTE *Diversifier)
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
{
	int i,j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_AUTHENTICATE_EV1;	// DESFIRE instruction
	giCSCTrame[j++]=PICCKeyNumber;						
	giCSCTrame[j++]=AuthMode;						
	giCSCTrame[j++]=SAMKeyNumber;						
	giCSCTrame[j++]=SAMKeyVersion;						
	giCSCTrame[j++]=Type;						
	if (LgDiversifier > 31)
		LgDiversifier=31;
	giCSCTrame[j++]=LgDiversifier;						

	for(i=0; i < LgDiversifier; i++, j++)
	  giCSCTrame[j]= *(Diversifier+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;
}


/*****************************************************************/
void iDESFIRE_CommitTransaction()
/*****************************************************************
Commits the transaction to end a transaction operation with changes

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_COMMITTRANSACTION;	// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_AbortTransaction()
/*****************************************************************
Aborts the current transaction to end a transaction operation with no changes

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_ABORTTRANSACTION;	// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_ChangeKey(	BYTE CurKeyNo,
							BYTE CurKeyV,
							BYTE NewKeyNo,
							BYTE NewKeyV,
							BYTE KeyCompMeth,
							BYTE Cfg,
							BYTE Algo,
							BYTE LgDiversifier,
							BYTE *Diversifier)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CHANGEKEY;			// DESFIRE instruction
	giCSCTrame[j++]=CurKeyNo;			
	giCSCTrame[j++]=CurKeyV;			
	giCSCTrame[j++]=NewKeyNo;			
	giCSCTrame[j++]=NewKeyV;			
	giCSCTrame[j++]=KeyCompMeth;			
	giCSCTrame[j++]=Cfg;			
	giCSCTrame[j++]=Algo;			

	if (LgDiversifier > 31)
		LgDiversifier=31;
	giCSCTrame[j++]=LgDiversifier;						

	for(i=0; i < LgDiversifier; i++, j++)
	  giCSCTrame[j]= *(Diversifier+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_ChangeKeySetting(BYTE pKeySetting)
/*****************************************************************
Changes the key settings information  

INPUTS
	pKeySetting		:	new master key settings either for the currently selected application or for the whole PICC  (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CHANGEKEYSETTING;	// DESFIRE instruction
	giCSCTrame[j++]=pKeySetting;					// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetKeySetting()
/*****************************************************************
Gets the configuration information on the PIDD and the application master key configuration settings.

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETKEYSETTING;		// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetKeyVersion(BYTE pKeyNum)
/*****************************************************************
Gets Key Version.

INPUTS
	pKeyNum			:	Specify the number of the access key (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETKEYVERSION;		// DESFIRE instruction
	giCSCTrame[j++]=pKeyNum;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_ChangeFileSetting(BYTE pFileID, BYTE pCommEncrypted, BYTE pCommMode, BYTE pAccessRight)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CHANGEFILESETTING;	// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommEncrypted;					// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=pAccessRight;					// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_ClearRecordFile(BYTE pFileID)
/*****************************************************************
Clears the record files selected by the input param

INPUTS
	pFileID			:	ID of the file which shall be cleared (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CLEARRECORDFILE;	// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_CreateBackUpDataFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, LPBYTE pFileSize)
/*****************************************************************
Creation of a Backup Data File

INPUTS
	pFileID			:	ID of the file for which the new Backup File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAccessRight		:	New File access rights settings (2 byte)
	pFileSize		:	Size of the new Backup File in bytes (3 byte)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREATEBACKUPDATAFILE;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pAccessRight&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pAccessRight&0xFF);		// Data
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pFileSize+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_CreateCyclicRecordFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, 
									LPBYTE pRecordSize, LPBYTE pMaxNumRecord)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREATECYCLICRECORDFILE;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pAccessRight&0xFF00)>>8);		// Data
	giCSCTrame[j++]=(BYTE)(pAccessRight&0xFF);			// Data
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pRecordSize+i);				// memcopy of parameter 
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pMaxNumRecord+i);			// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_CreateLinearRecordFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, 
									 LPBYTE pRecordSize, LPBYTE pMaxNumRecord)
/*****************************************************************
Creation of a Linear Data File

INPUTS
	pFileID			:	ID of the file for which the new Linear record File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAccessRight		:	New File access rights settings (2 byte)
	pRecordSize		:	Size of the new linear File in bytes (3 byte)
	pMaxNumRecord	:	Number of the records for the new linear File (3 byte)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREATELINEARRECORDFILE;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pAccessRight&0xFF00)>>8);		// Data
	giCSCTrame[j++]=(BYTE)(pAccessRight&0xFF);			// Data
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pRecordSize+i);				// memcopy of parameter 
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pMaxNumRecord+i);			// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_CreateStandardDataFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, LPBYTE pFileSize)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREATESTANDARDDATAFILE;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pAccessRight&0xFF00)>>8);		// Data
	giCSCTrame[j++]=(BYTE)(pAccessRight&0xFF);			// Data
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pFileSize+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_CreateValueFile(BYTE pFileID, BYTE pCommMode, WORD pAccessRight, LPBYTE pLower, 
							LPBYTE pUpper, LPBYTE pInitial, BYTE pLimited)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREATEVALUEFILE;	// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pAccessRight&0xFF00)>>8);		// Data
	giCSCTrame[j++]=(BYTE)(pAccessRight&0xFF);			// Data
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pLower+i);					// memcopy of parameter 
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pUpper+i);					// memcopy of parameter 
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pInitial+i);					// memcopy of parameter 
	giCSCTrame[j++]=pLimited;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_Credit(BYTE pFileID, BYTE pCommMode, LPBYTE pAmount)
/*****************************************************************
Credit a Value on a Value File

INPUTS
	pFileID			:	ID of the file for which the new File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAmount			:	Amount to be credited in the value file (4 byte)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_CREDIT;				// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pAmount+i);					// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_Debit(BYTE pFileID, BYTE pCommMode, LPBYTE pAmount)
/*****************************************************************
Debit a Value on a Value File

INPUTS
	pFileID			:	ID of the file for which the new File is to be created (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAmount			:	Amount to be credited in the value file (4 byte)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_DEBIT;				// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pAmount+i);					// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_DeleteFile(BYTE pFileID)
/*****************************************************************
Delete a File 

INPUTS
	pFileID			:	ID of the file for which the new File is to be deleted (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_DELETEFILE;			// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetFileID(BYTE pMaxFileID)
/*****************************************************************
Get File ID for the current application 

INPUTS
	pMaxFileID		:	Max response expected  (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETFILEID;			// DESFIRE instruction
	giCSCTrame[j++]=pMaxFileID;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetFileSetting(BYTE pFileID)
/*****************************************************************
Get File Settings for the current application 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETFILESETTING;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_GetValue(BYTE pFileID, BYTE pCommMode)
/*****************************************************************
Get File Settings for the current application 

INPUTS
	pFileID			:	ID of the file for which the setting is to be Retrieve (1 byte)
	pCommMode		:	File communication mode (1 byte)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_GETVALUE;			// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_LimitedCredit(BYTE pFileID, BYTE pCommMode, LPBYTE pAmount)
/*****************************************************************
Limited Credit 

INPUTS
	pFileID			:	ID of the file for which the credit is to increase (1 byte)
	pCommMode		:	File communication mode (1 byte)
	pAmount			:	Max Amount that can be added to the File value (4 bytes)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_LIMITEDCREDIT;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	for(i=0; i < 4; i++, j++)
	  giCSCTrame[j]= *(pAmount+i);					// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_ReadData(BYTE pFileID, BYTE pCommMode, WORD pFromOffset, WORD pNumByteToRead)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_READDATA;			// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pFromOffset&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pFromOffset&0xFF);		// Data
	giCSCTrame[j++]=(BYTE)((pNumByteToRead&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pNumByteToRead&0xFF);	// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_WriteData(BYTE pFileID, BYTE pCommMode, WORD pFromOffset, WORD pNumByteToWrite, LPBYTE pDataToWrite)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_WRITEDATA;			// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pFromOffset&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pFromOffset&0xFF);		// Data
	giCSCTrame[j++]=(BYTE)((pNumByteToWrite&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pNumByteToWrite&0xFF);	// Data
	for(i=0; i < (int)pNumByteToWrite; i++, j++)
	  giCSCTrame[j]= *(pDataToWrite+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_ReadRecord(BYTE pFileID, BYTE pCommMode, WORD pFromRecord, WORD pNumRecordToRead, WORD pRecordSize)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_READRECORD;			// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pFromRecord&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pFromRecord&0xFF);		// Data
	giCSCTrame[j++]=(BYTE)((pNumRecordToRead&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pNumRecordToRead&0xFF);	// Data
	giCSCTrame[j++]=(BYTE)((pRecordSize&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pRecordSize&0xFF);	// Data

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_WriteRecord(BYTE pFileID, BYTE pCommMode, WORD pFromRecord, WORD pNumRecordToWrite, LPBYTE pDataToWrite)
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
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_WRITERECORD;		// DESFIRE instruction
	giCSCTrame[j++]=pFileID;						// Data
	giCSCTrame[j++]=pCommMode;						// Data
	giCSCTrame[j++]=(BYTE)((pFromRecord&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pFromRecord&0xFF);		// Data
	giCSCTrame[j++]=(BYTE)((pNumRecordToWrite&0xFF00)>>8);// Data
	giCSCTrame[j++]=(BYTE)(pNumRecordToWrite&0xFF);	// Data
	for(i=0; i < (int)pNumRecordToWrite; i++, j++)
	  giCSCTrame[j]= *(pDataToWrite+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_SamGetVersion()
/*****************************************************************
Sam Firmware Info

INPUTS
	-

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SAMGETVERSION;		// DESFIRE instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_SamSelectApplication(LPBYTE pDirFileAID)
/*****************************************************************
Select an application in the SAM

INPUTS
	pDirFileAID:	Directory File AID (3 bytes)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SAMSELECTAPPLICATION;// DESFIRE instruction
	for(i=0; i < 3; i++, j++)
	  giCSCTrame[j]= *(pDirFileAID+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_SamLoadInitVector(LPBYTE pInitVector)
/*****************************************************************
Load an init vector in the SAM for 3DES seeding

INPUTS
	pInitVector:	Crypto seed (8 bytes)

OUTPUTS
	-

*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SAMLOADINITVECTOR;	// DESFIRE instruction
	for(i=0; i < 8; i++, j++)
	  giCSCTrame[j]= *(pInitVector+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_SamGetKeyEntry(BYTE pKeyNum)
/*****************************************************************
Key entry Info

INPUTS
	pKeyNum:	Key Entry Number (1 bytes)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SAMGETKEYENTRY;		// DESFIRE instruction
	giCSCTrame[j++]=pKeyNum;						// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iDESFIRE_SamGetKucEntry(BYTE pRefKucNum)
/*****************************************************************
Key Usage Counter Info

INPUTS
	pRefKucNum:	Key Usage Counter Entry Reference Number (1 bytes)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SAMGETKUCENTRY;		// DESFIRE instruction
	giCSCTrame[j++]=pRefKucNum;						// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/

/*****************************************************************/
void iDESFIRE_SamDisableCrypto(WORD pPROMAS)
/*****************************************************************
Disable the crypto of certain function on the SAM/PICC

INPUTS
	pPROMAS			:	Programming bit Mask (2 bytes)

OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_DESFIRE;				// DESFIRE class
	giCSCTrame[j++]=CSC_DESFIRE_SAMDISABLECRYPTO;	// DESFIRE instruction
	giCSCTrame[j++]=(BYTE)((pPROMAS&0xFF00)>>8);	// single byte parameter
	giCSCTrame[j++]=(BYTE)(pPROMAS&0xFF);			// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/


void iSRX_Active()
/*****************************************************************
Activate and select a SR, SRI, SRT or SRIX ticket and send back the chip type and the 64-bit UID.

INPUTS
	-
	
OUTPUTS
	-

*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_SRX;					// SR Family class
	giCSCTrame[j++]=CSC_SRX_ACTIVATE;				// SR instruction

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/*****************************************************************/
void iSRX_ReadBlock(BYTE pBlockNum, BYTE pNumBlock)
/*****************************************************************
Read Blocks.

INPUTS
	pBlockNum			:	Block Number to start reading (1 bytes)
	pNumBlock			:	Number of block to read (1 bytes)

OUTPUTS
	-
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_SRX;					// SR Family class
	giCSCTrame[j++]=CSC_SRX_READBLOCK;				// SR instruction
	giCSCTrame[j++]=pBlockNum;						// single byte parameter
	giCSCTrame[j++]=pNumBlock;						// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iSRX_WriteBlock(BYTE pBlockNum, BYTE pNumBlock, LPBYTE pDataToWrite, BYTE pChipType)
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
{
	int i, j = 0;
	BYTE NumByte = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_SRX;					// SR Family class
	giCSCTrame[j++]=CSC_SRX_WRITEBLOCK;				// SR instruction
	giCSCTrame[j++]=pBlockNum;						// single byte parameter
	giCSCTrame[j++]=pNumBlock;						// single byte parameter
	if(pChipType == 0)								// SR176
		NumByte = pNumBlock*2;
	else											// SR512 et SR4K
		NumByte = pNumBlock*4;

	for(i=0; i < NumByte; i++, j++)
		  giCSCTrame[j]= *(pDataToWrite+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iSRX_Release(BYTE pParam)
/*****************************************************************
Deactivate SRx ticket.

INPUTS
	Param				:	Param deactivation of the ticket (1 bytes)

OUTPUTS
	-	
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_SRX;					// SR Family class
	giCSCTrame[j++]=CSC_SRX_RELEASE;				// SR instruction
	giCSCTrame[j++]=pParam;							// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iSRX_Read(WORD pAdd, BYTE pNumBytes)
/*****************************************************************
Read Blocks.

INPUTS
	pAdd				:	Address of the first reading -> LSB / MSB (2 bytes)
	pNumBytes			:	Number of bytes to read (1 bytes)

OUTPUTS
	-
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_SRX;					// SR Family class
	giCSCTrame[j++]=CSC_SRX_READ;					// SR instruction
	giCSCTrame[j++]=(BYTE)(pAdd&0xFF);				// single byte parameter
	giCSCTrame[j++]=(BYTE)((pAdd&0xFF00)>>8);		// single byte parameter
	giCSCTrame[j++]=pNumBytes;						// single byte parameter

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}

/*****************************************************************/
void iSRX_Write(WORD pAdd, BYTE pNumBytes, LPBYTE pDataToWrite)
/*****************************************************************
Read Blocks.

INPUTS
	pAdd				:	Address of the first reading -> LSB / MSB (2 bytes)
	pNumBytes			:	Number of bytes to read (1 bytes)
	DataToWrite			:	Data to Write

OUTPUTS
	-
*****************************************************************/
{
	int i, j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;                   // EXEC Command Code
	giCSCTrame[j++]=0;					            // Length
	giCSCTrame[j++]=CSC_CLA_SRX;					// SR Family class
	giCSCTrame[j++]=CSC_SRX_WRITE;					// SR instruction
	giCSCTrame[j++]=(BYTE)(pAdd&0xFF);				// single byte parameter
	giCSCTrame[j++]=(BYTE)((pAdd&0xFF00)>>8);		// single byte parameter
	giCSCTrame[j++]=pNumBytes;						// single byte parameter
	for(i=0; i < pNumBytes; i++, j++)
	  giCSCTrame[j]= *(pDataToWrite+i);				// memcopy of parameter 

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		giCSCTrame[1] = giCSCTrameLn-3;				// Update Command lenght
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
		giCSCTrame[1] = giCSCTrameLn-2;				// Update Command lenght
	}
	giCSCStatus=iCSC_OK;

}


/****************************************************************/
void iCTX_512B_List(BYTE RFU)
/*****************************************************************
LIST CTX512B
Performs anticollision and answers serial numbers of all the chips
present in the antenna field

INPUTS
	RFU	:	default=0x00, RFU
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512B_LIST;				// INS = LIST
giCSCTrame[4]=RFU;								// RFU

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command							
	giCSCTrameLn=6;									// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;									// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTX_512B_Select(BYTE* serialNumber)
/*****************************************************************
SELECT CTX512B
Selects a ticket with its serial number

INPUTS
	serialNumber : pointer to the buffer containing the serial
					number (2 bytes)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512B_SELECT;				// INS = SELECT
giCSCTrame[4]=serialNumber[0];					// serial number, 1st byte 
giCSCTrame[5]=serialNumber[1];					// serial number, 2nd byte

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// end of command
	giCSCTrameLn=7;									// frame length								
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;									// frame length								
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512B_Read(BYTE ADD, BYTE NB)
/*****************************************************************
READ CTX512B
Reads a number of bytes (NB) from a given address (ADD)

INPUTS
	ADD		: adress of the first byte (0 ... 63)
	NB		: Number of bytes to be read (from 1 up to 64)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512B_READ;				// INS = read
giCSCTrame[4]=ADD;								// adress of the first byte
giCSCTrame[5]=NB;								// Number of bytes to read

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// End of Command
	giCSCTrameLn=7;									// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;									// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512B_Update(BYTE ADD, BYTE NB, BYTE *data)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=NB+4;				            // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512B_UPDATE;				// INS = update

giCSCTrame[4]=ADD;								// adress of the first byte
giCSCTrame[5]=NB;								// Number of bytes to be read

for(i=0; i < NB; i++)
{
  giCSCTrame[i+6]= *(data+i);                   // memcopy of data to write
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[NB+6]=0x00;						// End of Command
	giCSCTrameLn=NB+7;							// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=NB+6;							// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512B_Halt(BYTE Param)
/*****************************************************************
HALT CTX512B

INPUTS
	Param	0x00 : desactivates ticket using 'desactivate' instruction
			(others RFU)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512B_HALT;				// INS = halt
giCSCTrame[4]=Param;							// param (0x00)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTX_512X_List(BYTE RFU)
/*****************************************************************
LIST CTX512X
Performs anticollision and answers serial numbers of all the chips
present in the antenna field

INPUTS
	RFU	:	default=0x00, RFU
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_LIST;				// INS = LIST
giCSCTrame[4]=RFU;								// RFU

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command							
	giCSCTrameLn=6;									// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;									// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTX_512X_Select(BYTE* serialNumber)
/*****************************************************************
SELECT CTX512X
Selects a CTx512B with its serial number

INPUTS
	serialNumber : pointer to the buffer containing the serial
					number (2 bytes)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{
giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_SELECT;				// INS = SELECT
giCSCTrame[4]=serialNumber[0];					// serial number, 1st byte 
giCSCTrame[5]=serialNumber[1];					// serial number, 2nd byte

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// end of command
	giCSCTrameLn=7;									// frame length								
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;									// frame length								
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512X_Read(BYTE ADD, BYTE NB)
/*****************************************************************
READ CTX512X
Reads a number of bytes (NB) from a given address (ADD)

INPUTS
	ADD		: adress of the first byte (0 ... 63)
	NB		: Number of bytes to be read (from 1 up to 64)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_READ;				// INS = read
giCSCTrame[4]=ADD;								// adress of the first byte
giCSCTrame[5]=NB;								// Number of bytes to read

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// End of Command
	giCSCTrameLn=7;									// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;									// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512X_Update(BYTE ADD, BYTE NB, BYTE *data)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=NB+4;				            // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_UPDATE;				// INS = update

giCSCTrame[4]=ADD;								// adress of the first byte
giCSCTrame[5]=NB;								// Number of bytes to be read

for(i=0; i < NB; i++)
{
  giCSCTrame[i+6]= *(data+i);                   // memcopy of data to write
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[NB+6]=0x00;						// End of Command
	giCSCTrameLn=NB+7;							// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=NB+6;							// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512X_Halt(BYTE Param)
/*****************************************************************
HALT CTX512X

INPUTS
	Param	0x00 : desactivates ticket using 'desactivate' instruction
			(others RFU)
OTHERS
	modifies giCSCTrame, giCSCTrameLn, giCSCStatus
*****************************************************************/
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=3;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_HALT;				// INS = halt
giCSCTrame[4]=Param;							// param (0x00)

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[5]=0x00;								// End of Command
	giCSCTrameLn=6;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=5;
}
giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCTx_512X_Write(BYTE ADD, BYTE NB, BYTE *data)
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
{
int i;

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=NB+4;								// Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_WRITE;				// INS = write

giCSCTrame[4]=ADD;								// adress of the first byte
giCSCTrame[5]=NB;								// Number of bytes to be read

for(i=0; i < NB; i++)
{
  giCSCTrame[i+6]= *(data+i);                   // memcopy of data to write
}

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[NB+6]=0x00;						// End of Command
	giCSCTrameLn=NB+7;							// frame length
	icsc_SetCRC();
}
else{
	giCSCTrameLn=NB+6;							// frame length
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512X_Authenticate(BYTE address, BYTE kif_kref, BYTE kvc_zero)
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
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=5;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_AUTHENTICATE;		// INS = authenticate
giCSCTrame[4]=address;							// address
giCSCTrame[5]=kif_kref;							// KIF or key reference
giCSCTrame[6]=kvc_zero;							// KVC or 0x00

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[7]=0x00;								// End of Command
	giCSCTrameLn=8;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=7;
}

giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCTx_512X_WriteKey(BYTE kif_kref, BYTE kvc_zero)
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
{

giCSCTrame[0]=CSC_CMD_EXEC;                     // EXEC Command
giCSCTrame[1]=4;				                // Length
giCSCTrame[2]=CSC_CLA_CTX;						// CTx class
giCSCTrame[3]=CSC_CTX_512X_WRITEKEY;			// INS = write key
giCSCTrame[4]=kif_kref;							// KIF or key reference
giCSCTrame[5]=kvc_zero;							// KVC or 0x00

// Compute and Set the CRC at the end of the buffer
if (giCRCNeeded == TRUE){
	giCSCTrame[6]=0x00;								// End of Command
	giCSCTrameLn=7;
	icsc_SetCRC();
}
else{
	giCSCTrameLn=6;
}
giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iCSC_SetSAMBaudratePPS( BYTE ProProt, BYTE ParamFD)
/*****************************************************************
Parameters:
I	BYTE	ProProt		Proposed protocol (0 for T=0; 1 for T=1)
I	BYTE	ParamFD		FiDi parameter
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					// EXEC Command
	giCSCTrame[j++]=4;								// Length 
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_SYS_SAM_BAUDRATE_PPS;
	giCSCTrame[j++]=ProProt;						// length low
	giCSCTrame[j++]=ParamFD;						// length high

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iEMVCo_UserInterface (BYTE SequenceNumber)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					// EXEC Command
	giCSCTrame[j++]=3;								// Length 
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_SYS_EMV_USER_INTERFACE;
	giCSCTrame[j++]=SequenceNumber;						

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iEMVCo_Contactless (BYTE CommandNumber,
								LPBYTE Parameters)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					// EXEC Command
	giCSCTrame[j++]=3;								// Length 
	giCSCTrame[j++]=CSC_CLA_SYSTEM;                 // System class
	giCSCTrame[j++]=CSC_SYS_EMV_CONTACTLESS;
	giCSCTrame[j++]=CommandNumber;						

	switch (CommandNumber)
	{
	case 0:
	case 1:
		break;
	
	case 2:
	case 3:
	case 4:
	case 5:
		giCSCTrame[j++]=*Parameters;	// put parameter					
		giCSCTrame[1]+=1;				// adjust command lenght
		break;

	case 6:
		CopyMemory (&giCSCTrame[j],Parameters,6);	// put parameters					
		giCSCTrame[1]+=6;				// adjust command lenght
		j+=6;
		break;

	}



	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCalypsoRev3_GetMode ()
/*****************************************************************
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					// EXEC Command
	giCSCTrame[j++]=3;								// Length 
	giCSCTrame[j++]=CSC_CLA_GEN;					// System class
	giCSCTrame[j++]=CSC_GEN_CALYPSO_REV3_MODE;
	giCSCTrame[j++]=2;								// get mode

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iCalypsoRev3_SetMode (BYTE Mode)
/*****************************************************************
Parameters:
I	BYTE	Mode			$00: Disable Calypso Rev3 mode.
							$01: Enable Calypso Rev3 mode.
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					// EXEC Command
	giCSCTrame[j++]=3;								// Length 
	giCSCTrame[j++]=CSC_CLA_GEN;					// System class
	giCSCTrame[j++]=CSC_GEN_CALYPSO_REV3_MODE;
	giCSCTrame[j++]=Mode;							// set mode	

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}


/****************************************************************/
void iMFUL_Identify (BYTE RFU)
/*****************************************************************
I	BYTE	RFU			RFU, should be set to 0.
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=3;						// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_IDENTIFY;
	giCSCTrame[j++]=RFU;					

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}
/****************************************************************/
void iMFUL_Read (BYTE ByteAddress, BYTE Nb)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=4;						// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_READ;
	giCSCTrame[j++]=ByteAddress;					
	giCSCTrame[j++]=Nb;						

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFUL_Write (BYTE ByteAddress, BYTE Nb,BYTE *DataToWrite)
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
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=4+Nb;						// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_WRITE;
	giCSCTrame[j++]=ByteAddress;					
	giCSCTrame[j++]=Nb;						
	CopyMemory (&giCSCTrame[j],DataToWrite,Nb);
	j += Nb;
	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULC_Authenticate (BYTE KeyNo, BYTE KeyV,
						  BYTE DIVLength, BYTE *DIVInput)
/*****************************************************************
Parameters :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=5+DIVLength;						// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_C_AUTHENTICATE;
	giCSCTrame[j++]=KeyNo;					
	giCSCTrame[j++]=KeyV;					
	giCSCTrame[j++]=DIVLength;						
	CopyMemory (&giCSCTrame[j],DIVInput,DIVLength);
	j += DIVLength;
	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULC_WriteKeyFromSAM  (BYTE KeyNo, BYTE KeyV, 
       						  BYTE DIVLength, BYTE *DIVInput)
/*****************************************************************
Parameters  :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=5+DIVLength;						// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_C_WRITE_KEY_FROM_SAM;
	giCSCTrame[j++]=KeyNo;					
	giCSCTrame[j++]=KeyV;					
	giCSCTrame[j++]=DIVLength;						
	CopyMemory (&giCSCTrame[j],DIVInput,DIVLength);
	j += DIVLength;
	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULEV1_PasswordAuthenticate (BYTE *Password)
/*****************************************************************
Parameters  :
I	BYTE	*Password	password value for authentication (4 bytes)
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=2+4;							// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_EV1_PASSWORD_AUTHENTICATE;
	CopyMemory (&giCSCTrame[j],Password,4);
	j += 4;
	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULEV1_CreateDiversifiedPasswordandPACK (BYTE KeyNo, BYTE KeyV, 
       											BYTE DIVLength, BYTE *DIVInput)
/*****************************************************************
Parameters  :
I	BYTE	KeyNo		key reference number of key entry ($00 to $7F)
I	BYTE	KeyV		key version of KeyNo ($00 to $FF)
I	BYTE	DIVLength	length of the diversification input (0 to 31, 0 = no diversification)
I	BYTE	*DIVInput	diversification input
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=5+DIVLength;						// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_EV1_CREATE_PASSWORD_PACK;
	giCSCTrame[j++]=KeyNo;					
	giCSCTrame[j++]=KeyV;					
	giCSCTrame[j++]=DIVLength;						
	CopyMemory (&giCSCTrame[j],DIVInput,DIVLength);
	j += DIVLength;
	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULEV1_ReadCounter ( BYTE CounterNb)
/*****************************************************************
Parameters  :
I	BYTE	CounterNb		counter number from $00 to $02
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=3;								// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_EV1_READ_COUNTER;
	giCSCTrame[j++]=CounterNb;					

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULEV1_IncrementCounter (BYTE CounterNb, 
								DWORD IncrementValue)
/*****************************************************************
Parameters  :
I	BYTE	CounterNb		counter number from $00 to $02
I	DWORD	IncrementValue	increment value from $000000 to $FFFFFF
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=6;								// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_EV1_INCREMENT_COUNTER;
	giCSCTrame[j++]=CounterNb;					
	giCSCTrame[j++]=(BYTE)(IncrementValue>>16) & 0xFF;					
	giCSCTrame[j++]=(BYTE)(IncrementValue>>8) & 0xFF;					
	giCSCTrame[j++]=(BYTE)(IncrementValue>>0) & 0xFF;					

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULEV1_GetVersion ()
/*****************************************************************
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=2;								// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_EV1_GET_VERSION;

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}

/****************************************************************/
void iMFULEV1_CheckTearingEvent (BYTE CounterNb)
/*****************************************************************
Parameters  :
I	BYTE	CounterNb	counter number from $00 to $02
*****************************************************************/
{
	int j = 0;

	giCSCTrame[j++]=CSC_CMD_EXEC;					
	giCSCTrame[j++]=3;								// Length 
	giCSCTrame[j++]=CSC_CLA_MFUL;					
	giCSCTrame[j++]=CSC_MFUL_EV1_CHECK_TEARING_EVENT;
	giCSCTrame[j++]=CounterNb;					

	// Compute and Set the CRC at the end of the buffer
	if (giCRCNeeded == TRUE)
	{
		giCSCTrame[j]=0x00;							// End of Command
		giCSCTrameLn=j+1;
		icsc_SetCRC();
	}
	else
	{
		giCSCTrameLn=j;
	}
	giCSCStatus=iCSC_OK;
}
