/*****************************************************************
  HEADER INCLUDE FILE for TEST.C
 
  WIN32 plateform for WINDOWS 95 & WINDOWS NT4

  Copyright (C)2000 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Jean-Luc M. - ASK
*****************************************************************/
/* $Log:   W:/Lecteurs/DLL Askcsc/Sources/archives/test/test.h-arc  $
 * 
 *    Rev 1.6   Sep 16 2002 15:15:04   blepin
 * Voir Change_history
 * 
 *    Rev 1.5   Feb 08 2002 15:24:18   smanig
 * Ajout de la classe Mifare et autre tests manquants
 * 
 *    Rev 1.3   May 14 2001 11:09:34   ccoure
 * 1- Ajout de tests en erreur
 * 2- Séparation des fichiers de tests suivant la classe
 * 
 *    Rev 1.2   Mar 30 2001 16:07:40   ccoure
 * Maj pour harmonisation du nom des commandes ticket
 * 
 *    Rev 1.1   Mar 01 2001 15:04:30   ccoure
 * Modif des tests CT2000 (conflit de declaration de cle entre CT2000 et CT2000 TRANSCARTE)
*/
//mapping figé innovatron CD97, GTML
#define		MF_KEY1			6
#define		MF_KEY2			7
#define		MF_KEY3			8
#define		RT_KEY1			12
#define		RT_KEY2			2
#define		RT_KEY3			13
#define		EP_KEY1			9
#define		EP_KEY2			10
#define		EP_KEY3			11
#define		MPP_KEY1		14
#define		MPP_KEY2		4
#define		MPP_KEY3		15

// mapping cartes de test CT2000
// Config avec 1er SAM et CT2000 de test
/*
#define		MF_PER_KEY		0x02
#define		MF_UPD_KEY		0x03
#define		MF_PAR_KEY		0x04
#define		MF_INV_KEY		0x05
#define		MF_STR_KEY		0x06

#define		RT_PER_KEY		0x07
#define		RT_UPD_KEY		0x08
#define		RT_PAR_KEY		0x09
#define		RT_INV_KEY		0x0A
#define		RT_STR_KEY		0x0B

#define		MPP1_PER_KEY	0x0C
#define		MPP1_UPD_KEY	0x0D
#define		MPP1_PAR_KEY	0x0E
#define		MPP1_INV_KEY	0x0F
#define		MPP1_STR_KEY	0x10

#define		KVC				0x01

*/
// Config avec SAM de Kit de Developpement et CT2000 de Kit de developpement
#define		MF_PER_KEY		0x10
#define		MF_UPD_KEY		0x11
#define		MF_PAR_KEY		0x12
#define		MF_INV_KEY		0x13
#define		MF_STR_KEY		0x14

#define		RT_PER_KEY		0x15
#define		RT_UPD_KEY		0x16
#define		RT_PAR_KEY		0x03
#define		RT_INV_KEY		0x17
#define		RT_STR_KEY		0x18

#define		MPP1_PER_KEY	0x19
#define		MPP1_UPD_KEY	0x1A
#define		MPP1_PAR_KEY	0x05
#define		MPP1_INV_KEY	0x1B
#define		MPP1_STR_KEY	0x1C



// cle pour CT2000 TRANSCARTE
#define		MF_PER_KEY_TRANS		0x04
#define		MF_UPD_KEY_TRANS		0x05
#define		MF_PAR_KEY_TRANS		0x06
#define		MF_INV_KEY_TRANS		0x07

#define		SEMUR_PER_KEY_TRANS		0x08
#define		SEMUR_UPD_KEY_TRANS		0x09
#define		SEMUR_PAR_KEY_TRANS		0x0A
#define		SEMUR_INV_KEY_TRANS		0x0B

#define		RDA_PER_KEY_TRANS		0x0C
#define		RDA_UPD_KEY_TRANS		0x0D
#define		RDA_PAR_KEY_TRANS		0x0E
#define		RDA_INV_KEY_TRANS		0x0F

#define		RT_PER_KEY_TRANS		0x10
#define		RT_UPD_KEY_TRANS		0x11
#define		RT_PAR_KEY_TRANS		0x12
#define		RT_INV_KEY_TRANS		0x13

#define		LENS_PER_KEY_TRANS		0x14
#define		LENS_UPD_KEY_TRANS		0x15
#define		LENS_PAR_KEY_TRANS		0x16
#define		LENS_INV_KEY_TRANS		0x17

#define		SAEM_PER_KEY_TRANS		0x18
#define		SAEM_UPD_KEY_TRANS		0x19
#define		SAEM_PAR_KEY_TRANS		0x1A
#define		SAEM_INV_KEY_TRANS		0x1B


#define		KVC1			0x01
#define		SAM_DESX		0x40


DWORD GetTimer(DWORD StartValue);
LPSTR BinToString(BYTE* data,DWORD lndata);
void Mess(LPSTR text,DWORD ret);
int CheckFunc(LPSTR text,DWORD ret,sCARD_Status* Status);
int CheckFuncError(LPSTR text,DWORD ret,sCARD_Status* Status,sCARD_Status* WantedStatus);
FILE	*trace;