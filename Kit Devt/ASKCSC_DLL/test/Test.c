/*****************************************************************
  Test program for the DLL ASKCSC.DLL version 2.0

  WIN32 plateform for WINDOWS 95 & WINDOWS NT4

  Copyright (C)2002 by ASK SOPHIA ANTIPOLIS FRANCE
  All right reserved.

  Author : Jean-Luc M. / Serge M. - ASK
*****************************************************************/
/*****************************************************************
  HISTORY :
$Log:   W:/Lecteurs/DLL Askcsc/Sources/archives/test/Test.c-arc  $
 * 
 *    Rev 1.10   03 Jan 2005 14:15:04   gbrand
 * voir Change_history
 * 
 *    Rev 1.9   Sep 16 2002 15:15:04   blepin
 * Voir Change_history
 * 
 *    Rev 1.8   Mar 01 2002 12:21:44   smanig
 * modif pour change speed
 * 
 *    Rev 1.7   Feb 08 2002 15:24:16   smanig
 * Ajout de la classe Mifare et autre tests manquants
 * 
 *    Rev 1.5   May 14 2001 11:09:34   ccoure
 * 1- Ajout de tests en erreur
 * 2- Séparation des fichiers de tests suivant la classe
 * 3- mise à jour des test + classe MIFARE

******************************************************************/




#include <windows.h>
#include <stdio.h>
#include <conio.h>

#undef __ASKCSC_IN__
#include "..\\askcsc.h"
#include "Test.h"

int Error;
BYTE KVCSAM;

/****************************************************************/
DWORD GetTimer(DWORD StartValue)
/*****************************************************************
  Convert the binary bytes by ASCII characters 

  Input :	StartValue : The initial timer value

  Output :	None

  Return :	the number of milliseconds that have elapsed since
			the system was started. 

*****************************************************************/
{
	DWORD x=GetTickCount();
	return x-StartValue;
}

/****************************************************************/
LPSTR BinToString(BYTE* data,DWORD lndata)
/*****************************************************************
  Convert the binary bytes by ASCII characters 

  Input :	data : binary datas
			lndata : Length of the Binary datas

  Output :	None

  Return :	ASCII datas

*****************************************************************/
{
static char tx[2048];
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
void SetErrorTo1(void)
/*****************************************************************
  Set Global variable to 1 to avoid exiting on error by an OpenComErr 
	It allow to put Breakpoint in debug.

  Input :	None

  Output :	None

  Return :	None

*****************************************************************/
{
	printf("\nERROR oOo ERROR oOo ERROR oOo ERROR oOo ERROR oOo ERROR \n");
	Error=1;
}


/****************************************************************/
void Mess(LPSTR text,DWORD ret)
/*****************************************************************
  Display error function 

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	None

*****************************************************************/
{
	printf("\nTest Stop :\n");
	printf(text);
	printf("\n");

	fprintf(trace,"\nTest Stop : ");
	fprintf(trace,text);
	fprintf(trace," ---- %02X",ret);
	fprintf(trace,"\n");

	if(ret==0)return;

	printf("Function return value : ");
	switch(ret)
		{
		case RCSC_Ok:printf("RCSC_Ok");break;
		case RCSC_NoAnswer:printf("RCSC_NoAnswer");break;
		case RCSC_CheckSum:printf("RCSC_CheckSum");break;
		case RCSC_Fail:printf("RCSC_Fail");break;
		case RCSC_Timeout:printf("RCSC_Timeout");break;
		case RCSC_Overflow:printf("RCSC_Overflow");break;
		case RCSC_OpenCOMError:printf("RCSC_OpenCOMError");break;
		case RCSC_DataWrong:printf("RCSC_DataWrong");break;
		case RCSC_CardNotFound:printf("RCSC_CardNotFound");break;
		case RCSC_ErrorSAM:printf("RCSC_ErrorSAM");break;
		case RCSC_CSCNotFound:printf("RCSC_CSCNotFound");break;
		case RCSC_BadATR:printf("RCSC_BadATR");break;
		case RCSC_TXError:printf("RCSC_TXError");break;
		case RCSC_UnknownClassCommand:printf("RCSC_UnknowClassCommand");break;
		default:printf("Unknown Error = %04X",ret);break;
		}
	printf("\n");
}

/****************************************************************/
int CheckFunc(LPSTR text,DWORD ret,sCARD_Status* Status)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if((ret==RCSC_Ok)&&(Status->Code==0)&&(Status->Byte1==0x90)&&(Status->Byte2==0x00))
	{
		printf(".");
		return 1;
	}
	else if((ret==RCSC_Ok)&&(Status->Code==0)&&(Status->Byte1==0x62)&&(Status->Byte2==0x00))
	{
		printf(".");
		return 1;
	}
	Mess(text,ret);
	printf("Status = %02X %02X %02X\n",Status->Code,Status->Byte1,Status->Byte2);
	printf("\n\n");// display the command return status value
	return 0;
}



/****************************************************************/
int CheckFuncMIFARESAMNXP(LPSTR text,DWORD ret,BYTE StatusCard,WORD StatusSam)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if((ret==RCSC_Ok)&&(StatusCard==0x01)&&(StatusSam==0x9000))
	{
		printf(" OK");
		return 1;
	}
	Mess(text,ret);
	printf("StatusCard = %02X \n",StatusCard);
	printf("StatusSam = %02X \n",StatusSam);
	printf("\n\n");// display the command return status value
	return 0;
}

/****************************************************************/
int CheckFuncMFPSL3(LPSTR text,DWORD ret,BYTE StatusCard,WORD StatusSam)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if((ret==RCSC_Ok)&&(StatusCard==0x90)&&(StatusSam==0x9000))
	{
		printf(" OK");
		return 1;
	}
	Mess(text,ret);
	printf("StatusCard = %02X \n",StatusCard);
	printf("StatusSam = %02X \n",StatusSam);
	printf("\n\n");// display the command return status value
	return 0;
}

/****************************************************************/
int CheckFuncMIFARE(LPSTR text,DWORD ret,BYTE Status)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if((ret==RCSC_Ok)&&(Status==0x00))
	{
		printf(".");
		return 1;
	}
	Mess(text,ret);
	printf("Status = %02X \n",Status);
	printf("\n\n");// display the command return status value
	return 0;
}

/****************************************************************/
int CheckFuncDESFIRE(LPSTR text,DWORD ret,WORD Status)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if((ret==RCSC_Ok)&&((Status==0x9100) || (Status==0x9000)))
	{
		printf(" OK");
		return 1;
	}
	Mess(text,ret);
	printf("Status = %02X \n",Status);
	printf("\n\n");// display the command return status value
	return 0;
}

/****************************************************************/
int CheckFuncSRx(LPSTR text,DWORD ret,BYTE Status)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if((ret==RCSC_Ok)&&((Status==0x0F) || (Status==0x02)))
	{
		printf(" OK");
		return 1;
	}
	Mess(text,ret);
	printf("Status = %02X \n",Status);
	printf("\n\n");// display the command return status value
	return 0;
}

/****************************************************************/
int CheckFuncError(LPSTR text,DWORD ret,sCARD_Status* Status,sCARD_Status* WantedStatus)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if( (ret==RCSC_Ok)&& 
		( (Status->Code==WantedStatus->Code)&&(Status->Byte1==WantedStatus->Byte1)&&
		  (Status->Byte2==WantedStatus->Byte2) ) )
	{
		printf(".");
		return 1;
	}
	Mess(text,ret);
	printf("Status recu= %02X %02X %02X\n",Status->Code,Status->Byte1,Status->Byte2);
	printf("Status attendu= %02X %02X %02X\n",WantedStatus->Code,WantedStatus->Byte1,WantedStatus->Byte2);
	printf("\n\n");// display the command return status value
	return 0;
}
/****************************************************************/
int CheckFuncCTS(LPSTR text,DWORD ret,BYTE* Status)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if(  (ret==RCSC_Ok)&&( (*Status==0x02) || (*Status==0x0F) )  )
	{
		printf(".");
		return 1;
	}
	Mess(text,ret);
	printf("Status = %02X \n", *Status);
	printf("\n\n");// display the command return status value
	return 0;
}

/****************************************************************/
int CheckFuncCTM(LPSTR text,DWORD ret,BYTE Status)
/*****************************************************************
  Check if the return value function is correct

  Input :	text :	ASCII String to display
			ret :	status of the command

  Output :	None

  Return :	1 if OK
			0 if KO 

*****************************************************************/
{
	if(  (ret==RCSC_Ok)&&(Status==0x02)  )
	{
		printf(".");
		return 1;
	}
	Mess(text,ret);
	printf("Status = %02X \n",Status);
	printf("\n\n");// display the command return status value
	return 0;
}



/****************************************************************/
void GtmlClassTest(void)
/*****************************************************************
  Test of  GTML Class  function

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	unsigned char tx[256];
	DWORD ret,ln;
	DWORD CounterValue;

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_1000[]={0x10,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_3115[]={0x31,0x00,0x31,0x15};
	BYTE SEL_3102[]={0x31,0x00,0x31,0x02};
	BYTE SEL_3100[]={0x31,0x00};
	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;


/*---- Test the Change PIN et Verify PIN -----------*/	
		
	// function SELECT FILE
	ret=GTML_SelectFile(GTML_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("GTML_SelectFile Master File",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	ret=GTML_VerifyPIN(OLDPIN,&Status);
	if(!CheckFunc("GTML_VerifyPIN '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CHANGE PIN
	ret=GTML_ChangePIN(OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("GTML_ChangePIN '30 30 30 30' -> '31 31 31 31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	ret=GTML_VerifyPIN(NEWPIN,&Status);
	if(!CheckFunc("GTML_VerifyPIN '31 31 31 31''",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_MF_ID,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord ID",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function CHANGE PIN
	ret=GTML_ChangePIN(NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("GTML_ChangePIN '31 31 31 31'' -> '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Select File -----*/	
	
	// function Select File 2000
	ret=GTML_SelectFile(GTML_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("GTML_SelectFile 20 00 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=2)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function Select File 3F00
	ret=GTML_SelectFile(GTML_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("GTML_SelectMasterFile ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=1)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Select File 2010
	ret=GTML_SelectFile(GTML_SEL_PATH,SEL_2010,sizeof(SEL_2010),tx,&Status);
	if(!CheckFunc("GTML_SelectFile 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=4)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Append Record in session -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_VALID,GTML_SID_RT_EVENTS_LOG,1,NULL,&Status);
	if(!CheckFunc("GTML_OpenSession - File:None - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Append Record
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	ret=GTML_AppendRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_CURRENT_EF,tx,29,&Status);
	if(!CheckFunc("GTML_AppendRecord 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_RELOAD,GTML_SID_RT_EVENTS_LOG,1,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=GTML_UpdateRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_ALL_COUNTERS,1,27,tx,&Status);
	if(!CheckFunc("GTML_UpdateRecord All counters ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,1,29,tx,&Status);
	if(!CheckFunc("GTML_AppendRecord 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x01\x01\x01",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");

	// function Increase and test the value 
	ret=GTML_Increase(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,0x101010,&CounterValue,&Status);
	if(!CheckFunc("GTML_Increase 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x111111) printf("\nProbleme lors de l'icrementation du compteur 0x0A");

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x11\x11\x11",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");



	ret=GTML_Decrease(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,0x101010,&CounterValue,&Status);
	if(!CheckFunc("GTML_Decrease 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x010101) printf("\nProbleme lors de la decrementation du compteur 0x0A");

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x1\x1\x1",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");


	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_RELOAD,GTML_SID_RT_EVENTS_LOG,1,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=GTML_UpdateRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_ALL_COUNTERS,1,27,tx,&Status);
	if(!CheckFunc("GTML_UpdateRecord All counters ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_9,1,29,tx,&Status);
	if(!CheckFunc("GTML_AppendRecord 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x09\x09\x09",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");

	// function Increase and test the value 
	ret=GTML_Increase(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_9,0x909090,&CounterValue,&Status);
	if(!CheckFunc("GTML_Increase 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x999999) printf("\nProbleme lors de l'icrementation du compteur 0x09");

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_9,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x99\x99\x99",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");



	ret=GTML_Decrease(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_9,0x909090,&CounterValue,&Status);
	if(!CheckFunc("GTML_Decrease 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x090909) printf("\nProbleme lors de la decrementation du compteur 0x09");

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_9,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x9\x9\x9",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");


	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Update Record in session (Reload) -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_RELOAD,GTML_SID_RT_EVENTS_LOG,0,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ZeroMemory(tx,29);
	ret=GTML_UpdateRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_CONTRACTS,1,29,tx,&Status);
	if(!CheckFunc("GTML_UpdateRecord SID 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_CONTRACTS,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord SID 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",29);
	if(ret!=0) printf("\nProbleme lors du contole du contrat");
	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Write Record and Update Record in session -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_VALID,GTML_SID_RT_EVENTS_LOG,0,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	ret=GTML_WriteRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_CONTRACTS,1,29,tx,&Status);
	if(!CheckFunc("GTML_WriteRecord 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_9,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x09 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x9\x9\x9",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");
	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record in session (Reload) -----*/	

	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_RELOAD,GTML_SID_RT_EVENTS_LOG,0,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ZeroMemory(tx,29);
	ret=GTML_UpdateRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_CONTRACTS,1,29,tx,&Status);
	if(!CheckFunc("GTML_UpdateRecord RT_CONTRACTS ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_CONTRACTS,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord RT_CONTRACTS ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",29);
	if(ret!=0) printf("\nProbleme lors du contole du contrat");
	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Invalidate function in session (Valid) -----*/	

	// function Select File 2000
	ret=GTML_SelectFile(GTML_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("GTML_SelectFile 20 00 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_VALID,0,0,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Invalidate
	ret=GTML_Invalidate(GTML_ACCESS_MODE_DEFAULT,&Status);
	if(!CheckFunc("GTML_Invalidate RT ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Rehabilitate function in session (Reload) -----*/	

	// function Select File 2000
	ret=GTML_SelectFile(GTML_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("GTML_SelectFile 20 00 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_PERSO,0,0,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Rehabilitate
	ret=GTML_Rehabilitate(GTML_ACCESS_MODE_DEFAULT,&Status);
	if(!CheckFunc("GTML_Reabilitate RT ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test Abort Session -----*/	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_PERSO,0,0,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Abort SESSION
	ret=GTML_AbortSecuredSession(&Status);
	if(!CheckFunc("GTML_AbortSecuredSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	else
		printf("OK\n");

return;

}

/****************************************************************/
void CD97ClassTest(void)
/*****************************************************************
Test of CD97 Class function

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	unsigned char tx[256];
	DWORD ret,ln;

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_1000[]={0x10,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_3115[]={0x31,0x00,0x31,0x15};
	BYTE SEL_3102[]={0x31,0x00,0x31,0x02};
	BYTE SEL_3100[]={0x31,0x00};
	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;

/*---- Test the Verify PIN Function -----*/	
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile Master File",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function VERIFY PIN
	ret=CD97_VerifyPIN(OLDPIN,&Status);
	if(!CheckFunc("CD97_VerifyPIN '0x30 0x30 0x30 0x30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Change PIN Function -----*/	
	// function CHANGE PIN
	ret=CD97_ChangePIN(OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("CD97_ChangePIN '0x30 0x30 0x30 0x30' -> '0x31 0x31 0x31 0x31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function VERIFY PIN
	ret=CD97_VerifyPIN(NEWPIN,&Status);
	if(!CheckFunc("CD97_VerifyPIN '0x31 0x31 0x31 0x31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CHANGE PIN
	ret=CD97_ChangePIN(NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("CD97_ChangePIN '0x31 0x31 0x31 0x31' -> '0x30 0x30 0x30 0x30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	
/*---- Test the STATUS FILE Function -----*/	
	// function STATUS FILE
	ret=CD97_StatusFile(CD97_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("CD97_StatusFile 3F00",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INVALIDATE Function -----*/	
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 3F00",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	ret=CD97_Invalidate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Invalidate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the REHABILITATE Function -----*/	
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 3F00",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function REHABILITATE FILE
	ret=CD97_Rehabilitate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Rehabilitate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	

/*---- Test the UPDATE RECORD Function -----*/	
	// function UPDATE RECORD
	memcpy(tx,"\0\0\0\0\0\0\0\0\0\0\0\x9\0\0",14);
	ret=CD97_UpdateRecord(CD97_ACCESS_MODE_PROTECTED,0x0A,1,14,tx,&Status);
	if(!CheckFunc("CD97_UpdateRecord - File:0x0A",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INCREASE PROTECTED Function -----*/	
	// function INCREASE
	ret=CD97_Increase(CD97_ACCESS_MODE_PROTECTED,0x0A,4,NULL,&Status);
	if(!CheckFunc("CD97_Increase by 4",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the DECREASE PROTECTED Function -----*/	
	// function DECREASE
	ret=CD97_Decrease(CD97_ACCESS_MODE_PROTECTED,0x0A,2,&ln,&Status);
	if(!CheckFunc("CD97_Decrease by 2",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// counter test
	if(ln!=0x000002)
	{
		Mess("\nCounter value fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the READ RECORD STAMPED Function -----*/	
	// function READ RECORD Stamped mode
	ret=CD97_ReadRecord(CD97_ACCESS_MODE_STAMPED,0x0A,1,14,tx,&Status);
	if(!CheckFunc("CD97_ReadRecord Counter",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if((tx[0]!=0x02)&&(tx[11]!=0x09))
	{
		Mess("\nRead Counter fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Session Function -----*/	
	// function OPEN SESSION
	ret=CD97_OpenSession(SESSION_LEVEL_RELOAD,0x0A,1,NULL,&Status);
	if(!CheckFunc("CD97_OpenSession - File:0x0A - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CD97_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CD97_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_PATH,SEL_3115,sizeof(SEL_3115),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 3115",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function APPEND RECORD
	memcpy(tx,"\1\2\3\4",4);
	ret=CD97_AppendRecord(CD97_ACCESS_MODE_PROTECTED,0,tx,4,&Status);
	if(!CheckFunc("CD97_AppendRecord 3115",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function READ RECORD
	ZeroMemory(tx,4);
	ret=CD97_ReadRecord(0/*CD97_ACCESS_MODE_STAMPED*/,0,1,4,tx,&Status);
	if(!CheckFunc("CD97_ReadRecord 3115",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if((tx[0]!=1)&&(tx[3]!=4))
	{
		Mess("\nRead 3115 fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function READ RECORD STAMPED
	ZeroMemory(tx,4);
	ret=CD97_ReadRecord(CD97_ACCESS_MODE_STAMPED,0,1,4,tx,&Status);
	if(!CheckFunc("CD97_ReadRecord 3115",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if((tx[0]!=1)&&(tx[3]!=4))
	{
		Mess("\nRead 3115 fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the EP Purchase Function -----*/	
// N.B. : For the SAM S1 we need a fake operation in order to 
// set the parameters Amount and equipement type to KVC
	// function GET ELECTRONIC PURSE STATUS
	ret=CD97_GetEPStatus(1,&ln,tx,&Status);
	if(!CheckFunc("CD97_GetEPStatus ( Purchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0x00; // Amount
	tx[1] = 0x00; // Amount
	tx[2] = 0x02; // Date
	tx[3] = 0xC3; // Date
	tx[4] = 0x03; // Time
	tx[5] = 0xA1; // Time
	tx[6] = KVCSAM; // SAM S1 necessity
	ret=CD97_Purchase(0,tx,NULL,&Status);
	if(!CheckFunc("CD97_Purchase Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Reload EP Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	ret=CD97_GetEPStatus(0,&ln,NULL,&Status);
	if(!CheckFunc("CD97_GetEPStatus ( Loading )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function RELOAD ELECTRONIC PURSE
	ZeroMemory(tx,10);
	tx[0] = 0x02; // Date				Charg1
	tx[1] = 0xC3; // Date				Charg1
	tx[2] = 0x00; // Money Batch		Charg1
	tx[3] = 0x02; // Money Batch		Charg1
	tx[4] = KVCSAM; // Equipement Type	Charg1
	tx[5] = 0x00;	// Amount			Charg2
	tx[6] = 0x00;	// Amount			Charg2
	tx[7] = 0x0F;	// Amount			Charg2
	tx[8] = 0x03;	// Time				Charg2
	tx[9] = 0xA1;	// Time				Charg2
	ret=CD97_ReloadEP(tx,&tx[5],&Status);
	if(!CheckFunc("CD97_ReloadEP Value=256",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INVALIDATE function in Protected Mode -----*/		
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_PATH,SEL_1000,sizeof(SEL_1000),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 1000",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	ret=CD97_Invalidate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Invalidate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the REHABILITATE function in Protected Mode -----*/	
	// function REHABILITATE FILE
	ret=CD97_Rehabilitate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Rehabilitate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
/*---- Test the EP Purchase Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	ret=CD97_GetEPStatus(1,&ln,NULL,&Status);
	if(!CheckFunc("CD97_GetEPStatus ( Purchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0xFF;	// Amount
	tx[1] = 0xF0;	// Amount
	tx[2] = 0x02;	// Date
	tx[3] = 0x02;	// Date
	tx[4] = 0x03;	// Time
	tx[5] = 0xA1;	// Time
	tx[6] = KVCSAM;	// Equipement Type

	ret=CD97_Purchase(0,tx,NULL,&Status);
	if(!CheckFunc("CD97_Purchase Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the EP Purchase Function -----*/	
// N.B. : 2 consecutives Purchase  are necessary after a Reload 
// otherwise the Cancel Purchase will not be possible
	// function GET ELECTRONIC PURSE STATUS
	ret=CD97_GetEPStatus(1,&ln,NULL,&Status);
	if(!CheckFunc("CD97_GetEPStatus ( Purchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0xFF;	// Amount
	tx[1] = 0xF0;	// Amount
	tx[2] = 0x02;	// Date
	tx[3] = 0x02;	// Date
	tx[4] = 0x03;	// Time
	tx[5] = 0xA1;	// Time
	tx[6] = KVCSAM;	// Equipement Type
	ret=CD97_Purchase(0,tx,NULL,&Status);
	if(!CheckFunc("CD97_Purchase Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}



/*---- Test the EP Cancel Purchase Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	ret=CD97_GetEPStatus(2,&ln,NULL,&Status);
	if(!CheckFunc("CD97_GetEPStatus ( Cancel Purchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CANCEL PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0x00;	// Amount
	tx[1] = 0x10;	// Amount
	tx[2] = 0x02;	// Date
	tx[3] = 0x02;	// Date
	tx[4] = 0x03;	// Time
	tx[5] = 0xA1;	// Time
	tx[6] = KVCSAM;	// Equipement Type
	ret=CD97_CancelPurchase(0,tx,NULL,&Status);
	if(!CheckFunc("CD97_CancelPurchase Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}




//********* TEST RT *******************************************************		
	
/*---- Test the UpdateRecord function in session (Reload) -----*/	
	// function OPEN SESSION
	ret=CD97_OpenSession(SESSION_LEVEL_RELOAD,0x09,1,&Session,&Status);
	if(!CheckFunc("CD97_OpenSession - File:Contract 1 - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\1\2\3\4",4);
	// function UpdateRecord
	ret=CD97_UpdateRecord(CD97_ACCESS_MODE_DEFAULT,0,1,4,tx,&Status);
	if(!CheckFunc("CD97_UpdateRecord Contract 1 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CD97_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CD97_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the UpdateRecord function in session (Valid) -----*/	
	// function OPEN SESSION
	ret=CD97_OpenSession(SESSION_LEVEL_VALID,0x08,1,&Session,&Status);
	if(!CheckFunc("CD97_OpenSession - File:Events Log - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x05\x06\x07\x08",4);
	// function UpdateRecord
	ret=CD97_UpdateRecord(CD97_ACCESS_MODE_DEFAULT,0,1,4,tx,&Status);
	if(!CheckFunc("CD97_UpdateRecord Contract 1 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CD97_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CD97_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	
/*---- Test the INVALIDATE function in Protected Mode -----*/		
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_PATH,SEL_2000,sizeof(SEL_2000),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 2000",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	ret=CD97_Invalidate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Invalidate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the REHABILITATE function in Protected Mode -----*/	
	// function REHABILITATE FILE
	ret=CD97_Rehabilitate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Rehabilitate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


//********* TEST MPP *******************************************************		
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_PATH,SEL_3115,sizeof(SEL_3115),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 3115",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
/*---- Test the UpdateRecord function in session (Valid) -----*/	
	// function OPEN SESSION
	ret=CD97_OpenSession(SESSION_LEVEL_VALID,0,1,&Session,&Status);
	if(!CheckFunc("CD97_OpenSession - File:(current)3115 - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x05\x06\x07\x08",4);
	// function UpdateRecord
	ret=CD97_UpdateRecord(CD97_ACCESS_MODE_DEFAULT,0,1,4,tx,&Status);
	if(!CheckFunc("CD97_UpdateRecord journal MPP ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CD97_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CD97_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INVALIDATE function in Protected Mode -----*/		
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_PATH,SEL_3100,sizeof(SEL_3100),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 3100",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	ret=CD97_Invalidate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Invalidate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the REHABILITATE function in Protected Mode -----*/		
	// function REHABILITATE FILE
	ret=CD97_Rehabilitate(CD97_ACCESS_MODE_PROTECTED,&Status);
	if(!CheckFunc("CD97_Rehabilitate",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}



/*---- Test the UpdateRecord function in session (Reload) -----*/	
	// function SELECT FILE
	ret=CD97_SelectFile(CD97_SEL_PATH,SEL_3102,sizeof(SEL_3102),NULL,&Status);
	if(!CheckFunc("CD97_SelectFile 3102",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	ret=CD97_OpenSession(SESSION_LEVEL_PERSO,0,1,&Session,&Status);
	if(!CheckFunc("CD97_OpenSession - File:(current)3102 - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\1\2\3\4",4);
	// function UpdateRecord
	ret=CD97_UpdateRecord(CD97_ACCESS_MODE_DEFAULT,0,1,4,tx,&Status);
	if(!CheckFunc("CD97_UpdateRecord 3102 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CD97_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CD97_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


CSC_CardEnd();


}
/****************************************************************/
void GenClassTestGTML(void)
/*****************************************************************
Test of Generic Class function with GTML

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	unsigned char tx[256];
	DWORD ret,ln;
	DWORD CounterValue;

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_1000[]={0x10,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_3115[]={0x31,0x00,0x31,0x15};
	BYTE SEL_3102[]={0x31,0x00,0x31,0x02};
	BYTE SEL_3100[]={0x31,0x00};
	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;
	sCARD_SecurParam Secur;



	Secur.AccMode=0;
	Secur.LID=0;
	Secur.SID=0;
	Secur.NKEY=0;
	Secur.RFU=0;

/*---- Test the PINStatus  Function -----*/
	ret=PINStatus(&Status);
	if(!CheckFunc("PINStatus (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Change PIN et Verify PIN -----------*/	
		
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	Secur.NKEY=RT_KEY3;
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (GTML) '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CHANGE PIN
	Secur.NKEY=RT_KEY1;
	ret=ChangePIN(Secur,OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("ChangePIN (GTML) '30 30 30 30' -> '31 31 31 31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	Secur.NKEY=RT_KEY3;
	ret=VerifyPIN(Secur,NEWPIN,&Status);
	if(!CheckFunc("VerifyPIN (GTML) '31 31 31 31''",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=GTML_SID_MF_ID;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord ID (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function CHANGE PIN
	Secur.NKEY=RT_KEY1;
	ret=ChangePIN(Secur,NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("ChangePIN (GTML) '31 31 31 31'' -> '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Select File -----*/	
	
	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=2)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function Select File 3F00
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("SelectFile (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=1)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Select File 2010
	ret=SelectFile(GEN_SEL_PATH,SEL_2010,sizeof(SEL_2010),tx,&Status);
	if(!CheckFunc("SelectFile 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=4)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Append Record in session -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=RT_KEY3;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,NULL,&Status);
	if(!CheckFunc("OpenSession - File (GTML) :None - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Append Record
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	Secur.SID=0;
	ret=AppendRecord(Secur,tx,29,&Status);
	if(!CheckFunc("AppendRecord 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=RT_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	Secur.SID=GTML_SID_RT_ALL_COUNTERS;
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=UpdateRecord(Secur,1,27,tx,&Status);
	if(!CheckFunc("UpdateRecord All counters (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x01\x01\x01",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");

	// function Increase and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=Increase(Secur,0,0x101010,&CounterValue,&Status);
	if(!CheckFunc("Increase 0x0A (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x111111) printf("\nProbleme lors de l'icrementation du compteur 0x0A");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x0A (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x11\x11\x11",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");

	// function Read Record and test the value 

	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=Decrease(Secur,0,0x101010,&CounterValue,&Status);
	if(!CheckFunc("Decrease 0x0A (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x010101) printf("\nProbleme lors de la decrementation du compteur 0x0A");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x0A (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x1\x1\x1",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");


	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=RT_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	Secur.SID=GTML_SID_RT_ALL_COUNTERS;
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=UpdateRecord(Secur,1,27,tx,&Status);
	if(!CheckFunc("UpdateRecord All counters (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x09\x09\x09",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");

	// function Increase and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=Increase(Secur,0,0x909090,&CounterValue,&Status);
	if(!CheckFunc("Increase 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x999999) printf("\nProbleme lors de l'icrementation du compteur 0x09");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x99\x99\x99",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");



	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=Decrease(Secur,0,0x909090,&CounterValue,&Status);
	if(!CheckFunc("Decrease 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x090909) printf("\nProbleme lors de la decrementation du compteur 0x09");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x9\x9\x9",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");


	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Update Record in session (Reload) -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=RT_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_CONTRACTS;
	ZeroMemory(tx,29);
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord 0x09 (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",29);
	if(ret!=0) printf("\nProbleme lors du contole du contrat");
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Write Record in session -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=RT_KEY3;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=WriteRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("WriteRecord RT_CONTRACTS (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord RT_CONTRACTS (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x9\x9\x9",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record in session (Reload) -----*/	

	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=RT_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ZeroMemory(tx,29);
	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",29);
	if(ret!=0) printf("\nProbleme lors du contole du contrat");
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Invalidate function in session (Valid) -----*/	

	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
	// function OPEN SESSION
	Secur.SID=0;
	Secur.NKEY=RT_KEY3;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Invalidate
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate RT (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Rehabilitate function in session (Reload) -----*/	

	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function OPEN SESSION
	Secur.SID=0;
	Secur.NKEY=RT_KEY1;
	ret=OpenSession(SESSION_LEVEL_PERSO,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Rehabilitate
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Reabilitate RT (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test Abort Session -----*/	
	// function OPEN SESSION
	Secur.SID=0;
	Secur.NKEY=RT_KEY2;
	ret=OpenSession(SESSION_LEVEL_PERSO,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Abort SESSION
	ret=AbortSecuredSession(&Status);
	if(!CheckFunc("AbortSecuredSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	else
		printf("OK \n");

return;

}

/****************************************************************/
void GenClassTestCD97(void)
/*****************************************************************
Test of Generic Class function with CD97

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	unsigned char tx[256];
	unsigned long Count1, Count2;
	DWORD ret,ln;
	BYTE i = 0;
	BYTE KVC = 0;
	BYTE FCI[30] = {0};
	BYTE DEDUCT2[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
	BYTE ADD4[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04};

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_1000[]={0x10,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_3115[]={0x31,0x00,0x31,0x15};
	BYTE SEL_3102[]={0x31,0x00,0x31,0x02};
	BYTE SEL_3113[]={0x31,0x00,0x31,0x13};
	BYTE SEL_3100[]={0x31,0x00};
	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;
	sCARD_SecurParam Secur;



/*	memcpy(tx,"\x1\x1\x1\x1\x2\x2\x2\x2\x3\x3\x3\x3\x4\x4\x4\x4\x5\x5\x5\x5\x6\x6\x6\x6\x7\x7\x7\x7",28);
	MultiIncrease(Secur,7,tx,tx2,&Status);
	MultiDecrease(Secur,7,tx,tx2,&Status);
	Increase(Secur,1,200,&CounterValue,&Status);
	Decrease(Secur,1,200,&CounterValue,&Status);
*/
	Secur.AccMode=0;
	Secur.LID=0;
	Secur.SID=0;
	Secur.NKEY=0;
	Secur.RFU=0;


/*---- Test the PINStatus  Function -----*/
	ret=PINStatus(&Status);
	if(!CheckFunc("PINStatus (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Verify PIN Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN - clear mode
	Secur.NKEY=0x00; // key = 0x00 => clear mode
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (CD97) - clear mode'0x30 0x30 0x30 0x30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
		
	// function VERIFY PIN - crypted mode
	Secur.NKEY=MF_KEY3;
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (CD97) - crypted mode'0x30 0x30 0x30 0x30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Change PIN Function -----*/	
	// function CHANGE PIN
	Secur.NKEY=MF_KEY1;
	ret=ChangePIN(Secur,OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("ChangePIN (CD97)'0x30 0x30 0x30 0x30' -> '0x31 0x31 0x31 0x31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	Secur.NKEY=MF_KEY3;
	ret=VerifyPIN(Secur,NEWPIN,&Status);
	if(!CheckFunc("VerifyPIN (CD97)- crypted mode'0x31 0x31 0x31 0x31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CHANGE PIN
	Secur.NKEY=MF_KEY1;
	ret=ChangePIN(Secur,NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("ChangePIN (CD97)'0x31 0x31 0x31 0x31' -> '0x30 0x30 0x30 0x30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	
/*---- Test the STATUS FILE Function -----*/	
	// function STATUS FILE
	ret=StatusFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("StatusFile 3F00 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INVALIDATE Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile 3F00 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.LID=0x3F00;
	Secur.NKEY=MF_KEY3;
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate 3F00 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the REHABILITATE Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile 3F00 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function REHABILITATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.LID=0x3F00;
	Secur.NKEY=MF_KEY1;
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Rehabilitate 3F00 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	

/*---- Test the UPDATE RECORD Function -----*/	
	// function UPDATE RECORD
	Secur.SID=0x0A;
	Secur.LID=0x202A;
	Secur.NKEY=RT_KEY2;
	memcpy(tx,"\0\0\0\0\0\0\0\0\0\0\0\x9\0\0",14);
	ret=UpdateRecord(Secur,1,14,tx,&Status);
	if(!CheckFunc("UpdateRecord - File:0x0A (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INCREASE PROTECTED Function -----*/	
	// function INCREASE
	Secur.SID=0x0A;
	Secur.LID=0x202A;
	Secur.NKEY=RT_KEY2;
	ret=Increase(Secur,1,4,&ln,&Status);
	if(!CheckFunc("Increase by 4 Counter 0x0A (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the DECREASE PROTECTED Function -----*/	
	// function DECREASE
	Secur.NKEY=RT_KEY3;
	ret=Decrease(Secur,1,2,&ln,&Status);
	if(!CheckFunc("Decrease by 2 Counter 0x0A (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// counter test
	if(ln!=0x000002)
	{
		Mess("\nCounter value fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INCREASE LG Function -----*/	
	// function INCREASE LG
	Secur.SID=0x0A;
	Secur.LID=0x202A;
	Secur.NKEY=RT_KEY2;
	ret=IncreaseLG(Secur,1,ADD4,&Status,&ln);
	if(!CheckFunc("Increase LG by 2 Counter 0x0A (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the DECREASE LG Function -----*/	
	// function DECREASE LG
	Secur.NKEY=RT_KEY3;
	ret=DecreaseLG(Secur,1,DEDUCT2,&Status,&ln);
	if(!CheckFunc("Decrease LG by 2 Counter 0x0A (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// counter test
	if(ln!=0x000002)
	{
		Mess("\nCounter value fail. %04X",ln);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the READ RECORD STAMPED Function -----*/	
	// function READ RECORD Stamped mode
	Secur.AccMode=GEN_ACCESS_MODE_STAMPED;
	Secur.NKEY=RT_KEY3;
	ret=ReadRecord(Secur,1,14,tx,&Status);
	if(!CheckFunc("ReadRecord Counter 0x0A (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if((tx[0]!=0x02)&&(tx[11]!=0x09))
	{
		Mess("\nRead Counter fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Session Function -----*/	
	// function OPEN SESSION
	Secur.NKEY=RT_KEY2;
	Secur.SID=0x0A;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,NULL,&Status);
	if(!CheckFunc("OpenSession - File:0x0A (CD97) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Append Record Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3115,sizeof(SEL_3115),NULL,&Status);
	if(!CheckFunc("SelectFile 3115 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function APPEND RECORD
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.LID=0x3115;
	Secur.SID=0;
	Secur.NKEY=MPP_KEY3;
	memcpy(tx,"\1\2\3\4",4);
	ret=AppendRecord(Secur,tx,4,&Status);
	if(!CheckFunc("AppendRecord 3115 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function READ RECORD
	ZeroMemory(tx,4);
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	ret=ReadRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("ReadRecord 3115 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if((tx[0]!=1)&&(tx[3]!=4))
	{
		Mess("\nRead 3115 (CD97) fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function READ RECORD STAMPED
	ZeroMemory(tx,4);
	Secur.AccMode=GEN_ACCESS_MODE_STAMPED;
	Secur.SID=0;
	Secur.LID=0x3115;
	Secur.NKEY=MPP_KEY3;
	ret=ReadRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("ReadRecord Stamped 3115 (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if((tx[0]!=1)&&(tx[3]!=4))
	{
		Mess("\nRead 3115 (CD97) fail.",0);
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//********* TEST EP *******************************************************		

/*---- Test the Reload EP Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	Secur.NKEY=EP_KEY2;
	ret=GetEPStatus_CD97(Secur,0,&ln,NULL,&Status);
	if(!CheckFunc("GetEPStatus ( Loading ) (CD97)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function RELOAD ELECTRONIC PURSE
	ZeroMemory(tx,10);
	tx[0] = 0x02; // Date				Charg1
	tx[1] = 0xC3; // Date				Charg1
	tx[2] = 0x00; // Money Batch		Charg1
	tx[3] = 0x02; // Money Batch		Charg1
	tx[4] = KVCSAM; // Equipement Type	Charg1
	tx[5] = 0x00;	// Amount			Charg2
	tx[6] = 0x00;	// Amount			Charg2
	tx[7] = 0x0F;	// Amount			Charg2
	tx[8] = 0x03;	// Time				Charg2
	tx[9] = 0xA1;	// Time				Charg2
	ret=ReloadEP_CD97(tx,&tx[5],&Status);
	if(!CheckFunc("ReloadEP_CD97 Value=256",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
/*---- Test the EP Purchase Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	Secur.NKEY=EP_KEY3;
	ret=GetEPStatus_CD97(Secur,1,&ln,NULL,&Status);
	if(!CheckFunc("GetEPStatus_CD97 ( Purchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0xFF;	// Amount
	tx[1] = 0xF0;	// Amount
	tx[2] = 0x02;	// Date
	tx[3] = 0x02;	// Date
	tx[4] = 0x03;	// Time
	tx[5] = 0xA1;	// Time
	tx[6] = KVCSAM;	// Equipement Type
	ret=Purchase_CD97(0,tx,NULL,&Status);
	if(!CheckFunc("Purchase_CD97 Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the EP Purchase Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	Secur.NKEY=EP_KEY3;
	ret=GetEPStatus_CD97(Secur,1,&ln,NULL,&Status);
	if(!CheckFunc("GetEPStatus_CD97 ( Purchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0xFF;	// Amount
	tx[1] = 0xF0;	// Amount
	tx[2] = 0x02;	// Date
	tx[3] = 0x02;	// Date
	tx[4] = 0x03;	// Time
	tx[5] = 0xA1;	// Time
	tx[6] = KVCSAM;	// Equipement Type
	ret=Purchase_CD97(0,tx,NULL,&Status);
	if(!CheckFunc("Purchase_CD97 Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the EP CancelPurchase Function -----*/	
	// function GET ELECTRONIC PURSE STATUS
	Secur.NKEY=EP_KEY3;
	ret=GetEPStatus_CD97(Secur,2,&ln,NULL,&Status);
	if(!CheckFunc("GetEPStatus_CD97 ( CancelPurchase )",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CANCEL PURCHASE
	ZeroMemory(tx,7);
	tx[0] = 0x00;	// Amount
	tx[1] = 0x10;	// Amount
	tx[2] = 0x02;	// Date
	tx[3] = 0x02;	// Date
	tx[4] = 0x03;	// Time
	tx[5] = 0xA1;	// Time
	tx[6] = KVCSAM;	// Equipement Type
	ret=CancelPurchase_CD97(0,tx,NULL,&Status);
	if(!CheckFunc("CancelPurchase_CD97 Value=16",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the INVALIDATE function in Protected Mode -----*/		
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_1000,sizeof(SEL_1000),NULL,&Status);
	if(!CheckFunc("SelectFile 1000 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.LID=0x1000;
	Secur.NKEY=EP_KEY3;
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the REHABILITATE function in Protected Mode -----*/	
	// function REHABILITATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.NKEY=EP_KEY1;
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Rehabilitate (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//********* TEST RT *******************************************************		
/*---- Test the UpdateRecord function in session (Reload) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x09;
	Secur.NKEY=RT_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Contract 1 (CD97) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\1\2\3\4",4);
	// function UpdateRecord
	Secur.SID=0x09;
	Secur.LID=0x2020;	
	ret=UpdateRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the UpdateRecord function in session (Valid) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x08;
	Secur.NKEY=RT_KEY3;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (CD97) - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x05\x06\x07\x08",4);
	// function UpdateRecord
	Secur.SID=0x08;
	ret=UpdateRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	
/*---- Test the INVALIDATE function in Protected Mode -----*/		
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),NULL,&Status);
	if(!CheckFunc("SelectFile 2000 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.LID=0x2000;
	Secur.NKEY=RT_KEY3;
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the REHABILITATE function in Protected Mode -----*/	
	// function REHABILITATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.NKEY=RT_KEY1;
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Rehabilitate (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


//********* TEST MPP *******************************************************		

	

/*---- Test the UpdateRecord function in session (3113) : Reload key level for Update & Increase in RJL & Valid for Decrease) -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3113,sizeof(SEL_3113),NULL,&Status);
	if(!CheckFunc("SelectFile 3113 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0;
	Secur.LID=0x3113;
	Secur.NKEY=MPP_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:3113 (CD97) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x00\x00\x00\x31\x32\x33\x34\x35\x00\x00\x00\xFF\xFF\xFF  " ,14);
	// function UpdateRecord
	ret=UpdateRecord(Secur,1,14,tx,&Status);
	if(!CheckFunc("UpdateRecord Compteur MPP (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	
/*---- Test the Increase function in session (3113) : Reload key level for Update & Increase in RJL & Valid for Decrease) -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3113,sizeof(SEL_3113),NULL,&Status);
	if(!CheckFunc("SelectFile 3113 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0;
	Secur.LID=0x3113;
	Secur.NKEY=MPP_KEY2;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:3113 (CD97) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	Count1=2;
	// function Increase (Secure, Icount, Value, NewValue, Status)
	ret=Increase(Secur,0,Count1,&Count2, &Status);
	if(!CheckFunc("Increase Compteur 1 MPP (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	/*	Write record impossible dans le repertoire 3100 !!!!
	ret=SelectFile(GEN_SEL_PATH,SEL_3113,sizeof(SEL_3113),NULL,&Status);
	if(!CheckFunc("SelectFile 3113 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	Secur.LID = 0x3113;
	ret=WriteRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("WriteRecord Compteur MPP (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	*/

/*---- Test the UpdateRecord function in session (Valid key level in RJL for APPEND and UPDATE on 3115) -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3115,sizeof(SEL_3115),NULL,&Status);
	if(!CheckFunc("SelectFile 3115 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0;
	Secur.LID=0x3115;
	Secur.NKEY=MPP_KEY3;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:3115 (CD97) - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x05\x06\x07\x08",4);
	// function UpdateRecord
	ret=UpdateRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function AppendRecord
	ret=AppendRecord(Secur,tx,4,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Decrease function in session (Valid for Decrease on 3113) -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3113,sizeof(SEL_3113),NULL,&Status);
	if(!CheckFunc("SelectFile 3113 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0;
	Secur.LID=0x3113;
	Secur.NKEY=MPP_KEY3;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:3113 (CD97) - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	Count1=1;;
	// function Decrease
	ret=Decrease(Secur,0, Count1, &Count2, &Status);
	if(!CheckFunc("Decrease Counter 1 MPP (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}



/*---- Test the INVALIDATE function in Protected Mode -----*/		
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3100,sizeof(SEL_3100),NULL,&Status);
	if(!CheckFunc("SelectFile 3100 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function INVALIDATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.LID=0x3100;
	Secur.NKEY=MPP_KEY3;
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the REHABILITATE function in Protected Mode -----*/		
	// function REHABILITATE FILE
	Secur.AccMode=GEN_ACCESS_MODE_PROTECTED;
	Secur.NKEY=MPP_KEY1;
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Rehabilitate (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}



/*---- Test the UpdateRecord function in session (perso) -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_3102,sizeof(SEL_3102),NULL,&Status);
	if(!CheckFunc("SelectFile 3102 (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0;
	Secur.LID=0x3102;
	Secur.NKEY=MPP_KEY1;
	ret=OpenSession(SESSION_LEVEL_PERSO,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:3102 Public params MPP (CD97) - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\1\2\3\4",4);
	// function UpdateRecord
	ret=UpdateRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("UpdateRecord 3102 Public params MPP (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CD97) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test Abort Secured Session -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x09;
	Secur.NKEY=0x01;
	Secur.RFU=0x00;
	ret=CD97_OpenSessionExt(SESSION_LEVEL_VALID, Secur, 1, 0, 0, &Status, &Session, &KVC);
	if(!CheckFunc("CD97_OpenSession - File:(current)3102 - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	printf("\n");

	// function Abort Session
//	ret=CD97_CloseSessionExt(0, 0, &Status, &ln, tx);
	ret=CD97_AbortSecuredSession(&Status);
	if(!CheckFunc("CD97_AbortSecuredSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	else
		printf("OK\n");

	CSC_CardEnd();

}



/****************************************************************/
void GenClassTestCT2000(void)
/*****************************************************************
Test of Generic Class function with CT2000

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	unsigned char tx[256],tx2[256];
	DWORD ret,ln,CounterValue;
	BYTE KVC;

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_2001[]={0x20,0x00,0x20,0x01};
	BYTE SEL_2040[]={0x20,0x00,0x20,0x40};
	BYTE SEL_2020[]={0x20,0x00,0x20,0x20};
	BYTE SEL_2069[]={0x20,0x00,0x20,0x69};
	BYTE SEL_202A[]={0x20,0x00,0x20,0x2A};


	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;
	sCARD_SecurParam Secur;

	Secur.AccMode=0;
	Secur.SID=0;
	Secur.LID=0;
	Secur.NKEY=0;
	Secur.RFU=0;

/*---- Test the PINStatus  Function -----*/
	ret=PINStatus(&Status);
	if(!CheckFunc("PINStatus (CT2000)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	
/*---- Test the Verify PIN Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (CT2000)",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN - clear mode
	Secur.NKEY=0x00;	// NKEY = 0x00 => clear mode
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (CT2000) - clear mode'0x30 0x30 0x30 0x30'",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN - crypted mode
	Secur.NKEY=MF_INV_KEY;
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (CT2000) - crypted mode'0x30 0x30 0x30 0x30'",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Change PIN Function -----*/	
	// function CHANGE PIN
	Secur.NKEY=MF_PER_KEY;
	ret=ChangePIN(Secur,OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("ChangePIN (CT2000)'0x30 0x30 0x30 0x30' -> '0x31 0x31 0x31 0x31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function VERIFY PIN
	Secur.NKEY=MF_INV_KEY;
	ret=VerifyPIN(Secur,NEWPIN,&Status);
	if(!CheckFunc("VerifyPIN (CT2000) - crypted mode'0x31 0x31 0x31 0x31'",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CHANGE PIN
	Secur.NKEY=MF_PER_KEY;
	ret=ChangePIN(Secur,NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("ChangePIN (CT2000)'0x31 0x31 0x31 0x31' -> '0x30 0x30 0x30 0x30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	

/*---- Test the Select File -----*/	
	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=2)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Select File 3F00
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("SelectFile (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=1){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Select File 2010
	ret=SelectFile(GEN_SEL_PATH,SEL_2010,sizeof(SEL_2010),tx,&Status);
	if(!CheckFunc("SelectFile 20 10 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=4){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the STATUS FILE Function -----*/	
	// function STATUS FILE
	ret=StatusFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("StatusFile 3F00 (CT2000)",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the LOCK/UNLOCK Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (CT2000)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function VERIFY PIN
	Secur.NKEY=MF_INV_KEY;
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (CT2000)'0x30 0x30 0x30 0x30'",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Lock Card
	ret=Lock_Unlock(00,&Status);
	if(!CheckFunc("Lock DF 2000 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[15]!=0x04){
		printf("\nCard Lock Error");
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Unlock Card
	ret=Lock_Unlock(0x01,&Status);
	if(!CheckFunc("Lock DF 2000 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[15]!=0x00){
		printf("\nCard Lock Error");
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//********* TEST MF *******************************************************		
/*---- Test the INVALIDATE Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (CT2000)",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.NKEY=MF_INV_KEY;
	Secur.SID=0;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Contract 1 (CT2000) - Valid",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Invalidate
	Secur.LID=0x3F00;
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[15]!=0x01){
		printf("\nCard Lock Error");
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
/*---- Test the REHABILITATE Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (CT2000)",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.NKEY=MF_UPD_KEY;
	Secur.SID=0;
	ret=OpenSession(SESSION_LEVEL_PERSO,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Contract 1 (CT2000) - Perso",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Invalidate
	Secur.LID=0x3F00;
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[15]!=0x00){
		printf("\nCard Lock Error");
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//********* TEST "Billetique" *******************************************************		

/*---- Test the UpdateRecord function in session (Reload) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x09;
	Secur.NKEY=RT_PAR_KEY;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Contract 1 (CT2000) - Reload",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	// function UpdateRecord
	Secur.SID=0x09;
	Secur.LID=0x2020;	
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x09;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	if(ret!=0) printf("\nChecking contrat Error");


/*---- Test the UpdateRecord function in session (Reload) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x09;
	Secur.NKEY=RT_PAR_KEY;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Contract 1 (CT2000) - Reload",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\0\0\0\0",4);
	// function UpdateRecord
	Secur.SID=0x09;
	Secur.LID=0x2020;	
	ret=UpdateRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x09;
	ret=ReadRecord(Secur,1,4,tx,&Status);
	if(!CheckFunc("ReadRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\0\0\0\0",4);
	if(ret!=0) printf("\nChecking contrat Error");


/*---- Test the INVALIDATE Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),NULL,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000)",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.NKEY=RT_INV_KEY;
	Secur.SID=0;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:none (CT2000) - Valid",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Invalidate
	Secur.LID=0x2000;
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate DF 20 00  (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Select File
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[15]!=0x01)	{
		printf("\nCard invalidation Error");
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
/*---- Test the REHABILITATE Function -----*/	
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),NULL,&Status);
	if(!CheckFunc("SelectFile 2000 (CT2000)",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.NKEY=RT_UPD_KEY;
	Secur.SID=0;
	ret=OpenSession(SESSION_LEVEL_PERSO,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:none (CT2000) - Perso",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Invalidate
	Secur.LID=0x2000;
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Rehabilitate DF 20 00 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Select File
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[15]!=0x00)	{
		printf("\nCard Rehabilitation Error");
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the AppendRecord function in session (Valid) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x08;
	Secur.LID=0x2010;
	Secur.NKEY=RT_INV_KEY;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (CT2000) - Valid",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	// function AppendRecord
	Secur.SID=0x08;
	ret=AppendRecord(Secur,tx,29,&Status);
	if(!CheckFunc("AppendRecord Event Log (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x08;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	if(ret!=0) printf("\nChecking contrat Error");

/*---- Test the AppendRecord function in Extended session (Valid) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x08;
	Secur.LID=0x2010;
	Secur.NKEY=RT_INV_KEY;
	ret=OpenSessionExt(SESSION_LEVEL_VALID,Secur,1,&KVC,&Session,&Status);
	if(!CheckFunc("OpenSessionExt - File:Events Log (CT2000) - Valid",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	// function AppendRecord
	Secur.SID=0x08;
	ret=AppendRecord(Secur,tx,29,&Status);
	if(!CheckFunc("AppendRecord Event Log (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x08;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	if(ret!=0) printf("\nChecking contrat Error");

/*---- Test the WriteRecord function in session (Valid) -----*/	
	// function OPEN SESSION
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=0x09;
	Secur.LID=0x2020;
	Secur.NKEY=RT_INV_KEY;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Contract 1 (CT2000) - Valid",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	// function WriteRecord
	Secur.SID=0x09;
//	Secur.LID=0x2020;
	ret=WriteRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("WriteRecord Contract 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x09;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord Contract 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29",29);
	if(ret!=0) printf("\nChecking contrat 1 Error");



/*---- Test the Increase function in session (Reload) -----*/	
	//Counters Initialization
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
 	Secur.SID=0;
	Secur.NKEY=RT_PAR_KEY;
	//Open Session
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - (CT2000) - Reload",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ZeroMemory(tx,sizeof(tx));
	// function UpdateRecord
	Secur.SID=0x19;
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord AllCounter (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Close Session
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Select File 202A
	ret=SelectFile(GEN_SEL_PATH,SEL_202A,sizeof(SEL_202A),tx,&Status);
	if(!CheckFunc("SelectFile 20 2A (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.NKEY=RT_PAR_KEY;
	//Open Session
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - (CT2000) - Reload",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Increase
	Secur.SID=0x0;
	Secur.LID=0x0;
	ret=Increase(Secur,1,200,&CounterValue,&Status);
	if(!CheckFunc("Increase Simulated Counter 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x19;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord Contract 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x0\x0\xC8",3);
	if(ret!=0) printf("\nChecking counter 1 Error");
	

/*---- Test the Decrease function in session (Valid) -----*/	
	// function Select File 202A
	ret=SelectFile(GEN_SEL_PATH,SEL_202A,sizeof(SEL_202A),tx,&Status);
	if(!CheckFunc("SelectFile 20 2A (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.NKEY=RT_INV_KEY;
	// Open Session
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - (CT2000) - Valid",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Decrease
	Secur.SID=0x0;
	ret=Decrease(Secur,1,200,&CounterValue,&Status);
	if(!CheckFunc("Decrease Simulated Counter 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x19;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("Decrease Counter 1 (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x0\x0\x0",3);
	if(ret!=0) printf("\nChecking counter 1 Error");

/*---- Test the MultiIncrease function in session (Valid) -----*/	
	//Counters Initialization
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
 	Secur.SID=0;
	Secur.NKEY=RT_PAR_KEY;
	//Open Session
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - (CT2000) - Reload",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ZeroMemory(tx,sizeof(tx));
	// function UpdateRecord
	Secur.SID=0x19;
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord AllCounter (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function Close Session
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
 	Secur.SID=0x08;
	Secur.NKEY=RT_PAR_KEY;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (CT2000) - Reload",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x1\x1\x1\x1\x2\x2\x2\x2\x3\x3\x3\x3\x4\x4\x4\x4\x5\x5\x5\x5\x6\x6\x6\x6\x7\x7\x7\x7",28);
	// function MultiIncrease
	Secur.SID=0x19;
	Secur.LID=0x2069;
	ret=MultiIncrease(Secur,7,tx,tx2,&Status);
	if(!CheckFunc("MultiIncrease Event Log (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x19;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("readRecord All Counter (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7",21);
	if(ret!=0) printf("\nChecking All counter Error");
	
/*---- Test the MultiDecrease function in session (Valid) -----*/	
	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
 	Secur.SID=0x08;
	Secur.NKEY=RT_INV_KEY;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (CT2000) - Valid",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	memcpy(tx,"\x1\x1\x1\x1\x2\x2\x2\x2\x3\x3\x3\x3\x4\x4\x4\x4\x5\x5\x5\x5\x6\x6\x6\x6\x7\x7\x7\x7",28);
	// function MultiIncrease
	Secur.SID=0x19;
	Secur.LID=0x2069;
	ret=MultiDecrease(Secur,7,tx,tx2,&Status);
	if(!CheckFunc("MultiDecrease Event Log (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	// function ReadRecord
	ZeroMemory(tx,sizeof(tx));
	Secur.SID=0x19;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord All Counter (CT2000) ",ret,&Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	ret=memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",21);
	if(ret!=0) printf("\nChecking All counter Error");	

	CSC_CardEnd();

}


/****************************************************************/
void CTSClassTest(void)
/*****************************************************************
Test of CTS class with ticket

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	unsigned char Data[50], DataToWrite[40], DataInCTS[40];
	DWORD ret;
	BYTE Status[2];

/*---- Test the Active CTx function (succes) -----*/	
	ret= CTx_Active (Data, Status);
	if(!CheckFuncCTS("Active CTX", ret, Status))	{
 		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Read CTx function (succes) -----*/	
	ret= CTx_Read (0x00, 0x1F, Data, Status);
	if(!CheckFuncCTS("Read CTx", ret, Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//---- Test the Update CTx function (succes) -----	
//*************************************************************
//********* Update sans ancienne valeur (@ paire, nb pairs)
	DataToWrite[0] = 0x11;
	DataToWrite[1] = 0x11;

	DataInCTS[0] = 0xEE;
	DataInCTS[1] = 0xEE;

	ret= CTx_Update (0x10, 0x02,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x11) || (Data[1] != 0x11) ){
		printf("Data = %02X %02X\n",Data[0], Data[1]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
//********* Update avec ancienne valeur (@ paire, nb pairs)
	DataToWrite[0] = 0x55;
	DataToWrite[1] = 0x55;

	DataInCTS[0] = 0x11;
	DataInCTS[1] = 0x11;

	ret= CTx_Update (0x10, 0x02,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x55) || (Data[1] != 0x55) ){
		printf("Data = %02X %02X\n",Data[0], Data[1]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//*************************************************************
//********* Update sans ancienne valeur (@ paire, nb impairs)
	DataToWrite[0] = 0x11;
	DataToWrite[1] = 0x11;
	DataToWrite[2] = 0x11;

	DataInCTS[0] = 0xEE;
	DataInCTS[1] = 0xEE;
	DataInCTS[2] = 0xEE;

	ret= CTx_Update (0x10, 0x03,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x11) || (Data[1] != 0x11) || (Data[2] != 0x11) ){
		printf("Data = %02X %02X %02X\n",Data[0], Data[1], Data[2]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
//********* Update avec ancienne valeur (@ paire, nb impairs)
	DataToWrite[0] = 0x44;
	DataToWrite[1] = 0x44;
	DataToWrite[2] = 0x44;

	DataInCTS[0] = 0x11;
	DataInCTS[1] = 0x11;
	DataInCTS[2] = 0x11;

	ret= CTx_Update (0x10, 0x03,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x44) || (Data[1] != 0x44) || (Data[2] != 0x44) ){
		printf("Data = %02X %02X %02X\n",Data[0], Data[1], Data[2]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//*************************************************************
//********* Update sans ancienne valeur (@ impaire, nb impairs)
	DataToWrite[0] = 0x11;
	DataToWrite[1] = 0x11;
	DataToWrite[2] = 0x11;

	DataInCTS[0] = 0xEE;
	DataInCTS[1] = 0xEE;
	DataInCTS[2] = 0xEE;

	ret= CTx_Update (0x0B, 0x03,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x11) || (Data[1] != 0x11) || (Data[2] != 0x11) ){
		printf("Data = %02X %02X %02X\n",Data[0], Data[1], Data[2]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
//********* Update avec ancienne valeur (@ impaire, nb impairs)
	DataToWrite[0] = 0x44;
	DataToWrite[1] = 0x44;
	DataToWrite[2] = 0x44;

	DataInCTS[0] = 0x11;
	DataInCTS[1] = 0x11;
	DataInCTS[2] = 0x11;

	ret= CTx_Update (0x0B, 0x03,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x44) || (Data[1] != 0x44) || (Data[2] != 0x44) ){
		printf("Data = %02X %02X %02X\n",Data[0], Data[1], Data[2]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
//*************************************************************
//********* Update sans ancienne valeur (@ impaire, nb pairs)
	DataToWrite[0] = 0xAA;
	DataToWrite[1] = 0xAA;
	DataToWrite[2] = 0xAA;
	DataToWrite[3] = 0xAA;

	DataInCTS[0] = 0xEE;
	DataInCTS[1] = 0xEE;
	DataInCTS[2] = 0xEE;
	DataInCTS[3] = 0xEE;

	ret= CTx_Update (0x0B, 0x04,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0xAA) || (Data[1] != 0xAA) || (Data[2] != 0xAA) || (Data[3] != 0xAA)){
		printf("Data = %02X %02X %02X %02X\n",Data[0], Data[1], Data[2], Data[3]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
//********* Update avec ancienne valeur (@ impaire, nb pairs)
	DataToWrite[0] = 0x77;
	DataToWrite[1] = 0x77;
	DataToWrite[2] = 0x77;
	DataToWrite[3] = 0x77;

	DataInCTS[0] = 0xAA;
	DataInCTS[1] = 0xAA;
	DataInCTS[2] = 0xAA;
	DataInCTS[3] = 0xAA;

	ret= CTx_Update (0x0B, 0x04,
						DataToWrite, DataInCTS,
						Data, Status);

	if ( (Data[0] != 0x77) || (Data[1] != 0x77) || (Data[2] != 0x77) || (Data[3] != 0x77)){
		printf("Data = %02X %02X %02X %02X\n",Data[0], Data[1], Data[2], Data[3]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Update CTx", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

//---- Test the Release CTS function (succes) -----	
	ret= CTx_Release ( 0x00, Status);
	if (  (ret==RCSC_Ok) && (*Status==0x02) ){
		printf(".");
	}
	else{
		Mess("CTx_Release",ret);
		printf("Status = %02X \n", *Status);
		printf("\nError CTs Release\n");// display the command return status value
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
	}
}


/****************************************************************/
void CTS512BClassTest(void)
/*****************************************************************
Test of CTM class 

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	BYTE	RFU=0x00;
	BYTE	nbTickets;
	BYTE	param=0x00;
	BYTE	dataRead[64];
	BYTE	dataToUpdate4[4]={0x11,0x22,0x33,0x44};
	BYTE	dataToUpdate5[5]={0x11,0x22,0x33,0x44,0x55};
	BYTE	dataToUpdate54[54];
	BYTE	serialNumbers[10];
	BYTE	serialNumber[2];
	BYTE	serialNumberRead[2];
	BYTE	status;
	
	DWORD	ret;
	BYTE	indice;

	for (indice=0;indice<54;indice++) dataToUpdate54[indice]=0x00;


/*---- Test the LIST function (succes) -----*/	
	ret=CTx512B_List(RFU,&nbTickets,serialNumbers,&status);
	
	if(  (ret==RCSC_Ok)&&( (status==0x01)||(status==0x03) ) )
	{
		printf(".");	
	}
	else
	{
		Mess("List CTM",ret);
		printf("Status = %02X \n",status);
		printf("\n\n");// display the command return status value
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
	
/*---- Test the Select CTS512B function (succes) ---*/
	
	serialNumber[0]=serialNumbers[0];	// first CTM selected
	serialNumber[1]=serialNumbers[1];

	ret=CTx512B_Select(serialNumber,serialNumberRead,&status);
	if(!CheckFuncCTM("Active CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Read CTS512B function, 10 bytes (succes) -----*/	
	ret=CTx512B_Read (0x0A,0x0A,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Read CTS512B function, 64 bytes (succes) -----*/	
	ret=CTx512B_Read (0x00,0x3F,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update CTS512B function, 4 bytes, even address (succes) -----*/
	ret=CTx512B_Update(0x0A,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update CTS512B function, 4 bytes, odd address (succes) -----*/
	ret=CTx512B_Update(0x0B,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update CTS512B function, 5 bytes, even address (succes) -----*/
	ret=CTx512B_Update(0x0A,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update CTS512B function, 5 bytes, odd address (succes) -----*/
	ret=CTx512B_Update(0x0B,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update CTS512B function, whole writable memory (succes) -----*/
	ret=CTx512B_Update(0x0A,sizeof(dataToUpdate54),dataToUpdate54,dataRead,&status);
	if(!CheckFuncCTM("Read CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
/*---- Test the Release CTS512B function (succes) -----*/
	ret=CTx512B_Halt(param,&status);
	if(!CheckFuncCTM("Halt CTM", ret, status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
}


/****************************************************************/
void CTx512xClassTest(void)
/*****************************************************************
Test of CTx512x class 

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	BYTE	RFU=0x00;
	BYTE	nbTickets;
	BYTE	param=0x00;
	BYTE	dataRead[64];
	BYTE	dataToUpdate4[4]={0x11,0x22,0x33,0x44};
	BYTE	dataToUpdate5[5]={0x11,0x22,0x33,0x44,0x55};
	BYTE	dataToUpdate54[54];
	BYTE	serialNumbers[10];
	BYTE	serialNumber[2];
	BYTE	serialNumberRead[2];
	BYTE	status;
	BYTE	dataSAMLength;
	BYTE	dataSam[5];
	
	DWORD	ret;
	BYTE	indice;
                                                                                                                                                                                                                                                      
	DWORD	choice;
	BOOL	exit = FALSE;

	BYTE	atr[32]; 
	DWORD	atrLn;
	BYTE	COM;
	sCARD_SearchExt search;
	DWORD	search_mask;

	for (indice=0;indice<54;indice++) dataToUpdate54[indice]=0x00;


	while (exit == FALSE)
	{
		
		printf("\n-------------------------------------------------------\n");
		printf("\n              -> CTx512xClassTest ---------------------\n");
		printf("\nWhich Test ?"); 
		printf("\n 1:CTS512B (present a CTS512B)");
		printf("\n 2:CTS512A (present a CTS512A)");
		printf("\n 3:CTM512B (present a CTM512B) ...WARNING!! personalized if not already!!...");
		printf("\n x:exit");

		choice=_getch();
		
		switch(choice)
		{

		case '1':

/*-------------------------------------------------------
------------------- CTS512B test ------------------------
-------------------------------------------------------*/

/*---- Test the LIST function (succes) -----*/	
			ret=CTx512x_List(1,&nbTickets,serialNumbers,&status);
			
			if(  (ret==RCSC_Ok)&&( (status==0x01)||(status==0x03) ) )
			{
				printf(".");	
			}
			else
			{
				Mess("List CTM",ret);
				printf("Status = %02X \n",status);
				printf("\n\n");// display the command return status value
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
			
/*---- Test the Select CTx512x function (succes) ---*/
			
			serialNumber[0]=serialNumbers[0];	// first CTM selected
			serialNumber[1]=serialNumbers[1];

			ret=CTx512x_Select(serialNumber,serialNumberRead,&status);
			if(!CheckFuncCTM("Select CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Read CTx512x function, 10 bytes (succes) -----*/	
			ret=CTx512x_Read (0x0A,0x0A,dataRead,&status);
			if(!CheckFuncCTM("Read CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Read CTx512x function, 64 bytes (succes) -----*/	
			ret=CTx512x_Read (0x00,0x3F,dataRead,&status);
			if(!CheckFuncCTM("Read CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 4 bytes, even address (succes) -----*/
			ret=CTx512x_Update(0x0A,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 4 bytes, odd address (succes) -----*/
			ret=CTx512x_Update(0x0B,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 5 bytes, even address (succes) -----*/
			ret=CTx512x_Update(0x0A,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 5 bytes, odd address (succes) -----*/
			ret=CTx512x_Update(0x0B,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, whole writable memory (succes) -----*/
			ret=CTx512x_Update(0x0A,sizeof(dataToUpdate54),dataToUpdate54,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			
/*---- Test the Write CTx512x function, 4 bytes, even address (succes) -----*/
			ret=CTx512x_Write(0x0A,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 4 bytes, odd address (succes) -----*/
			ret=CTx512x_Write(0x0B,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 5 bytes, even address (succes) -----*/
			ret=CTx512x_Write(0x0A,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 5 bytes, odd address (succes) -----*/
			ret=CTx512x_Write(0x0B,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, whole writable memory (succes) -----*/
/*			ret=CTx512x_Write(0x0A,sizeof(dataToUpdate54),dataToUpdate54,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
*/
/*---- Test the Release CTx512x function (succes) -----*/
			ret=CTx512x_Halt(param,&status);
			if(!CheckFuncCTM("Halt CTM", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			CSC_AntennaOFF();

			break;	// end of CTS512B test

/*-------------------------------------------------------
------------------- CTS512A test ------------------------
-------------------------------------------------------*/

			case '2':	// CTS512A test

/*---- search a CTS512A, in ISOA mode (succes) -----*/			
				search.ISOA = 1;
				search_mask = SEARCH_MASK_ISOA;
				ret = CSC_SearchCardExt(&search,search_mask,1,0x77,&COM,&atrLn,atr);
				if ((ret != RCSC_Ok) || (COM != 0x08))
				{
					CSC_AntennaOFF();
					CSC_Close();
					SetErrorTo1();
					return;
				}

/*---- Test the Read CTx512x function, 10 bytes (succes) -----*/	
			ret=CTx512x_Read (0x10,0x0A,dataRead,&status);
			if(!CheckFuncCTM("Read CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Read CTx512x function, 64 bytes (succes) -----*/	
			ret=CTx512x_Read (0x00,0x3F,dataRead,&status);
			if(!CheckFuncCTM("Read CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 4 bytes, even address (succes) -----*/
			ret=CTx512x_Update(0x10,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 4 bytes, odd address (succes) -----*/
			ret=CTx512x_Update(0x11,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 5 bytes, even address (succes) -----*/
			ret=CTx512x_Update(0x10,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, 5 bytes, odd address (succes) -----*/
			ret=CTx512x_Update(0x11,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Update CTx512x function, whole writable memory (succes) -----*/
			ret=CTx512x_Update(0x10,48,dataToUpdate54,dataRead,&status);
			if(!CheckFuncCTM("Update CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 4 bytes, even address (succes) -----*/
			ret=CTx512x_Write(0x10,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 4 bytes, odd address (succes) -----*/
			ret=CTx512x_Write(0x11,sizeof(dataToUpdate4),dataToUpdate4,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 5 bytes, even address (succes) -----*/
			ret=CTx512x_Write(0x10,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, 5 bytes, odd address (succes) -----*/
			ret=CTx512x_Write(0x11,sizeof(dataToUpdate5),dataToUpdate5,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Write CTx512x function, whole writable memory (succes) -----*/
			ret=CTx512x_Write(0x10,48,dataToUpdate54,dataRead,&status);
			if(!CheckFuncCTM("Write CTS512A", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
/*---- Test the Release CTx512x function (succes) -----*/
			ret=CTx512x_Halt(param,&status);
			if(!CheckFuncCTM("Halt CTM", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			break;	// end of CTS512A test

			case '3':

/*-------------------------------------------------------
------------------- CTM512B test ------------------------
-------------------------------------------------------*/

/*---- Test the LIST function (succes) -----*/	
			ret=CTx512x_List(1,&nbTickets,serialNumbers,&status);
			
			if(  (ret==RCSC_Ok)&&( (status==0x01)||(status==0x03) ) )
			{
				printf(".");	
			}
			else
			{
				Mess("List CTM",ret);
				printf("Status = %02X \n",status);
				printf("\n\n");// display the command return status value
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
			
/*---- Test the Select CTx512x function (succes) ---*/
			
			serialNumber[0]=serialNumbers[0];	// first CTM selected
			serialNumber[1]=serialNumbers[1];

			ret=CTx512x_Select(serialNumber,serialNumberRead,&status);
			if(!CheckFuncCTM("Select CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Read CTx512x function, 10 bytes (succes) -----*/	
			ret=CTx512x_Read (0x0A,0x0A,dataRead,&status);
			if(!CheckFuncCTM("Read CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the CTx512x_WriteKey function (succes) -----*/	
			ret=CTx512x_WriteKey(0x21,0x00,&status,&dataSAMLength,dataSam);
			if ((status == 0x07) && (ret == RCSC_Ok))
				{
					printf("\n!CTM already personalized... continuing...");
				}
				else
				{			
					if(!CheckFuncCTM("WriteKey CTM512B", ret, status))
					{	
						CSC_AntennaOFF();
						CSC_Close();
						SetErrorTo1();
						return;
					}
					else
					{
						printf("\n!!CTM personalized!!");
					}
				}

/*---- Antenna OFF -----*/	
			CSC_AntennaOFF();

/*---- Test the LIST function (succes) -----*/	
			ret=CTx512x_List(1,&nbTickets,serialNumbers,&status);
			
			if(  (ret==RCSC_Ok)&&( (status==0x01)||(status==0x03) ) )
			{
				printf(".");	
			}
			else
			{
				Mess("List CTM",ret);
				printf("Status = %02X \n",status);
				printf("\n\n");// display the command return status value
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
			
/*---- Test the Select CTx512x function (succes) ---*/
			
			serialNumber[0]=serialNumbers[0];	// first CTM selected
			serialNumber[1]=serialNumbers[1];

			ret=CTx512x_Select(serialNumber,serialNumberRead,&status);
			if(!CheckFuncCTM("Select CTS512B", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Authenticate CTx512x function (succes) -----*/
			ret=CTx512x_Authenticate(0x14,0x21,0x00,&status,&dataSAMLength,dataSam);
			if(!CheckFuncCTM("Authenticate CTM", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

/*---- Test the Release CTx512x function (succes) -----*/
			ret=CTx512x_Halt(param,&status);
			if(!CheckFuncCTM("Halt CTM", ret, status))	{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			break;

			case 'x':
			exit = TRUE;
			break;

			default:
			break;
			
		}

	}
}




/******************************************************************/
void CertificatClassTest(void)
/*****************************************************************
Test of Certificat class with ticket

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{

	unsigned char Buffer[50], Certificat[50];
	DWORD ret;
	BYTE Status[2], i;

/*---- Test the Give Certificat function with certificat length =2 (succes) -----*/	
// Certificat de longueur 2, cle 0x1F
	for (i=0; i<7; i++)		// diversifiant
		Buffer[i] = 0x00;
	Buffer[7] = 0x01;

	Buffer[8] = 0x01;		// data
	Buffer[9] = 0x02;
	Buffer[10]= 0x03;
	Buffer[11]= 0x04;
	// Give Certificat : Clé 1F pour longueur 2
	// Check Certificat : Clé 20 pour longueur 2
	ret= GiveCertificate (0x1F, 0x00,
							  0x0C, Buffer,
							  0x02, Certificat, Status );
	if ( (Certificat[0] != 0x5C) || (Certificat[1] != 0x67) ){
		printf("Certificat = %02X %02X \n",Certificat[0], Certificat[1]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Give Certificate", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Check Certificat function (succes) -----*/	
// Certificat de longueur 2, cle 0x20
	for (i=0; i<7; i++)		// diversifiant
		Buffer[i] = 0x00;
	Buffer[7] = 0x01;

	Buffer[8] = 0x01;		// data
	Buffer[9] = 0x02;
	Buffer[10]= 0x03;
	Buffer[11]= 0x04;

	ret= CheckCertificate (0x20, 0x00,
							  0x0C, Buffer,
							  0x02, Certificat, Status );
	if(!CheckFuncCTS("Check Certificate", ret, Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Give Certificat function with certificat length =4 (succes) -----*/	
// Certificat de longueur 4, cle 0x1D
	for (i=0; i<7; i++)		// diversifiant
		Buffer[i] = 0x00;
	Buffer[7] = 0x01;

	Buffer[8] = 0x01;		// data
	Buffer[9] = 0x02;
	Buffer[10]= 0x03;
	Buffer[11]= 0x04;
	// Give Certificat : Clé 1D pour longueur 4
	// Check Certificat : Clé 1E pour longueur 4
	ret= GiveCertificate (0x1D, 0x00,
							  0x0C, Buffer,
							  0x04, Certificat, Status );
	if ( (Certificat[0] != 0xC0) || (Certificat[1] != 0x61) || (Certificat[2] != 0x1B) || (Certificat[3] != 0xA6) ){
		printf("Certificat = %02X %02X %02X %02X \n",Certificat[0], Certificat[1], Certificat[2], Certificat[3]);
		printf("\n\n");// display the command return status value
	}
	if(!CheckFuncCTS("Give Certificate", ret, Status)){
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Check Certificat function (succes) -----*/	
// Certificat de longueur 2, cle 0x20
	for (i=0; i<7; i++)		// diversifiant
		Buffer[i] = 0x00;
	Buffer[7] = 0x01;

	Buffer[8] = 0x01;		// data
	Buffer[9] = 0x02;
	Buffer[10]= 0x03;
	Buffer[11]= 0x04;

	ret= CheckCertificate (0x1E, 0x00,
							  0x0C, Buffer,
							  0x04, Certificat, Status );
	if(!CheckFuncCTS("Check Certificate", ret, Status))	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

}


/******************************************************************/
void SAMmemoryTest(void)
/*****************************************************************
test of the CSC_WriteSAMNumber function

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	DWORD	ret;
	BYTE	status;
	BYTE	atr[50];
	DWORD	atrLn;

	//---- write the SAM nb in memory = SAM slot 2
	ret = CSC_WriteSAMNumber(2,&status);
	if( (ret != RCSC_Ok)||(status != 0x01) )
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	//---- close COM with the reader
	CSC_Close();

	//---- search the reader and reset it
	ret = CSC_SearchCSC();
	if(ret != RCSC_Ok)
	{
		CSC_AntennaOFF();
		SetErrorTo1();
		return;
	}

	//---- select the default SAM (should be 4) in ISO mode
/*	ret = CSC_SelectSAM(SAM_SLOT_0,1);
	if(ret != RCSC_Ok)
	{
		CSC_AntennaOFF();
		SetErrorTo1();
		return;
	}
*/
	//---- reset the SAM in the default slot (should be 2 !!)
	printf("\nplease insert a SAM in slot 2 and strike 'return'");
	fflush(stdin);
	getchar();

	ret = CSC_ResetSAM(atr, &atrLn);
	if( (ret != RCSC_Ok)||(atrLn < 5) )
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	//---- write back the SAM nb in memory = slot 1
	ret = CSC_WriteSAMNumber(1,&status);
	if( (ret != RCSC_Ok)||(status != 0x01) )
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	printf("\nplease insert a SAM in slot 1 and strike 'return'");
	fflush(stdin);
	getchar();

}

/******************************************************************/
void transparentCommandsTest(void)
/*****************************************************************
test of the CSC_TransparentCommandConfig and CSC_TransparentCommand
	functions

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	DWORD	ret;
	BYTE	rx[16];
	BYTE	tx[16];
	DWORD	lnIn;
	DWORD	lnOut;
	BOOL	exit = FALSE;
	DWORD	choice;
	BYTE	atr[32]; 
	DWORD	atrLn;
	BYTE	COM;
	sCARD_SearchExt search;
	DWORD	search_mask;
	BYTE	configIso;
	BYTE	configAddCRC;
	BYTE	configCheckCRC;
	BYTE	configField;
	BYTE	status;


	BYTE	mfUl16[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};

	while (exit == FALSE)
	{
		
		printf("\n-------------------------------------------------------\n");
		printf("\n              -> transparentCommands ------------------\n");
		printf("\nWhich Test ?"); 
		printf("\n 1: mode B (present a CTS256B before striking '1')");
		printf("\n 2: mode A (present a CTS512A before striking '2')");
		printf("\n x: exit\n");

		choice=_getch();
		
		switch(choice)
		{

		case '1':
			/*************************************************
				MODE B - NO CRC ADDED NOR CHECKED
			*************************************************/
			
			/*---- send the config command ----*/
			printf(".");
			ret = CSC_TransparentCommandConfig(0x01,0x00,0x00,0x00,&configIso,&configAddCRC,&configCheckCRC,&configField);
			if ((ret != RCSC_Ok)	|| (configIso != 0x01)
									|| (configAddCRC != 0x00)
									|| (configCheckCRC != 0x00)
									|| (configField != 0x00))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}


			/*---- send the REQT command ----*/
			printf(".");
			tx[0] = 0x10;	// CMD
			tx[1] = 0xF9;	// CRCB
			tx[2] = 0xE0;	// CRCB
			lnIn = 3;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 4) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x11;	// CMD : read address 1
			tx[1] = 0x70;	// CRCB
			tx[2] = 0xF1;	// CRCB
			lnIn = 3;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 4)|| (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
			/*---- send the erase command ----*/
			printf(".");
			tx[0] = 0x4A;	// CMD : erase address 10
			tx[1] = 0x26;	// CRCB
			tx[2] = 0x1D;	// CRCB
			lnIn = 3;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the write command ----*/
			printf(".");
			tx[0] = 0x2A;	// CMD : write address 10
			tx[1] = 0x11;	// data1
			tx[2] = 0x22;	// data2
			tx[3] = 0xD4;	// CRCB
			tx[4] = 0x38;	// CRCB
			lnIn = 5;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x1A;	// CMD : read address 10
			tx[1] = 0xA3;	// CRCB
			tx[2] = 0x4F;	// CRCB
			lnIn = 3;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ( (ret != RCSC_Ok) || (lnOut != 4) || (rx[0] != 0x11) || (rx[1] != 0x22) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*************************************************
				MODE B - CRC ADDED AND CHECKED
			*************************************************/

			/*---- send the config command ----*/
			printf(".");
			ret = CSC_TransparentCommandConfig(0x01,0x01,0x01,0x00,&configIso,&configAddCRC,&configCheckCRC,&configField);
			if ((ret != RCSC_Ok)	|| (configIso != 0x01)
									|| (configAddCRC != 0x01)
									|| (configCheckCRC != 0x01)
									|| (configField != 0x00))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}


			/*---- send the REQT command ----*/
			printf(".");
			tx[0] = 0x10;	// CMD
			lnIn = 1;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 4) || (status != 0x01))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x11;	// CMD : read address 1
			lnIn = 1;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 4)|| (status != 0x01))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
			/*---- send the erase command ----*/
			printf(".");
			tx[0] = 0x4A;	// CMD : erase address 10
			lnIn = 1;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0xFF))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the write command ----*/
			printf(".");
			tx[0] = 0x2A;	// CMD : write address 10
			tx[1] = 0x11;	// data1
			tx[2] = 0x22;	// data2
			lnIn = 3;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0xFF))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x1A;	// CMD : read address 10
			lnIn = 1;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ( (ret != RCSC_Ok) || (lnOut != 4) || (rx[0] != 0x11) || (rx[1] != 0x22) || (status != 0x01))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}


			break;
		
		
		case '2':

			/*************************************************
				MODE A - NO CRC ADDED NOR CHECKED
			*************************************************/

			/*---- search a CTS512A, in ISOA mode (succes) -----*/	
			printf(".");		
			search.ISOA = 1;
			search_mask = SEARCH_MASK_ISOA;
			ret = CSC_SearchCardExt(&search,search_mask,1,0x77,&COM,&atrLn,atr);
			if ((ret != RCSC_Ok) || (COM != 0x08))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the config command ----*/
			printf(".");
			ret = CSC_TransparentCommandConfig(0x02,0x00,0x00,0x00,&configIso,&configAddCRC,&configCheckCRC,&configField);
			if ((ret != RCSC_Ok)	|| (configIso != 0x02)
									|| (configAddCRC != 0x00)
									|| (configCheckCRC != 0x00)
									|| (configField != 0x00))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x30;	// CMD
			tx[1] = 0x04;	// ARG = address
			tx[2] = 0x26;	// CRCA
			tx[3] = 0xEE;	// CRCA
			lnIn = 4;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 18)|| (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			
			/*---- send the update command 1 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x04;	// address = page 4
			memcpy(&tx[2],&mfUl16[0],4);	// data to write
			tx[6] = 0x78;	// CRCA
			tx[7] = 0x57;	// CRCA
			ret = CSC_TransparentCommand(tx,8,&status,&lnOut,rx);
			if ((ret != RCSC_Ok)|| (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 2 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x05;	// address = 16
			memcpy(&tx[2],&mfUl16[4],4);	// data to write
			tx[6] = 0xBD;	// CRCA
			tx[7] = 0xE0;	// CRCA
			ret = CSC_TransparentCommand(tx,8,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 3 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x06;	// address = 16
			memcpy(&tx[2],&mfUl16[8],4);	// data to write
			tx[6] = 0x62;	// CRCA
			tx[7] = 0x20;	// CRCA
			ret = CSC_TransparentCommand(tx,8,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 4 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x07;	// address = 16
			memcpy(&tx[2],&mfUl16[12],4);	// data to write
			tx[6] = 0x26;	// CRCA
			tx[7] = 0x87;	// CRCA
			ret = CSC_TransparentCommand(tx,8,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x30;	// CMD
			tx[1] = 0x04;	// ARG = address
			tx[2] = 0x26;	// CRCA
			tx[3] = 0xEE;	// CRCA
			lnIn = 4;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 18)|| (status != 0))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			if ( memcmp(rx,mfUl16,16) != 0 )
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			

			/*************************************************
				MODE A - CRC ADDED AND CHECKED
			*************************************************/

			/*---- search a CTS512A, in ISOA mode (succes) -----*/
			printf(".");			
			search.ISOA = 1;
			search_mask = SEARCH_MASK_ISOA;
			ret = CSC_SearchCardExt(&search,search_mask,1,0x77,&COM,&atrLn,atr);
			if ((ret != RCSC_Ok) || (COM != 0x08))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the config command ----*/
			printf(".");
			ret = CSC_TransparentCommandConfig(0x02,0x01,0x01,0x00,&configIso,&configAddCRC,&configCheckCRC,&configField);
			if ((ret != RCSC_Ok)	|| (configIso != 0x02)
									|| (configAddCRC != 0x01)
									|| (configCheckCRC != 0x01)
									|| (configField != 0x00))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 1 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x04;	// address = page 4
			memcpy(&tx[2],&mfUl16[0],4);	// data to write
			ret = CSC_TransparentCommand(tx,6,&status,&lnOut,rx);
			if ((ret != RCSC_Ok)|| (status != 0xFF))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 2 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x05;	// address = 16
			memcpy(&tx[2],&mfUl16[4],4);	// data to write
			ret = CSC_TransparentCommand(tx,6,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0xFF))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 3 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x06;	// address = 16
			memcpy(&tx[2],&mfUl16[8],4);	// data to write
			ret = CSC_TransparentCommand(tx,6,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0xFF))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the update command 4 ----*/
			printf(".");
			tx[0] = 0xA2;	// update
			tx[1] = 0x07;	// address = 16
			memcpy(&tx[2],&mfUl16[12],4);	// data to write
			ret = CSC_TransparentCommand(tx,6,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (status != 0xFF))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}

			/*---- send the read command ----*/
			printf(".");
			tx[0] = 0x30;	// CMD
			tx[1] = 0x04;	// ARG = address
			lnIn = 2;
			ret = CSC_TransparentCommand(tx,lnIn,&status,&lnOut,rx);
			if ((ret != RCSC_Ok) || (lnOut != 18)|| (status != 0x01))
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}
			if ( memcmp(rx,mfUl16,16) != 0 )
			{
				CSC_AntennaOFF();
				CSC_Close();
				SetErrorTo1();
				return;
			}


			break;
		
		
		case 'x':
			exit = TRUE;
			break;

		default:
			break;
		}
	}
}


/******************************************************************/
void MifareSAMNXPClassTest(BYTE* tx)
/*****************************************************************
Test of Mifare - SAM NXP class with a Genxx + a Mifare Classic Card + SAM AV2-R NXP

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{

	DWORD ret			 = 0;
	BYTE StatusCard		 = 0;
	WORD StatusSam		 = 0;
	BYTE StatusWrite	 = 0;
	BYTE i				 = 0;
	BYTE DataRead[16]	 = {0};
	BYTE DataToWrite[16] = {0};
	BYTE InitDataToWrite[16] = {0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x01,0xFE,0x01,0xFE};
	BYTE Increment5[4] = {0x00,0x00,0x00,0x05};
	BYTE Decrement2[4] = {0x00,0x00,0x00,0x02};

	#define NUMKEY			0x06
	#define VERSIONKEY		0x03
	#define PICCKEY			0x0A
	#define NUMBLOCK1		0x01
	#define NUMBLOCK2		0x02
	#define LGDIVERSIFIANT	0x00
	#define DIVERSIFIANT	0x00

//---- Test the MIFARE - SAM NXP Authenticate in block 1 -----------	
	printf("\n-MIFARE - SAM NXP Authenticate in block 1-\n");	
	// function Authenticate
	ret=MIFARE_SAMNXP_Authenticate(NUMKEY, VERSIONKEY, PICCKEY, NUMBLOCK1, 
							LGDIVERSIFIANT, DIVERSIFIANT, &StatusCard, &StatusSam);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Authenticate in block 1",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");


//---- Test the MIFARE - SAM NXP Read block 1 -----------	
	printf("\n-MIFARE - SAM NXP Read block 1-\n");	

	// function Read Block
	ret=MIFARE_SAMNXP_ReadBlock(NUMBLOCK1, &StatusCard, &StatusSam, DataRead);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Read block 1",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

//---- Test the MIFARE - SAM NXP Write block 1 -----------	
	printf("\n-MIFARE - SAM NXP Write block 1-\n");	

	// init tab DataToWrite
	for (i=0; i<16; i++)
		DataToWrite[i] = ~DataRead[i];

	// function Write Block
	ret=MIFARE_SAMNXP_WriteBlock(NUMBLOCK1, DataToWrite, &StatusCard, &StatusSam, &StatusWrite);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Write block 1",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche le status write
		printf("\n StatusWrite = %02X\n", StatusWrite);
	}

//---- Test the MIFARE - SAM NXP Read block 1 -----------	
	printf("\n-MIFARE - SAM NXP Read block 1-\n");	

	// function Read Block
	ret=MIFARE_SAMNXP_ReadBlock(NUMBLOCK1, &StatusCard, &StatusSam, DataRead);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Read block 1",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

//---- Test the MIFARE - SAM NXP Init block 2 - for Increment/Decrement -----------	
	printf("\n-MIFARE - SAM NXP Init block 2-\n");	

	// function Write Block
	ret=MIFARE_SAMNXP_WriteBlock(NUMBLOCK2, InitDataToWrite, &StatusCard, &StatusSam, &StatusWrite);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Init block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche le status write
		printf("\n StatusWrite = %02X\n", StatusWrite);
	}

//---- Test the MIFARE - SAM NXP Read block 2 -----------	
	printf("\n-MIFARE - SAM NXP Read block 2-\n");	

	// function Read Block
	ret=MIFARE_SAMNXP_ReadBlock(NUMBLOCK2, &StatusCard, &StatusSam, DataRead);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Read block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

//---- Test the MIFARE - SAM NXP Increment block 2 -----------	
	printf("\n-MIFARE - SAM NXP Increment block 2-\n");	

	// function Increment Block
	ret=MIFARE_SAMNXP_Increment(NUMBLOCK2, Increment5, &StatusCard, &StatusSam, &StatusWrite);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Increment block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche le status write
		printf("\n StatusWrite = %02X\n", StatusWrite);
	}

//---- Test the MIFARE - SAM NXP Read block 2 -----------	
	printf("\n-MIFARE - SAM NXP Read block 2-\n");	

	// function Read Block
	ret=MIFARE_SAMNXP_ReadBlock(NUMBLOCK2, &StatusCard, &StatusSam, DataRead);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Read block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

	//---- Test the MIFARE - SAM NXP Decrement block 2 -----------	
	printf("\n-MIFARE - SAM NXP Decrement block 2-\n");	

	// function Decrement Block
	ret=MIFARE_SAMNXP_Decrement(NUMBLOCK2, Decrement2, &StatusCard, &StatusSam, &StatusWrite);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Decrement block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche le status write
		printf("\n StatusWrite = %02X\n", StatusWrite);
	}

//---- Test the MIFARE - SAM NXP Read block 2 -----------	
	printf("\n-MIFARE - SAM NXP Read block 2-\n");	

	// function Read Block
	ret=MIFARE_SAMNXP_ReadBlock(NUMBLOCK2, &StatusCard, &StatusSam, DataRead);

	if(!CheckFuncMIFARESAMNXP("Mifare - SAM NXP Read block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

}


/******************************************************************/
void MFPSL3ClassTest(BYTE* tx)
/*****************************************************************
Test of Mifare Plus SL3 class with a Genxx + a Mifare Plus Card + SAM AV2-R NXP

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{

	DWORD ret			 = 0;
	BYTE StatusCard		 = 0;
	WORD StatusSam		 = 0;
	BYTE StatusWrite	 = 0;
	BYTE i				 = 0;
	BYTE atr[50]		 = {0}; 
	DWORD lnAtr[1];
	DWORD ln			 = 0;
	BYTE COM			 = 0;
	sCARD_SearchExt search;
	DWORD search_mask;
	BYTE DataRead[240]	 = {0};
	BYTE DataToWrite[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15};
	BYTE InitDataToWrite[16] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	#define SAMKEYNUM		0x02
	#define SAMKEYVERSION	0x02
	#define KEYBLOCKNUM		0x4000
	#define LGDIVERSIFIANT	0x00
	#define DIVERSIFIANT	0x00
	#define MODEREAD		0x33
	#define BLOCKNUMREAD	0x0000
	#define NUMBLOCKREAD	0x04
	#define MODEWRITE		0xA3
	#define BLOCKNUMWRITE	0x0002
	#define NUMBLOCKWRITE	0x01
	#define MODERESET		0x03

//---- Select SAM ISO 7816 T=1 -----------	
	printf("\n-Select SAM ISO 7816 T=1-\n");	
	ret = CSC_SelectSAM(SAM_SLOT_1, 2);
	if (ret==RCSC_Ok)
		printf(" Ok\n");
	else
	{
		printf("\nError SAM 1 Select\n");
		SetErrorTo1();
	}

//---- Reset Sam ISO 7816 -----------	
	printf("\n-Reset Sam ISO 7816-\n");	
	ret = CSC_ResetSAM(atr, lnAtr);
	if (ret==RCSC_Ok)
		printf(" Ok\n");
	else
	{
		printf("\nError SAM 1 Reset\n");
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
	}

//---- EHP Param : No Select Application -----------	
	printf("\n-EHP Param : No Select Application-\n");	
	ret = CSC_EHP_PARAMS(1, 0, 0, 0, 0);	// 1 cards, Req, Slots, AFI, Div
	if (ret == RCSC_Ok)		
		printf(" OK\n");
	else 					
	{
		printf("\nError changing EHP param . code : %d",ret);
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
	}

//---- EHP : ISO A -----------	
	printf("\n-EHP : ISO A -\n"); 
	search.CONT=0;
	search.ISOB=0;
	search.ISOA=1;
	search.TICK=0;
	search.INNO=0;
	search.MV4k=0;
	search.MV5k=0;
	search.MIFARE=0;
	search_mask=SEARCH_MASK_ISOA;

	ret=CSC_SearchCardExt(&search,search_mask,0x01,100,&COM,&ln,tx);
	if (ret==RCSC_Ok)
		printf(" Ok\n");
	else
	{
		printf("\nError EHP . code %d",ret);
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
	}


//---- Test the MIFARE Plus SL3 Authenticate sans diversif Sector 0 -----------	
	printf("\n-MIFARE Plus SL3 Authenticate sans diversif Sector 0-\n");	
	// function Authenticate
	ret=MFP_SL3_Authentication(SAMKEYNUM, SAMKEYVERSION, KEYBLOCKNUM, LGDIVERSIFIANT, DIVERSIFIANT, 
							   &StatusCard, &StatusSam);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Authenticate Sector 0",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test the MIFARE Plus SL3 Read Block 0 1 2 3 -----------	
	printf("\n-MIFARE Plus SL3 Read Block 0 1 2 3-\n");	
	// function Read
	ret=MFP_SL3_ReadBlock(MODEREAD, BLOCKNUMREAD, NUMBLOCKREAD, 
						  &StatusCard, &StatusSam, DataRead);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Read Block 0 1 2 3",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(NUMBLOCKREAD*16); i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

//---- Test the MIFARE Plus SL3 Write Block 2 -----------	
	printf("\n-MIFARE Plus SL3 Write Block 2-\n");	
	// function Write
	ret=MFP_SL3_WriteBlock(MODEWRITE, BLOCKNUMWRITE, NUMBLOCKWRITE, DataToWrite,
						  &StatusCard, &StatusSam);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Write Block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");


//---- Test the MIFARE Plus SL3 Read Block 0 1 2 3 -----------	
	printf("\n-MIFARE Plus SL3 Read Block 0 1 2 3-\n");	
	// function Read
	ret=MFP_SL3_ReadBlock(MODEREAD, BLOCKNUMREAD, NUMBLOCKREAD, 
						  &StatusCard, &StatusSam, DataRead);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Read Block 0 1 2 3",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(NUMBLOCKREAD*16); i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

//---- Test the MIFARE Plus SL3 Reset Block 2 -----------	
	printf("\n-MIFARE Plus SL3 Reset Block 2-\n");	
	// function Write
	ret=MFP_SL3_WriteBlock(MODEWRITE, BLOCKNUMWRITE, NUMBLOCKWRITE, InitDataToWrite,
						  &StatusCard, &StatusSam);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Reset Block 2",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");


//---- Test the MIFARE Plus SL3 Read Block 0 1 2 3 -----------	
	printf("\n-MIFARE Plus SL3 Read Block 0 1 2 3-\n");	
	// function Read
	ret=MFP_SL3_ReadBlock(MODEREAD, BLOCKNUMREAD, NUMBLOCKREAD, 
						  &StatusCard, &StatusSam, DataRead);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Read Block 0 1 2 3",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(NUMBLOCKREAD*16); i++)
		{
			printf("%02X ",DataRead[i]);
		}
		printf("\n");
	}

//---- Test the MIFARE Plus SL3 Change Key sans diversif -----------	
	printf("\n-MIFARE Plus SL3 Change Key sans diversif-\n");	
	// function Change Key
	ret=MFP_SL3_ChangeKey(SAMKEYNUM, SAMKEYVERSION, KEYBLOCKNUM, LGDIVERSIFIANT, DIVERSIFIANT,
						  &StatusCard, &StatusSam);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Change Key sans diversif",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
		
	}
	printf("\n");

//---- Test the MIFARE Plus SL3 Reset Authentication -----------	
	printf("\n-MIFARE Plus SL3 Reset Authentication-\n");	
	// function Reset Authentication
	ret=MFP_SL3_ResetAuthentication(MODERESET, &StatusCard, &StatusSam);
															
	if(!CheckFuncMFPSL3("MIFARE Plus SL3 Reset Authentication",ret,StatusCard,StatusSam))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
		
	}
	printf("\n");

}


/******************************************************************/
void MifareClassTest(BYTE* tx)
/*****************************************************************
Test of Mifare class with a Gen3x5 + a Mifare Classic Card

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{

	unsigned char Buffer[256];
	DWORD BufferLn=0;
	DWORD ret;
	BYTE Status, Verif[4], i;
	BYTE MifareType[1];
	BYTE SerialNumber[6];
	BYTE DataRead[16], DataToWrite[16], DataVerif[16]; 
	BYTE DataReadMulti[64] 	= {0};

	BYTE DEFAULTKEY0[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	BYTE DEFAULTKEY1[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
	BYTE INVERSEKEY1[6] = {0x66,0x55,0x44,0x33,0x22,0x11};
	BYTE TRANSPORTACCESS[4] = {0xFF ,0x07, 0x80, 0x00};
	BYTE VALUEACCESS[4]		= {0x08 ,0x77, 0x8F, 0x00};
	BYTE VALUEDATA6[16] = {0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x06,0xF9,0x06,0xF9};
	BYTE DATATOWRITE[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	BYTE DATATOWRITESECTOR[48] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F};
	BYTE VALUEDATASECTOR[48] = {0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x06,0xF9,0x06,0xF9,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x06,0xF9,0x06,0xF9,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x06,0xF9,0x06,0xF9};
	BYTE INCREMENT5[4] = {0x00,0x00,0x00,0x05};
	BYTE DECREMENT2[4] = {0x00,0x00,0x00,0x02};
	

#define KEYINDEX0		0	// pour clé A
#define KEYINDEX1		1	// pour clé B
#define SECTOR0			0
#define SECTOR1			1
#define SECTOR2			2
#define INITIAL_IS_A	0x0A
#define INITIAL_IS_B	0x0B
#define FINAL_IS_A		0x0A
#define FINAL_IS_B		0x0B
#define BLOCK_NUM0		0
#define BLOCK_NUM1		1
#define BLOCK_NUM4		4
#define BLOCK_NUM5		5
#define BLOCK_NUM6		6

#define NUM_BLOCK2		2
#define NUM_BLOCK3		3

/*---- Test the MIFARE Load Reader Key Index in the first of the 32 locations in EEPROM -----------*/	
		
	// function Load Reader Key
	ret=MIFARE_LoadReaderKeyIndex(KEYINDEX0, DEFAULTKEY0, &Status);
	if(!CheckFuncMIFARE("Mifare Load Default Key in index 0",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	ret=MIFARE_LoadReaderKeyIndex(KEYINDEX1, INVERSEKEY1, &Status);
	if(!CheckFuncMIFARE("Mifare Load Default Key in index 0",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}


/*---- Test the MIFARE Select -----------*/	
		
	// function MIFARE_Select
	ret=MIFARE_Select(tx+2,4, &Status, tx+2);

	if(!CheckFuncMIFARE("Mifare Select",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	
	
/*---- Test the MIFARE Authenticate in sector 0 -----------*/	
		
	// function Authenticate
	ret=MIFARE_Authenticate(SECTOR0, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 0",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}



/*---- Test the MIFARE detect -----------*/	
	// function Init
	//CSC_SendReceive(Timeout,BYTE* BufIN, LnIN, BufOUT,LPDWORD LnOUT);
/*	Buffer[0]=0x80;	// EXEC Command
	Buffer[1]=0x04;			// Length
	Buffer[2]=0x10;			// Mifare class
	Buffer[3]=0x01;			// Command 
	Buffer[4]=0x01;			// Lenght of subcommand
	Buffer[5]=0x00;			// Subcommand Init
	Buffer[6]=0x00;			// End of Command
	Buffer[7]=0xE6;			// CRC1
	Buffer[8]=0xE8;			// CRC2
	BufferLn=9;
	ret=CSC_SendReceive(2000, Buffer, BufferLn, Buffer, &BufferLn);
*/

/*---- Test the MIFARE Read Block 4 in sector 1 -----------*/	
		
	// function Authenticate
	ret=MIFARE_Authenticate(SECTOR1, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Read Block
	ret=MIFARE_ReadBlock(BLOCK_NUM4, DataRead, &Status);

	if(!CheckFuncMIFARE("MIFARE ReadBlock 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

/*---- Test the MIFARE Read sector 1 -----------*/	
		
	// function ReadSector
	ret=MIFARE_ReadSector(SECTOR1, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, Buffer, &Status);

	if(!CheckFuncMIFARE("Mifare ReadSector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	for (i=0; i<16; i++)
	{
		if (Buffer[i] != DataRead[i])
		{
			SetErrorTo1();
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}
	}

/*---- Test the MIFARE Write Block 1 in sector 0 -----------*/	
		
	// function Authenticate
	ret=MIFARE_Authenticate(SECTOR1, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Read Block
	ret=MIFARE_ReadBlock(BLOCK_NUM4, DataRead, &Status);

	if(!CheckFuncMIFARE("MIFARE ReadBlock 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	for (i=0; i<16; i++)
		DataToWrite[i] = ~DataRead[i];

	// function Write Block
	ret=MIFARE_WriteBlock(BLOCK_NUM4, DataToWrite, DataVerif, &Status);

	if(!CheckFuncMIFARE("MIFARE WriteBlock 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	for (i=0; i<16; i++)
	{
		if (DataToWrite[i] != DataVerif[i])
		{
			SetErrorTo1();
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}
	}

	// function Read Block
	ret=MIFARE_ReadBlock(BLOCK_NUM4, DataRead, &Status);

	if(!CheckFuncMIFARE("MIFARE ReadBlock 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// reverify 
	for (i=0; i<16; i++)
	{
		if (DataToWrite[i] != DataVerif[i])
		{
			SetErrorTo1();
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}
	}

	//Get back to original data
	for (i=0; i<16; i++)
		DataToWrite[i] = ~DataRead[i];

	// function Write Block
	ret=MIFARE_WriteBlock(BLOCK_NUM4, DataToWrite, DataVerif, &Status);

	if(!CheckFuncMIFARE("MIFARE WriteBlock 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

/*---- Test the MIFARE Increment/Decrement Block value in sector 1 -----------*/	
		
	// function Authenticate
	ret=MIFARE_Authenticate(SECTOR1, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Write Block block 5 as Backup
	ret=MIFARE_WriteBlock(BLOCK_NUM5, VALUEDATA6, DataVerif, &Status);

	if(!CheckFuncMIFARE("MIFARE WriteBlock 5",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	// function Write Block block 6 as Value Block
	ret=MIFARE_WriteBlock(BLOCK_NUM6, VALUEDATA6, DataVerif, &Status);

	if(!CheckFuncMIFARE("MIFARE WriteBlock 6",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

/*---- Test the MIFARE Read sector 1 -----------*/	
		
	// function ReadSector
	ret=MIFARE_ReadSector(SECTOR1, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, Buffer, &Status);

	if(!CheckFuncMIFARE("Mifare ReadSector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function ChangeKey to convert block 5 and block 6 as Value Blocks
	ret=MIFARE_ChangeKey(INITIAL_IS_A, SECTOR1, KEYINDEX0, FINAL_IS_B, 
					DEFAULTKEY0, VALUEACCESS, DEFAULTKEY1, MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Change Key value in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

/*---- Test the MIFARE Read sector 1 -----------*/	
		
	// function ReadSector
	ret=MIFARE_ReadSector(SECTOR1, INITIAL_IS_B, KEYINDEX1, 
							MifareType, SerialNumber, Buffer, &Status);

	if(!CheckFuncMIFARE("Mifare ReadSector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}


	// function Authenticate
	ret=MIFARE_Authenticate(SECTOR1, INITIAL_IS_B, KEYINDEX1, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Increment
	ret=MIFARE_IncrementValue(BLOCK_NUM6, INCREMENT5, Verif, &Status);
	if(!CheckFuncMIFARE("Mifare Increment of 2 in block value 6",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Decrement
	ret=MIFARE_DecrementValue(BLOCK_NUM6, DECREMENT2, Verif, &Status);

	if(!CheckFuncMIFARE("Mifare Decrement of 1 in block value 6",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	if (Verif[0] !=3)
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}


/*---- Test the MIFARE BackUp/Restore  Block value in sector 1 -----------*/	
		
	// function Authenticate
	ret=MIFARE_Authenticate(SECTOR1, INITIAL_IS_B, KEYINDEX1, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function BackUp/Restore block value 6
	ret=MIFARE_BackUpRestoreValue(BLOCK_NUM5, BLOCK_NUM6, &Status);

	if(!CheckFuncMIFARE("MIFARE ReadBlock 6",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}


	// function Read Block block value 6
	ret=MIFARE_ReadBlock(BLOCK_NUM6, DataRead, &Status);

	if(!CheckFuncMIFARE("MIFARE ReadBlock 6",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	if (DataRead[3] != 0)
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

/*---- Restore the MIFARE access key to origine value in sector 1 -----------*/	
		
	// function Change Key
	ret=MIFARE_ChangeKey(INITIAL_IS_B, SECTOR1, KEYINDEX1, FINAL_IS_A, DEFAULTKEY0, TRANSPORTACCESS, DEFAULTKEY0, MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Change Key in sector 0",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

/*---- Test the MIFARE Halt       -----------*/	
		
	// function Halt
	ret=MIFARE_Halt();
	Status=0x00; //no status return
	if(!CheckFuncMIFARE("Mifare Halt",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}


/*---- Test the MIFARE Read Multiple Block -----------*/	
	// function Detect
	printf("\n-Mifare Detect-\n");	
	ret=MIFARE_Detect(&Status, MifareType, SerialNumber);

	if(!CheckFuncMIFARE("Mifare Detect",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n UID = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", SerialNumber[i]);
		}
		printf("\n");
	}

	// function Authenticate Secteur 1
	printf("\n-Mifare Authenticate Secteur 1-\n");	
	ret=MIFARE_Authenticate(SECTOR1, INITIAL_IS_A, KEYINDEX0, 
							MifareType, SerialNumber, &Status);

	if(!CheckFuncMIFARE("Mifare Authenticate in sector 1",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n UID = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", SerialNumber[i]);
		}
		printf("\n");
	}

	// function Read Multiple Block 4 et 5
	printf("\n-Mifare Read Multiple Block 4 et 5-\n");	
	ret=MIFARE_ReadMultipleBlock(BLOCK_NUM4, NUM_BLOCK2, &Status, DataReadMulti);

	if(!CheckFuncMIFARE("MIFARE Read Multiple Block 4 et 5",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataReadMulti = ");
		for(i=0; i<(NUM_BLOCK2*16); i++)
		{
			printf("%02X ", DataReadMulti[i]);
		}
		printf("\n");
	}

		// function Read Multiple Block 5, 6 et 7
	printf("\n-Mifare Read Multiple Block 5, 6 et 7-\n");	
	ret=MIFARE_ReadMultipleBlock(BLOCK_NUM5, NUM_BLOCK3, &Status, DataReadMulti);

	if(!CheckFuncMIFARE("MIFARE Read Multiple Block 5, 6 et 7",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataReadMulti = ");
		for(i=0; i<(NUM_BLOCK3*16); i++)
		{
			printf("%02X ", DataReadMulti[i]);
		}
		printf("\n");
	}

/*---- Test the MIFARE Simple Write Block -----------*/	
	// function Simple Write Block 4
	printf("\n-Mifare Simple Write Block 4-\n");	
	ret=MIFARE_SimpleWriteBlock(BLOCK_NUM4, DATATOWRITE, &Status);

	if(!CheckFuncMIFARE("MIFARE Simple Write Block",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Read Block 4
	printf("\n-Mifare Read Block 4-\n");	
	ret=MIFARE_ReadBlock(BLOCK_NUM4, DataRead, &Status);

	if(!CheckFuncMIFARE("MIFARE Read Block 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}

	// function Clear Block 4
	printf("\n-Mifare Clear Block 4-\n");	
	ret=MIFARE_SimpleWriteBlock(BLOCK_NUM4, VALUEDATA6, &Status);

	if(!CheckFuncMIFARE("MIFARE Simple Write Block",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Read Block 4
	printf("\n-Mifare Read Block 4-\n");	
	ret=MIFARE_ReadBlock(BLOCK_NUM4, DataRead, &Status);

	if(!CheckFuncMIFARE("MIFARE Read Block 4",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<16; i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");

/*---- Test the MIFARE Read/Write Sector Data -----------*/	
	// function Read Sector Data 2
	printf("\n-Mifare Read Sector Data 2-\n");	
	ret=MIFARE_ReadSectorData(INITIAL_IS_A, SECTOR2, KEYINDEX0, &Status, MifareType, SerialNumber, DataReadMulti);

	if(!CheckFuncMIFARE("MIFARE Read Sector Data 2",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n UID = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", SerialNumber[i]);
		}
		printf("\n");
		printf("\n DataRead = ");
		if(*MifareType == 0x08)				// Mifare 1K
			for(i=0; i<48; i++) printf("%02X ", DataReadMulti[i]);
		else								// Mifare 4K
			for(i=0; i<240; i++) printf("%02X ", DataReadMulti[i]);

		printf("\n");
	}

	// function Write Sector Data 2
	printf("\n-Mifare Write Sector Data 2-\n");	
	ret=MIFARE_WriteSectorData(INITIAL_IS_A, SECTOR2, KEYINDEX0, DATATOWRITESECTOR, *MifareType, &Status);

	if(!CheckFuncMIFARE("MIFARE Write Sector Data 2",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Read Sector Data 2
	printf("\n-Mifare Read Sector Data 2-\n");	
	ret=MIFARE_ReadSectorData(INITIAL_IS_A, SECTOR2, KEYINDEX0, &Status, MifareType, SerialNumber, DataReadMulti);

	if(!CheckFuncMIFARE("MIFARE Read Sector Data 2",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n UID = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", SerialNumber[i]);
		}
		printf("\n");
		printf("\n DataRead = ");
		if(*MifareType == 0x08)				// Mifare 1K
			for(i=0; i<48; i++) printf("%02X ", DataReadMulti[i]);
		else								// Mifare 4K
			for(i=0; i<240; i++) printf("%02X ", DataReadMulti[i]);

		printf("\n");
	}
	// function Clear Sector Data 2
	printf("\n-Mifare Clear Sector Data 2-\n");	
	ret=MIFARE_WriteSectorData(INITIAL_IS_A, SECTOR2, KEYINDEX0, VALUEDATASECTOR, *MifareType, &Status);

	if(!CheckFuncMIFARE("MIFARE Clear Sector Data 2",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// function Read Sector Data 2
	printf("\n-Mifare Read Sector Data 2-\n");	
	ret=MIFARE_ReadSectorData(INITIAL_IS_A, SECTOR2, KEYINDEX0, &Status, MifareType, SerialNumber, DataReadMulti);

	if(!CheckFuncMIFARE("MIFARE Read Sector Data 2",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n UID = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", SerialNumber[i]);
		}
		printf("\n");
		printf("\n DataRead = ");
		if(*MifareType == 0x08)				// Mifare 1K
			for(i=0; i<48; i++) printf("%02X ", DataReadMulti[i]);
		else								// Mifare 4K
			for(i=0; i<240; i++) printf("%02X ", DataReadMulti[i]);

		printf("\n");
	}
}


/******************************************************************/
void DesfireSamClassTest(BYTE* tx)
/*****************************************************************
Test of Desfire Sam class with a Genxx

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{

	DWORD ret			= 0;
	WORD Status			= 0;
	BYTE KEYNUM00		= 0;
	BYTE INITVECTOR[8]	= {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};
	BYTE DIRFILEAID[3]	= {0x00,0x00,0x00};
	BYTE Lg				= 0;
	BYTE i				= 0;
	BYTE NumKey			= 0;
	BYTE DataRead[240] 	= {0};


//---- Test SAM Get Version -----------	
	printf("\n-SAM Get Version-\n");	
	ret=DESFIRE_SamGetVersion(&Lg, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("SAM Get Version",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n VersionSAM = ");
		for(i=0; i<(Lg-2); i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test SAM Select Application -----------	
	printf("\n-SAM Select Application-\n");	
	ret=DESFIRE_SamSelectApplication(DIRFILEAID, &Status);
															
	if(!CheckFuncDESFIRE("SAM Select Application",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test SAM Load Init Vector -----------	
	printf("\n-SAM Load Init Vector-\n");	
	ret=DESFIRE_SamLoadInitVector(INITVECTOR, &Status);
															
	if(!CheckFuncDESFIRE("SAM Load Init Vector",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test SAM Get Key Entry -----------	
	printf("\n-SAM Get Key Entry-\n");	
	ret=DESFIRE_SamGetKeyEntry(KEYNUM00, &Lg, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("SAM Get Key Entry",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Key Entry = ");
		for(i=0; i<(Lg-2); i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

}

/******************************************************************/
void DesfireClassTest(BYTE* tx)
/*****************************************************************
Test of Desfire class with a Genxx

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{

	DWORD ret			= 0;
	BYTE SAMKEYNO		= 1;  
	BYTE SAMKEYV		= 0x01;
	BYTE KEYNUM00		= 0;
	BYTE KEYNUM01		= 1;
	BYTE NUMID			= 3;
	BYTE OPT			= 0x0F;
	BYTE FILEID01		= 0x01;
	BYTE FILEID02		= 0x02;
	BYTE FILEID03		= 0x03;
	BYTE FILEID04		= 0x04;
	BYTE FILEID05		= 0x05;
	BYTE COMMMODE		= 0x00;
	WORD ACCESSRIGHT	= 0x0000;
	BYTE MAXFILEID		= 7;
	WORD OFFSET			= 1;
	WORD NUMBYTE		= 20;
	WORD NUMRECORD		= 1;
	WORD RECORDNUM		= 1;
	WORD SIZERECORD		= 0x0018;
	BYTE APPID00[3]		= {0x00,0x00,0x00};
	BYTE APPID01[3]		= {0x30,0x05,0xF2};
	BYTE INITVECTOR[8]	= {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};
	BYTE DIRFILEAID[3]	= {0x00,0x00,0x00};
	BYTE RECORDSIZE[3]	= {0x00,0x00,0x18};
	BYTE MAXNUMRECORD[3]= {0x00,0x00,0x08};
	BYTE FILESIZE[3]	= {0x00,0x00,0x20};
	BYTE LOWER[4]		= {0x00,0x00,0x00,0x00};
	BYTE UPPER[4]		= {0x00,0x00,0xFF,0xFF};
	BYTE INITIAL[4]		= {0x00,0x00,0x00,0x08};
	BYTE CREDITMAX[4]	= {0x00,0x00,0x00,0xFF};
	BYTE CREDIT6[4]		= {0x00,0x00,0x00,0x06};
	BYTE CREDIT300[4]	= {0x00,0x00,0x01,0x2C};
	BYTE DEBIT2[4]		= {0x00,0x00,0x00,0x02};
	BYTE DEBIT260[4]	= {0x00,0x00,0x01,0x04};
	BYTE DATATOWRITE[20]= {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
	BYTE DATATOWRITEINIT[20]= {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	WORD Status			= 0;
	BYTE Lg				= 0;
	BYTE i				= 0;
	BYTE KeyInfo		= 0;
	BYTE NumKey			= 0;
	BYTE Cw				= 0;
	BYTE Year			= 0;
	BYTE NbIDFound		= 0;
	BYTE FileType		= 0;
	BYTE CommMode		= 0;
	WORD AccessRight	= 0;
	WORD NumByte		= 0;
	WORD NumRecord		= 0;
	BYTE KeyEntry[12]	= {0};
	BYTE HardInfo[7]	= {0};
	BYTE SoftInfo[7]	= {0};
	BYTE UID[7]			= {0};
	BYTE Batch[5]		= {0};
	BYTE DataRead[240] 	= {0};

//---- Test Get Version Card -----------	
	printf("\n-Get Version Card-\n");	
	ret=DESFIRE_GetVersion(&Status, HardInfo, SoftInfo, UID, Batch, &Cw, &Year);
															
	if(!CheckFuncDESFIRE("Get Version Card",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n HardInfo = ");
		for(i=0; i<7; i++)
			printf("%02X ", HardInfo[i]);
		printf("\n SoftInfo = ");
		for(i=0; i<7; i++)
			printf("%02X ", SoftInfo[i]);
		printf("\n UID = ");
		for(i=0; i<7; i++)
			printf("%02X ", UID[i]);
		printf("\n Batch = ");
		for(i=0; i<5; i++)
			printf("%02X ", Batch[i]);
		printf("\n Cw = %02X", Cw);
		printf("\n Year = %02X", Year);
	}
	printf("\n");

//---- Test Select Application -----------	
	printf("\n-Select Application 000000-\n");	
	ret=DESFIRE_SelectApplication(APPID00, &Status);
															
	if(!CheckFuncDESFIRE("Select Application",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Prepare Authentication -----------	
	printf("\n-Prepare Authentication-\n");	
	ret=DESFIRE_PrepareAuthentication(0,SAMKEYNO,SAMKEYV, &Status);
															
	if(!CheckFuncDESFIRE("Authentication",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Format PICC -----------	




//---- Test Authentication -----------	
	printf("\n-Authentication-\n");	
	ret=DESFIRE_Authenticate(KEYNUM00, &Status);
															
	if(!CheckFuncDESFIRE("Authentication",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Format PICC -----------	
	printf("\n-Format PICC-\n");	
	ret=DESFIRE_FormatPICC(&Status);
															
	if(!CheckFuncDESFIRE("Format PICC",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get Key Setting -----------	
	printf("\n-Get Key Setting-\n");	
	ret=DESFIRE_GetKeySetting(&Status, &KeyInfo, &NumKey);
															
	if(!CheckFuncDESFIRE("Get Key Setting",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n KeySetting = %02X", KeyInfo);
		printf("\n NumKey = %02X", NumKey);
	}
	printf("\n");

//---- Test Get Key Version -----------	
	printf("\n-Get Key Master Version-\n");	
	ret=DESFIRE_GetKeyVersion(KEYNUM00, &Status, &KeyInfo);
															
	if(!CheckFuncDESFIRE("Get Key Version",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Key Version = %02X ", KeyInfo);
	}
	printf("\n");

//---- Test Create Application -----------	
	printf("\n-Create Application 3005F2 Opt 0F Key 01-\n");	
	ret=DESFIRE_CreateApplication(APPID01, OPT, KEYNUM01, &Status);
															
	if(!CheckFuncDESFIRE("Create Application",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get Application IDs -----------	
	printf("\n-Get Application IDs-\n");	
	ret=DESFIRE_GetApplicationIDs(NUMID, &Lg, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("Get Application IDs",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n IDs = ");
		for(i=0; i<(Lg-2); i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Select Application -----------	
	printf("\n-Select Application 3005F2-\n");	
	ret=DESFIRE_SelectApplication(APPID01, &Status);
															
	if(!CheckFuncDESFIRE("Select Application",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Authentication -----------	
	printf("\n-Authentication-\n");	
	ret=DESFIRE_Authenticate(KEYNUM00, &Status);
															
	if(!CheckFuncDESFIRE("Authentication",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Create Linear Record File -----------	
	printf("\n-Create Linear Record File 01-\n");	
	ret=DESFIRE_CreateLinearRecordFile(FILEID01, COMMMODE, ACCESSRIGHT, RECORDSIZE, MAXNUMRECORD, &Status);
															
	if(!CheckFuncDESFIRE("Create Linear Record File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File Setting -----------	
	printf("\n-Get File Setting 01-\n");	
	ret=DESFIRE_GetFileSetting(FILEID01, &Status, &FileType, &CommMode, &AccessRight);
															
	if(!CheckFuncDESFIRE("Get File Setting",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n FileType = %02X", FileType);
		printf("\n CommMode = %02X", CommMode);
		printf("\n AccessRight = %02X", AccessRight);
	}
	printf("\n");

//---- Test Write Record File -----------	
	printf("\n-Write Record File 01-\n");	
	ret=DESFIRE_WriteRecord(FILEID01, COMMMODE, RECORDNUM, NUMRECORD, DATATOWRITE, &Status);
															
	if(!CheckFuncDESFIRE("Write Record File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");
/*
//---- Test Read Record File -----------	
	printf("\n-Read Record File 01-\n");	
	ret=DESFIRE_ReadRecord(FILEID01, COMMMODE, RECORDNUM, NUMRECORD, SIZERECORD, &Status, &NumRecord, DataRead);
															
	if(!CheckFuncDESFIRE("Read Record File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n NumRecord = %02X", NumRecord);
		printf("\n DataRead = ");
		for(i=0; i<(int)NumByte; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");
*/
//---- Test Clear Linear Record File -----------	
	printf("\n-Clear Record File 01-\n");	
	ret=DESFIRE_ClearRecordFile(FILEID01, &Status);
															
	if(!CheckFuncDESFIRE("Clear Record File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Create Cyclic Record File -----------	
	printf("\n-Create Cyclic Record File 02-\n");	
	ret=DESFIRE_CreateCyclicRecordFile(FILEID02, COMMMODE, ACCESSRIGHT, RECORDSIZE, MAXNUMRECORD, &Status);
															
	if(!CheckFuncDESFIRE("Create Cyclic Record File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File Setting -----------	
	printf("\n-Get File Setting 02-\n");	
	ret=DESFIRE_GetFileSetting(FILEID02, &Status, &FileType, &CommMode, &AccessRight);
															
	if(!CheckFuncDESFIRE("Get File Setting",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n FileType = %02X", FileType);
		printf("\n CommMode = %02X", CommMode);
		printf("\n AccessRight = %02X", AccessRight);
	}
	printf("\n");

//---- Test Create Standard Data File -----------	
	printf("\n-Create Standard Data File 03-\n");	
	ret=DESFIRE_CreateStandardDataFile(FILEID03, COMMMODE, ACCESSRIGHT, FILESIZE, &Status);
															
	if(!CheckFuncDESFIRE("Create Standard Data File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File Setting -----------	
	printf("\n-Get File Setting 03-\n");	
	ret=DESFIRE_GetFileSetting(FILEID03, &Status, &FileType, &CommMode, &AccessRight);
															
	if(!CheckFuncDESFIRE("Get File Setting",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n FileType = %02X", FileType);
		printf("\n CommMode = %02X", CommMode);
		printf("\n AccessRight = %02X", AccessRight);
	}
	printf("\n");

//---- Test Read Data -----------	
	printf("\n-Read Data Std File 03-\n");	
	ret=DESFIRE_ReadData(FILEID03, COMMMODE, OFFSET, NUMBYTE, &Status, &NumByte, DataRead);
															
	if(!CheckFuncDESFIRE("Read Data Std File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n NumByte = %02X", NumByte);
		printf("\n DataRead = ");
		for(i=0; i<(int)NumByte; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Write Data -----------	
	printf("\n-Write Data Std File 03-\n");	
	ret=DESFIRE_WriteData(FILEID03, COMMMODE, OFFSET, NUMBYTE, DATATOWRITE, &Status);
															
	if(!CheckFuncDESFIRE("Write Data Std File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Read Data -----------	
	printf("\n-Read Data Std File 03-\n");	
	ret=DESFIRE_ReadData(FILEID03, COMMMODE, OFFSET, NUMBYTE, &Status, &NumByte, DataRead);
															
	if(!CheckFuncDESFIRE("Read Data Std File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n NumByte = %02X", NumByte);
		printf("\n DataRead = ");
		for(i=0; i<(int)NumByte; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Clear Data -----------	
	printf("\n-Clear Data Std File 03-\n");	
	ret=DESFIRE_WriteData(FILEID03, COMMMODE, OFFSET, NUMBYTE, DATATOWRITEINIT, &Status);
															
	if(!CheckFuncDESFIRE("Clear Data Std File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Read Data -----------	
	printf("\n-Read Data Std File 03-\n");	
	ret=DESFIRE_ReadData(FILEID03, COMMMODE, OFFSET, NUMBYTE, &Status, &NumByte, DataRead);
															
	if(!CheckFuncDESFIRE("Read Data Std File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n NumByte = %02X", NumByte);
		printf("\n DataRead = ");
		for(i=0; i<(int)NumByte; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Delete Std File -----------	
	printf("\n-Delete Std File 03-\n");	
	ret=DESFIRE_DeleteFile(FILEID03, &Status);
															
	if(!CheckFuncDESFIRE("Delete Std File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File ID -----------	
	printf("\n-Get File ID-\n");	
	ret=DESFIRE_GetFileID(MAXFILEID, &Status, &NbIDFound, DataRead);
															
	if(!CheckFuncDESFIRE("Get File ID",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Nb ID = %02X", NbIDFound);
		printf("\n File IDs = ");
		for(i=0; i<NbIDFound; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Create BackUp Data File -----------	
	printf("\n-Create BackUp Data File 04-\n");	
	ret=DESFIRE_CreateBackUpDataFile(FILEID04, COMMMODE, ACCESSRIGHT, FILESIZE, &Status);
															
	if(!CheckFuncDESFIRE("Create BackUp Data File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File Setting -----------	
	printf("\n-Get File Setting 04-\n");	
	ret=DESFIRE_GetFileSetting(FILEID04, &Status, &FileType, &CommMode, &AccessRight);
															
	if(!CheckFuncDESFIRE("Get File Setting",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n FileType = %02X", FileType);
		printf("\n CommMode = %02X", CommMode);
		printf("\n AccessRight = %02X", AccessRight);
	}
	printf("\n");

//---- Test Create Value File -----------	
	printf("\n-Create Value File 05-\n");	
	ret=DESFIRE_CreateValueFile(FILEID05, COMMMODE, ACCESSRIGHT, LOWER, UPPER, INITIAL, 0, &Status);
															
	if(!CheckFuncDESFIRE("Create Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File Setting -----------	
	printf("\n-Get File Setting 05-\n");	
	ret=DESFIRE_GetFileSetting(FILEID05, &Status, &FileType, &CommMode, &AccessRight);
															
	if(!CheckFuncDESFIRE("Get File Setting",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n FileType = %02X", FileType);
		printf("\n CommMode = %02X", CommMode);
		printf("\n AccessRight = %02X", AccessRight);
	}
	printf("\n");

//---- Test Get File ID -----------	
	printf("\n-Get File ID-\n");	
	ret=DESFIRE_GetFileID(MAXFILEID, &Status, &NbIDFound, DataRead);
															
	if(!CheckFuncDESFIRE("Get File ID",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Nb ID = %02X", NbIDFound);
		printf("\n File IDs = ");
		for(i=0; i<NbIDFound; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");
/*
//---- Test Limited Credit -----------	
	printf("\n-Limited Credit-\n");	
	ret=DESFIRE_LimitedCredit(FILEID05, COMMMODE, CREDITMAX, &Status);
															
	if(!CheckFuncDESFIRE("Limited Credit",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");
*/
//---- Test Get Value File -----------	
	printf("\n-Get Value File 05-\n");	
	ret=DESFIRE_GetValue(FILEID05, COMMMODE, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("Get Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Value = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Credit Value File -----------	
	printf("\n-Credit+6 Value File 05-\n");	
	ret=DESFIRE_Credit(FILEID05, COMMMODE, CREDIT6, &Status);
															
	if(!CheckFuncDESFIRE("Credit Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

	printf("\n-Commit Transaction-\n");	
	ret=DESFIRE_CommitTransaction(&Status);
															
	if(!CheckFuncDESFIRE("Commit Transaction",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get Value File -----------	
	printf("\n-Get Value File 05-\n");	
	ret=DESFIRE_GetValue(FILEID05, COMMMODE, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("Get Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Value = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Debit Value File -----------	
	printf("\n-Debit-2 Value File 05-\n");	
	ret=DESFIRE_Debit(FILEID05, COMMMODE, DEBIT2, &Status);
															
	if(!CheckFuncDESFIRE("Debit Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

	printf("\n-Commit Transaction-\n");	
	ret=DESFIRE_CommitTransaction(&Status);
															
	if(!CheckFuncDESFIRE("Commit Transaction",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get Value File -----------	
	printf("\n-Get Value File 05-\n");	
	ret=DESFIRE_GetValue(FILEID05, COMMMODE, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("Get Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Value = ");
		for(i=0; i<4; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Delete Value File -----------	
	printf("\n-Delete Value File 05-\n");	
	ret=DESFIRE_DeleteFile(FILEID05, &Status);
															
	if(!CheckFuncDESFIRE("Delete Value File",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get File ID -----------	
	printf("\n-Get File ID-\n");	
	ret=DESFIRE_GetFileID(MAXFILEID, &Status, &NbIDFound, DataRead);
															
	if(!CheckFuncDESFIRE("Get File ID",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Nb ID = %02X", NbIDFound);
		printf("\n File IDs = ");
		for(i=0; i<NbIDFound; i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

//---- Test Select Application -----------	
	printf("\n-Select Application 000000-\n");	
	ret=DESFIRE_SelectApplication(APPID00, &Status);
															
	if(!CheckFuncDESFIRE("Select Application",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Authentication -----------	
	printf("\n-Authentication-\n");	
	ret=DESFIRE_Authenticate(KEYNUM00, &Status);
															
	if(!CheckFuncDESFIRE("Authentication",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Delete Application -----------	
	printf("\n-Delete Application 3005F2-\n");	
	ret=DESFIRE_DeleteApplication(APPID01, &Status);
															
	if(!CheckFuncDESFIRE("Delete Application",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

//---- Test Get Application IDs -----------	
	printf("\n-Get Application IDs-\n");	
	ret=DESFIRE_GetApplicationIDs(NUMID, &Lg, &Status, DataRead);
															
	if(!CheckFuncDESFIRE("Get Application IDs",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n IDs = ");
		for(i=0; i<(Lg-2); i++)
		{
			printf("%02X ", DataRead[i]);
		}
	}
	printf("\n");

/*
//---- Test Get Free Memory -----------	
	printf("\n-Get Free Memory Card-\n");	
	ret=DESFIRE_GetFreeMem(&Status, DataRead);
															
	if(!CheckFuncDESFIRE("Get Free Memory Card",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n Size = ");
		for(i=0; i<3; i++)
			printf("%02X ", DataRead[i]);
	}
	printf("\n");
*/
}

/******************************************************************/
void SRxClassTest(BYTE* tx)
/*****************************************************************
Test of SRx family class with a Genxx

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{

	DWORD ret			= 0;
	BYTE Status			= 0;
	BYTE ChipType		= 0;
	BYTE Lg				= 0;
	BYTE i				= 0;
	BYTE UID[8]			= {0};
	BYTE DataRead[240] 	= {0};
	BYTE DataToWrite[8] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
	BYTE InitDataToWrite[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

	#define BLOCKNUM		0x09
	#define NUMBLOCK		0x02
	#define ADD				0x001C
	#define NUMBYTES		0x08
	#define PARAMRELEASE	0x00

//---- Test Activate SRx -----------	
	printf("\n-Activate SRx-\n");	
	// function Authenticate
	ret=SRX_Active(&Status, &ChipType, UID);
															
	if(!CheckFuncSRx("Activate SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n ChipType = %d", ChipType);
		printf("\n UID = ");
		for(i=0; i<8; i++)
		{
			printf("%02X ",UID[i]);
		}
		printf("\n");
	}
	printf("\n");

	
//---- Test ReadBlock 9 et 10 SRx -----------	
	printf("\n-ReadBlock SRx-\n");	
	// function Authenticate
	ret=SRX_ReadBlock(BLOCKNUM, NUMBLOCK, ChipType, &Lg, &Status, DataRead);
															
	if(!CheckFuncSRx("ReadBlock SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(Lg-1); i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");
	
//---- Test WriteBlock 9 et 10 SRx -----------	
	printf("\n-WriteBlock SRx-\n");	
	// function Authenticate
	ret=SRX_WriteBlock(BLOCKNUM, NUMBLOCK, DataToWrite, ChipType, &Lg, &Status, DataRead);
															
	if(!CheckFuncSRx("WriteBlock SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(Lg-1); i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");
	
//---- Test ClearBlock 9 et 10 SRx -----------	
	printf("\n-ClearBlock SRx-\n");	
	// function Authenticate
	ret=SRX_WriteBlock(BLOCKNUM, NUMBLOCK, InitDataToWrite, ChipType, &Lg, &Status, DataRead);
															
	if(!CheckFuncSRx("ClearBlock SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(Lg-1); i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");
	
//---- Test Read ADD 28 SRx -----------	
	printf("\n-Read ADD SRx-\n");	
	// function Authenticate
	ret=SRX_Read(ADD, NUMBYTES, ChipType, &Lg, &Status, DataRead);
															
	if(!CheckFuncSRx("Read ADD SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(Lg-1); i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");


//---- Test Write ADD 28 SRx -----------	
	printf("\n-Write ADD SRx-\n");	
	// function Authenticate
	ret=SRX_Write(ADD, NUMBYTES, DataToWrite, ChipType, &Lg, &Status, DataRead);
															
	if(!CheckFuncSRx("Write ADD SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(Lg-1); i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");


//---- Test Clear ADD 28 SRx -----------	
	printf("\n-Clear ADD SRx-\n");	
	// function Authenticate
	ret=SRX_Write(ADD, NUMBYTES, InitDataToWrite, ChipType, &Lg, &Status, DataRead);
															
	if(!CheckFuncSRx("Clear ADD SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
	{
		// affiche les data
		printf("\n DataRead = ");
		for(i=0; i<(Lg-1); i++)
		{
			printf("%02X ", DataRead[i]);
		}
		printf("\n");
	}
	printf("\n");


//---- Test Release SRx -----------	
	printf("\n-Release SRx-\n");	
	// function Authenticate
	ret=SRX_Release(PARAMRELEASE, &Status);
															
	if(!CheckFuncSRx("Release SRx",ret,Status))
	{
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	printf("\n");

}


/******************************************************************/
void GenClassTestISO14443B(void)
/*****************************************************************
Test of ISO14443 type B with GTML2

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	unsigned char tx[256];
	DWORD ret,ln;
	DWORD CounterValue;

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_1000[]={0x10,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_3115[]={0x31,0x00,0x31,0x15};
	BYTE SEL_3102[]={0x31,0x00,0x31,0x02};
	BYTE SEL_3100[]={0x31,0x00};
	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;
	sCARD_SecurParam Secur;



	Secur.AccMode=0;
	Secur.LID=0;
	Secur.SID=0;
	Secur.NKEY=0;
	Secur.RFU=0;

/*---- Test the PINStatus  Function -----*/
	ret=PINStatus(&Status);
	if(!CheckFunc("PINStatus (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Change PIN et Verify PIN -----------*/	
		
	// function SELECT FILE
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("SelectFile Master File (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	Secur.NKEY=0x17;
	ret=VerifyPIN(Secur,OLDPIN,&Status);
	if(!CheckFunc("VerifyPIN (GTML) '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CHANGE PIN
	Secur.NKEY=0x16;
	ret=ChangePIN(Secur,OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("ChangePIN (GTML) '30 30 30 30' -> '31 31 31 31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	Secur.NKEY=0x17;
	ret=VerifyPIN(Secur,NEWPIN,&Status);
	if(!CheckFunc("VerifyPIN (GTML) '31 31 31 31''",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.AccMode=GEN_ACCESS_MODE_DEFAULT;
	Secur.SID=GTML_SID_MF_ID;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord ID (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function CHANGE PIN
	Secur.NKEY=0x16;
	ret=ChangePIN(Secur,NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("ChangePIN (GTML) '31 31 31 31'' -> '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Select File -----*/	
	
	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=2)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function Select File 3F00
	ret=SelectFile(GEN_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("SelectFile (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=1)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Select File 2010
	ret=SelectFile(GEN_SEL_PATH,SEL_2010,sizeof(SEL_2010),tx,&Status);
	if(!CheckFunc("SelectFile 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=4)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Append Record in session -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=0x17;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,NULL,&Status);
	if(!CheckFunc("OpenSession - File (GTML) :None - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Append Record
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	Secur.SID=0;
	ret=AppendRecord(Secur,tx,29,&Status);
	if(!CheckFunc("AppendRecord 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=0x03;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	Secur.SID=GTML_SID_RT_ALL_COUNTERS;
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=UpdateRecord(Secur,1,27,tx,&Status);
	if(!CheckFunc("UpdateRecord All counters (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x01\x01\x01",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");

	// function Increase and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=Increase(Secur,0,0x101010,&CounterValue,&Status);
	if(!CheckFunc("Increase 0x0A (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x111111) printf("\nProbleme lors de l'icrementation du compteur 0x0A");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x0A (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x11\x11\x11",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");

	// function Read Record and test the value 

	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=Decrease(Secur,0,0x101010,&CounterValue,&Status);
	if(!CheckFunc("Decrease 0x0A (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x010101) printf("\nProbleme lors de la decrementation du compteur 0x0A");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_1;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x0A (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x1\x1\x1",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");


	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=0x03;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	Secur.SID=GTML_SID_RT_ALL_COUNTERS;
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=UpdateRecord(Secur,1,27,tx,&Status);
	if(!CheckFunc("UpdateRecord All counters (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 20 10 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x09\x09\x09",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");

	// function Increase and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=Increase(Secur,0,0x909090,&CounterValue,&Status);
	if(!CheckFunc("Increase 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x999999) printf("\nProbleme lors de l'icrementation du compteur 0x09");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x99\x99\x99",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");



	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=Decrease(Secur,0,0x909090,&CounterValue,&Status);
	if(!CheckFunc("Decrease 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x090909) printf("\nProbleme lors de la decrementation du compteur 0x09");

	// function Read Record and test the value 
	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x9\x9\x9",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");


	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Update Record in session (Reload) -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=0x03;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_CONTRACTS;
	ZeroMemory(tx,29);
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord 0x09 (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",29);
	if(ret!=0) printf("\nProbleme lors du contole du contrat");
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML)",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Write Record in session -----*/	
	
	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=0x17;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=WriteRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("WriteRecord RT_CONTRACTS (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_COUNTER_9;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord RT_CONTRACTS (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x9\x9\x9",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 09");
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record in session (Reload) -----*/	

	// function OPEN SESSION
	Secur.SID=GTML_SID_RT_EVENTS_LOG;
	Secur.NKEY=0x03;
	ret=OpenSession(SESSION_LEVEL_RELOAD,Secur,1,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ZeroMemory(tx,29);
	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=UpdateRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("UpdateRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	Secur.SID=GTML_SID_RT_CONTRACTS;
	ret=ReadRecord(Secur,1,29,tx,&Status);
	if(!CheckFunc("ReadRecord 0x09 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",29);
	if(ret!=0) printf("\nProbleme lors du contole du contrat");
	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Invalidate function in session (Valid) -----*/	

	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	
	// function OPEN SESSION
	Secur.SID=0;
	Secur.NKEY=0x17;
	ret=OpenSession(SESSION_LEVEL_VALID,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Valid",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Invalidate
	ret=Invalidate(Secur,&Status);
	if(!CheckFunc("Invalidate RT (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


/*---- Test the Rehabilitate function in session (Reload) -----*/	

	// function Select File 2000
	ret=SelectFile(GEN_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("SelectFile 20 00 (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function OPEN SESSION
	Secur.SID=0;
	Secur.NKEY=0x16;
	ret=OpenSession(SESSION_LEVEL_PERSO,Secur,0,&Session,&Status);
	if(!CheckFunc("OpenSession - File:Events Log (GTML) - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Rehabilitate
	ret=Rehabilitate(Secur,&Status);
	if(!CheckFunc("Reabilitate RT (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=CloseSession(tx,&ln,&Status);
	if(!CheckFunc("CloseSession (GTML) ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

return;

}

/******************************************************************/
void GenClassTestISO14443B_old(void)
/*****************************************************************
Test of ISO14443 type B with GTML2

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	unsigned char tx[256];
	DWORD ret,ln;
	DWORD CounterValue;

	BYTE SEL_MF[]={0x3F,0x00};
	BYTE SEL_1000[]={0x10,0x00};
	BYTE SEL_2000[]={0x20,0x00};
	BYTE SEL_2010[]={0x20,0x00,0x20,0x10};
	BYTE SEL_3115[]={0x31,0x00,0x31,0x15};
	BYTE SEL_3102[]={0x31,0x00,0x31,0x02};
	BYTE SEL_3100[]={0x31,0x00};
	BYTE OLDPIN[4]={0x30,0x30,0x30,0x30};
	BYTE NEWPIN[4]={0x31,0x31,0x31,0x31};

	sCARD_Status Status;
	sCARD_Session Session;


/*---- Test the Change PIN et Verify PIN -----------*/	
		
	// function SELECT FILE
	ret=GTML_SelectFile(GTML_SEL_MF,SEL_MF,sizeof(SEL_MF),NULL,&Status);
	if(!CheckFunc("GTML_SelectFile Master File",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function VERIFY PIN
	ret=GTML_VerifyPIN(OLDPIN,&Status);
	if(!CheckFunc("GTML_VerifyPIN '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CHANGE PIN
	ret=GTML_ChangePIN(OLDPIN,NEWPIN,&Status);
	if(!CheckFunc("GTML_ChangePIN '30 30 30 30' -> '31 31 31 31'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function VERIFY PIN
	ret=GTML_VerifyPIN(NEWPIN,&Status);
	if(!CheckFunc("GTML_VerifyPIN '31 31 31 31''",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_MF_ID,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord ID",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function CHANGE PIN
	ret=GTML_ChangePIN(NEWPIN,OLDPIN,&Status);
	if(!CheckFunc("GTML_ChangePIN '31 31 31 31'' -> '30 30 30 30'",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Select File -----*/	
	
	// function Select File 2000
	ret=GTML_SelectFile(GTML_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
	if(!CheckFunc("GTML_SelectFile 20 00 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=2)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}


	// function Select File 3F00
	ret=GTML_SelectFile(GTML_SEL_MF,SEL_MF,sizeof(SEL_MF),tx,&Status);
	if(!CheckFunc("GTML_SelectMasterFile ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=1)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Select File 2010
	ret=GTML_SelectFile(GTML_SEL_PATH,SEL_2010,sizeof(SEL_2010),tx,&Status);
	if(!CheckFunc("GTML_SelectFile 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}
	if(tx[3]!=4)
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Append Record in session -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_VALID,GTML_SID_RT_EVENTS_LOG,1,NULL,&Status);
	if(!CheckFunc("GTML_OpenSession - File:None - Perso",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Append Record
	memcpy(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29);
	ret=GTML_AppendRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_CURRENT_EF,tx,29,&Status);
	if(!CheckFunc("GTML_AppendRecord 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

/*---- Test the Update Record, increase and decrease in session (Reload) -----*/	
	
	// function OPEN SESSION
	ret=GTML_OpenSession(SESSION_LEVEL_RELOAD,GTML_SID_RT_EVENTS_LOG,1,&Session,&Status);
	if(!CheckFunc("GTML_OpenSession - File:Events Log - Reload",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	memcpy(tx,Session.Data,29);
	ret=(memcmp(tx,"\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D",29));
	if(ret!=0) printf("\nProbleme lors du contole de l'AppendRecord");

	
	// function Update Record
	memcpy(tx,"\x1\x1\x1\x2\x2\x2\x3\x3\x3\x4\x4\x4\x5\x5\x5\x6\x6\x6\x7\x7\x7\x8\x8\x8\x9\x9\x9",27);
	ret=GTML_UpdateRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_ALL_COUNTERS,1,27,tx,&Status);
	if(!CheckFunc("GTML_UpdateRecord All counters ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,1,29,tx,&Status);
	if(!CheckFunc("GTML_AppendRecord 20 10 ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x01\x01\x01",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");

	// function Increase and test the value 
	ret=GTML_Increase(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,0x101010,&CounterValue,&Status);
	if(!CheckFunc("GTML_Increase 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x111111) printf("\nProbleme lors de l'icrementation du compteur 0x0A");

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x11\x11\x11",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");



	ret=GTML_Decrease(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,0x101010,&CounterValue,&Status);
	if(!CheckFunc("GTML_Decrease 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	if(CounterValue != 0x010101) printf("\nProbleme lors de la decrementation du compteur 0x0A");

	// function Read Record and test the value 
	ret=GTML_ReadRecord(GTML_ACCESS_MODE_DEFAULT,GTML_SID_RT_COUNTER_1,1,29,tx,&Status);
	if(!CheckFunc("GTML_ReadRecord 0x0A ",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}

	ret = memcmp(tx,"\x1\x1\x1",3);
	if(ret!=0) printf("\nProbleme lors du contole du compteur 0A");


	// function CLOSE SESSION
	ret=GTML_CloseSession(tx,&ln,&Status);
	if(!CheckFunc("GTML_CloseSession",ret,&Status))
	{
		CSC_AntennaOFF();
		CSC_Close();
		SetErrorTo1();
		return;
	}



}

/****************************************************************/
void SystemClassTest(void)
/*****************************************************************
Test of System Class function 

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	int Choice;
	BYTE tx[256];
	DWORD ret;
	BYTE lpATR[32]; 
	DWORD lpcbATR[1];
	BYTE lpREC[32]; 
	DWORD lpcbREC[1];
	DWORD ln;
	DWORD timer;
	DWORD timer2;
	BYTE COM;
	sCARD_Search SearchOld;
	sCARD_SearchExt SearchStruct;
	DWORD search_mask;
	BYTE SEL_2000[]={0x20,0x00};
	sCARD_Status Status;
	BYTE Result;
	BYTE StatusByte;

	sCARD_SearchExt* Search=&SearchStruct;

	const BYTE BufCmdSAM[]	 ={0x94, 0x14, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44}; 
	const BYTE BufCmdSAMISO[]={0x94, 0x14, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x01}; 
	const BYTE BufCmdOUT_ISO[]	={0x94, 0xB2, 0x01, 0x44, 0x1D, 0x02}; //read journal du transport
	const BYTE BufCmd_IN_ISO[]	={0x94, 0x86, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01}; 
	const BYTE BufCmdINOUT_ISO[]={0x94, 0xA4, 0x08, 0x00, 0x02, 0x20, 0x00, 0x03}; 

	do
	{
		_flushall();

		CSC_Close();

		// Search the ASK CSC on PC serial port
		ret=CSC_SearchCSC();
		if(ret!=RCSC_Ok){
			Mess("Search CSC function fail.",ret);
		}
		
		printf("\n-------------------------------------------------------\n");
		printf("\n---------------- system class test --------------------\n");
		printf("\nWhich Test ?"); 
		printf("\n 1:CPU LED 1 On"); 
		printf("\n 2:CPU LED 2 On"); 
		printf("\n 3:CPU LED 3 On"); 
		printf("\n 4:ANT LED 1 On"); 
		printf("\n 5:ANT LED 2 On"); 
		printf("\n 6:ANT BUZZER On"); 
		printf("\n 7:LED 123 CPU On"); 
		printf("\n 8:SAM on SLOT 1 in HSP "); 
		printf("\n 9:SAM on SLOT 2 in HSP "); 
		printf("\n A:SAM on SLOT 3 in ISO "); 
		printf("\n B:Card on SLOT 4 in ISO (CD97) "); 
		printf("\n C:SAM transparent commands "); 
		printf("\n D:Contact Card commands (CD97)"); 
		printf("\n E:Contactless Card transparent commands (CD97)"); 
		printf("\n F:Contact Card transparent commands (CD97)");
		printf("\n G:Change Speed commands "); 
		printf("\n H:Search Card commands - CSC_SearchCardExt ");
		printf("\n I:Search Card commands - CSC_SearchCard ");
		printf("\n J:SetTimings command ");
		printf("\n Press ESC key to exit\n"); 

		Choice=_getch();
		switch(Choice)
		{
			case '1':	CSC_Switch_Led_Buz(CSC_CPU_LED1);
				 		printf("\nLED 1 CPU On.\n");
						break;
			case '2':	CSC_Switch_Led_Buz(CSC_CPU_LED2);
						printf("\nLED 2 CPU On.\n");
						break;
			case '3':	CSC_Switch_Led_Buz(CSC_CPU_LED3);
				 		printf("\nLED 3 CPU On.\n");
						break;
			case '4':	CSC_Switch_Led_Buz(CSC_ANT_LED1);
				 		printf("\nLED 1 ANT On.\n");
						break;
			case '5':	CSC_Switch_Led_Buz(CSC_ANT_LED2);
				 		printf("\nLED 2 ANT On.\n");
						break;
			case '6':	CSC_Switch_Led_Buz(CSC_ANT_BUZZER);
				 		printf("\nBUZZER ANT On.\n");
						break;
			case '7':	CSC_Switch_Led_Buz(CSC_CPU_LED1|CSC_CPU_LED2|CSC_CPU_LED3);
				 		printf("\nLED 123 CPU On.\n");
						break;
			case '8':	ret = CSC_SelectSAM(SAM_SLOT_1, SAM_PROT_HSP_INNOVATRON);
						if (ret==RCSC_Ok)
							printf("\nSAM 1 Select Ok.\n");
						else
						{
							printf("\nSAM 1 Select fail.\n");
							SetErrorTo1();
							break;
						}

						ret = CSC_ResetSAM(lpATR, lpcbATR);
						if (ret==RCSC_Ok)
							printf("\nSAM 1 Reset Ok.\n");
						else
						{
							printf("\nSAM 1 Reset fail.\n");
							SetErrorTo1();
							break;
						}
						
						lpcbATR[0]=sizeof (BufCmdSAM);
						memcpy(lpATR, BufCmdSAM,lpcbATR[0]);
						ret = CSC_ISOCommandSAM(lpATR, lpcbATR[0], lpREC, lpcbREC);

						if ((ret==RCSC_Ok) && (lpREC[0]==0x90) && (lpREC[1]==0x00) && (lpcbREC[0]==0x03))
							printf("\nSAM Communication Ok\n");
						else
						{
							printf("\nSAM Communication fail\n");
							SetErrorTo1();
						}
						break;
			case '9':	ret = CSC_SelectSAM(SAM_SLOT_2, SAM_PROT_HSP_INNOVATRON);
						if (ret==RCSC_Ok)
							printf("\nSAM 2 Select Ok.\n");
						else
						{
							printf("\nSAM 2 Select fail.\n");
							SetErrorTo1();
							break;
						}

						ret = CSC_ResetSAM(lpATR, lpcbATR);
						if (ret==RCSC_Ok)
							printf("\nSAM 2 Reset Ok.\n");
						else
						{
							printf("\nSAM 2 Reset fail.\n");
							SetErrorTo1();
							break;
						}
						lpcbATR[0]=sizeof (BufCmdSAM);
						memcpy(lpATR, BufCmdSAM,lpcbATR[0]);
						ret = CSC_ISOCommandSAM(lpATR, lpcbATR[0], lpREC, lpcbREC);

						if ((ret==RCSC_Ok) && (lpREC[0]==0x90) && (lpREC[1]==0x00) && (lpcbREC[0]==0x03))
							printf("\nSAM Communication Ok\n");
						else
						{
							printf("\nSAM Communication fail\n");
							SetErrorTo1();
						}
						break;
			case 'a':	
			case 'A':	
						ret = CSC_SelectSAM(SAM_SLOT_3, SAM_PROT_ISO_7816);
						if (ret==RCSC_Ok)
							printf("\nSAM 3 Select Ok.\n");
						else
						{
							printf("\nSAM 3 Select fail.\n");
							SetErrorTo1();
							break;
						}
						ret = CSC_ResetSAM(lpATR, lpcbATR);
						if (ret==RCSC_Ok)
							printf("\nSAM 3 Reset Ok.\n");
						else
						{
							printf("\nSAM 3 Reset fail.\n");
							SetErrorTo1();
							break;
						}
						lpcbATR[0]=sizeof (BufCmdSAMISO);
						memcpy(lpATR, BufCmdSAMISO,lpcbATR[0]);
						ret = CSC_ISOCommandSAM(lpATR, lpcbATR[0], lpREC, lpcbREC);

						if ((ret==RCSC_Ok) && (lpREC[0]==0x90) && (lpREC[1]==0x00) && (lpcbREC[0]==0x03))
							printf("\nSAM Communication Ok\n");
						else
						{
							printf("\nSAM Communication fail\n");
							SetErrorTo1();
						}
						break;
						

			case 'b':	
			case 'B':	
						CSC_AntennaOFF();
						ret = CSC_SelectSAM(SAM_SLOT_4, SAM_PROT_ISO_7816);
						if (ret==RCSC_Ok)
							printf("\nSAM 4 Select Ok.\n");
						else
						{
							printf("\nSAM 4 Select fail.\n");
							SetErrorTo1();
							break;
						}
						ret = CSC_ResetSAM(lpATR, lpcbATR);
						if (ret==RCSC_Ok)
							printf("\nSAM 4 Reset Ok.\n");
						else
						{
							printf("\nSAM 4 Reset fail.\n");
							SetErrorTo1();
							break;
						}
						lpcbATR[0]=sizeof (BufCmdOUT_ISO);
						memcpy(lpATR, BufCmdOUT_ISO,lpcbATR[0]);
						ret = CSC_ISOCommandSAM(lpATR, lpcbATR[0], lpREC, lpcbREC);

						if ((ret==RCSC_Ok) && (lpREC[0x1D]==0x90) && (lpREC[0x1E]==0x00) && (lpcbREC[0]==0x20))
							printf("\nCard Communication OUT Ok\n");
						else
						{
							printf("\nCard Communication OUT fail\n");
							SetErrorTo1();
							break;
						}
						lpcbATR[0]=sizeof (BufCmd_IN_ISO);
						memcpy(lpATR, BufCmd_IN_ISO,lpcbATR[0]);
						ret = CSC_ISOCommandSAM(lpATR, lpcbATR[0], lpREC, lpcbREC);

						if ((ret==RCSC_Ok) && (lpREC[0]==0x90) && (lpREC[1]==0x00) && (lpcbREC[0]==0x03))
							printf("\nCard Communication IN Ok\n");
						else
						{
							printf("\nCard Communication IN fail\n");
							SetErrorTo1();
							break;
						}
						lpcbATR[0]=sizeof (BufCmdINOUT_ISO);
						memcpy(lpATR, BufCmdINOUT_ISO,lpcbATR[0]);
						ret = CSC_ISOCommandSAM(lpATR, lpcbATR[0], lpREC, lpcbREC);

						if ((ret==RCSC_Ok) && (lpcbREC[0]==0x1C))
							printf("\nCard Communication IN-OUT Ok\n");
						else
						{
							printf("\nCard Communication IN-OUT fail\n");
							SetErrorTo1();
						}

						break;


			case 'c':				
			case 'C':				
					/* TEST SAM Functions  */
					printf("\nTest SAM Functions \n"); 
					// function RESET SAM
					ret=CSC_ResetSAM(tx,&ln);
					if(ret!=RCSC_Ok){
						printf("\nError ResetSAM. code : %d",ret);
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");

					// function SEND ISO TO SAM
					ret=CSC_ISOCommandSAM("\x94\x14\0\0\4\1\2\3\4",9,tx,&ln);
					if(ret!=RCSC_Ok){
						printf("\nError ISOCommandSAM. code: %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if((ln!=3)||(tx[0]!=0x90)||(tx[1]!=0))	{
						printf("\nError return value ISOCommandSAM. code %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");
					break;

					
			case 'd':				
			case 'D':				
					/* Contact Card Functions  */
					printf("\nContact Card Functions \n"); 
					Search->CONT=1;
					Search->ISOB=0;
					Search->ISOA=0;
					Search->TICK=0;
					Search->INNO=0;
					Search->MV4k=0;
					Search->MV5k=0;
					Search->MIFARE=0;
					search_mask=SEARCH_MASK_CONT;

					ret=CSC_SearchCardExt(Search,search_mask,0x01,100,&COM,&ln,tx);
					if (ret != RCSC_Ok)	
					{
						printf("\nReset Card in contact Error . code %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					else
					{
						if(COM==0x6F)	
						{
							printf("\nReset Card in contact Timout . code %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else			
							printf(".");
					}

					// function send a command to a Contact Card
					/*---- Test the Select File function -----*/		
					// function SELECT FILE
					ret=CD97_SelectFile(CD97_SEL_PATH,SEL_2000,sizeof(SEL_2000),tx,&Status);
					if(!CheckFunc("CD97_SelectFile 2000",ret,&Status))
					{
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					else 
							printf(".");
					if ((tx[0] != 0x85) || (tx[1] != 0x17))
					{
						printf("\nError in data returned. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}

					printf(".");
					
					
					break;

					
			case 'e':				
			case 'E':				
					/* Contactless Card ISO transparent commands */
					printf("\nContactless Card ISO transparent commands\n"); 
					(*Search).CONT=0;
					(*Search).ISOB=0;
					(*Search).ISOA=0;
					(*Search).TICK=0;
					(*Search).INNO=1;
					(*Search).MV4k=0;
					(*Search).MV5k=0;
					(*Search).MIFARE=0;
					search_mask=SEARCH_MASK_INNO;
					ret=CSC_SearchCardExt(Search,search_mask,0x01,100,&COM,&ln,tx);
					if (ret != RCSC_Ok)	
					{
						printf("\nReset Card in contactless Error . code %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					else
					{
						if(COM==0x6F)	
						{
							printf("\nReset Card in contact Timout . code %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else			
							printf(".");
					}
					/* Transparent Command Select File */
						tx[0] = 0x94;
						tx[1] = 0xA4;
						tx[2] = 0x00;
						tx[3] = 0x00;
						tx[4] = 0x02;
						tx[5] = 0x3F;
						tx[6] = 0x00;
						ln = 7; 
					ret=CSC_ISOCommand(tx,ln,tx,&ln);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Sending commande in transparent Mode. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if (ln != 0x1C) 
					{
						printf("\nError in data returned. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}

					printf(".");
					break;

			case 'f' :
			case 'F' :
					/* Contact Card ISO transparent commands */
					printf("\nContact Card ISO transparent commands\n"); 
					Search->CONT=1;
					Search->ISOB=0;
					Search->ISOA=0;
					Search->TICK=0;
					Search->INNO=0;
					Search->MV4k=0;
					Search->MV5k=0;
					Search->MIFARE=0;
					search_mask=SEARCH_MASK_CONT;
					ret=CSC_SearchCardExt(Search,search_mask,0x01,100,&COM,&ln,tx);
					if (ret != RCSC_Ok)	
					{
						printf("\nReset Card in contact Error . code %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					else
					{
						if(COM==0x6F)	
						{
							printf("\nReset Card in contact Timout . code %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else			
							printf(".");
					}
					
					/* Select SAM slot contact */

					ret=CSC_SelectSAM(CONTACT_SLOT,1);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Selecting SAM slot contact. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");
					
					/* Transparent Command Select File - IN and OUT */
						tx[0] = 0x94;
						tx[1] = 0xA4;
						tx[2] = 0x00;
						tx[3] = 0x00;
						tx[4] = 0x02;
						tx[5] = 0x3F;
						tx[6] = 0x00;
						ln = 7; 
					ret=CSC_ISOCommandContact(tx,ln,03,tx,&ln);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Sending command in transparent,contact Mode - IN and OUT. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if (ln != 0x1B) 
					{
						printf("\nError in data returned. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}

					printf(".");
					
					/* Transparent Command Select File - IN */
						tx[0] = 0x94;
						tx[1] = 0xA4;
						tx[2] = 0x00;
						tx[3] = 0x00;
						tx[4] = 0x02;
						tx[5] = 0x3F;
						tx[6] = 0x00;
						ln = 7; 
					ret=CSC_ISOCommandContact(tx,ln,01,tx,&ln);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Sending command in transparent,contact Mode - IN. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if ((ln !=0x02)||(tx[0]!=0x90)||(tx[1]!=0x00)) 
					{
						printf("\nError in data returned. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}

					printf(".");

					/* Transparent Command GET RESPONSE - OUT */
						tx[0] = 0x00;
						tx[1] = 0xC0;
						tx[2] = 0x00;
						tx[3] = 0x00;
						tx[4] = 0x00;
						ln = 5; 
					ret=CSC_ISOCommandContact(tx,ln,02,tx,&ln);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Sending command in transparent,contact Mode - OUT. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if ((ln != 0x02)||(tx[0]!=0x6C)) 
					{
						printf("\nError in data returned. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}

					printf(".");
					
					/* Select SAM slot 1 */

					ret=CSC_SelectSAM(SAM_SLOT_1,0);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Selecting SAM slot contact. code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");
					
					break;
						
			case 'g':				
			case 'G':				
					printf("\n Change Speed commandes "); 
					/********** 9600 BAUDS ***********/
					/* Change the CSC Speed */
					CSC_Close();
					ret=CSC_SearchCSC();
					if(ret!=RCSC_Ok){
						Mess("Search CSC function fail.",ret);
					}

					ret = CSC_ChangeCSCSpeed(9600, 115200, 115200, &Result);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");

					/* Reset Command */
					tx[0]=0x01;	// Reset Command
					ln=1;
					ret=CSC_SendReceive(2000, tx, ln, tx, &ln);
					// no control on the result which should be in the new baud rate

					/* Change the DLL Speed */
					CSC_ChangeDLLSpeed(9600);

					CSC_Close();
					ret=CSC_SearchCSC();
					if(ret!=RCSC_Ok){
						Mess("Search CSC function fail.",ret);
					}
					ret=CSC_VersionCSC(tx);
					if (ret == RCSC_Ok)		
						printf(".");
					else 					
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if ((tx[0] != 0x43) || (tx[1] != 0x53) || (tx[2] != 0x43))
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");
					/********** 19200 BAUDS ***********/
					/* Change the CSC Speed */
					ret = CSC_ChangeCSCSpeed(19200, 115200, 115200, &Result);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");

					/* Reset Command */
					tx[0]=0x01;	// Reset Command
					ln=1;
					ret=CSC_SendReceive(2000, tx, ln, tx, &ln);
					// no control on the result which should be in the new baud rate

					/* Change the DLL Speed */
					CSC_ChangeDLLSpeed(19200);

					CSC_Close();
					ret=CSC_SearchCSC();
					if(ret!=RCSC_Ok){
						Mess("Search CSC function fail.",ret);
					}
					ret=CSC_VersionCSC(tx);
					if (ret == RCSC_Ok)		
						printf(".");
					else 					
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if ((tx[0] != 0x43) || (tx[1] != 0x53) || (tx[2] != 0x43))
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");
					/********** 57600 BAUDS ***********/
					/* Change the CSC Speed */
					ret = CSC_ChangeCSCSpeed(57600, 115200, 115200, &Result);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");

					/* Reset Command */
					tx[0]=0x01;	// Reset Command
					ln=1;
					ret=CSC_SendReceive(2000, tx, ln, tx, &ln);
					// no control on the result which should be in the new baud rate

					/* Change the DLL Speed */
					CSC_ChangeDLLSpeed(57600);

					CSC_Close();
					ret=CSC_SearchCSC();
					if(ret!=RCSC_Ok){
						Mess("Search CSC function fail.",ret);
					}
					ret=CSC_VersionCSC(tx);
					if (ret == RCSC_Ok)		
						printf(".");
					else 					
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if ((tx[0] != 0x43) || (tx[1] != 0x53) || (tx[2] != 0x43))
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");

					/********** 115200 BAUDS ***********/
					/* Change the CSC Speed */
					ret = CSC_ChangeCSCSpeed(115200, 115200, 115200, &Result);
					if(ret!=RCSC_Ok)
					{
						printf("\nError Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");

					/* Reset Command */
					tx[0]=0x01;	// Reset Command
					ln=1;
					ret=CSC_SendReceive(2000, tx, ln, tx, &ln);
					// no control on the result which should be in the new baud rate

					/* Change the DLL Speed */
					CSC_ChangeDLLSpeed(115200);

					CSC_Close();
					ret=CSC_SearchCSC();
					if(ret!=RCSC_Ok){
						Mess("Search CSC function fail.",ret);
					}
					ret=CSC_VersionCSC(tx);
					if (ret == RCSC_Ok)		
						printf(".");
					else 					
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					if ((tx[0] != 0x43) || (tx[1] != 0x53) || (tx[2] != 0x43))
					{
						printf("\nError after Changing CSC Speed . code : %d",ret);
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
						break;
					}
					printf(".");
					break;

			case 'h':				
			case 'H':				
				do {
					_flushall();
					printf("\n  commands "); 
					printf("\n-------------------------------------------------------\n");
					printf("\n              -> system /searchCardExt ----------------\n");
					printf("\nWhich Test ?"); 
					printf("\n 1:Search ISO 14443 - A Protocol - 'ISOA' "); 
					printf("\n 2:Search ISO 14443 - B Protocol"); 
					printf("\n 3:Search INNOVATRON Protocol"); 
					printf("\n 4:Search CTx Protocol "); 
					printf("\n 5:Search Contact Protocol"); 
					printf("\n 6:Combined Search ISO A,B"); 
					printf("\n 7:Combined Search ISO A,B, INNO"); 
					printf("\n 8:Combined Search ISO B, Ctx, INNO"); 
					printf("\n 9:Combined Search ISO All but Contact"); 
					printf("\n A:Combined Search ISO All "); 
					printf("\n B:Multi-type A card Search"); 
					printf("\n C:Multi-type B card Search ");
					printf("\n D:Old Style card Search loop");
					printf("\n E:Search ISO 14443 - A Protocol - 'MIFARE' ");
					printf("\n F:Multi-type A card Search - MIFARE"); 
					printf("\n G:Search MONO - all (cont,B,A,tick,Inno,MF,MV)"); 
					printf("\n x:to exit\n");
					Choice=_getch();
					switch(Choice)
					{
					case '1':	
						Search->CONT=0; Search->ISOB=0; Search->ISOA=1; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOA;
						break;
					case '2':	
						Search->CONT=0; Search->ISOB=1; Search->ISOA=0; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB;
						break;
					case '3':	
						Search->CONT=0; Search->ISOB=0; Search->ISOA=0; 
						Search->TICK=0; Search->INNO=1; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_INNO;
						break;
					case '4':	
						Search->CONT=0; Search->ISOB=0; Search->ISOA=1; 
						Search->TICK=1; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOA | SEARCH_MASK_TICK;
						break;
					case '5':	
						Search->CONT=1; Search->ISOB=0; Search->ISOA=0; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_CONT;
						break;
					case '6':	
						Search->CONT=0; Search->ISOB=1; Search->ISOA=1; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB | SEARCH_MASK_ISOA;
						break;
					case '7':	
						Search->CONT=0; Search->ISOB=1; Search->ISOA=1; 
						Search->TICK=0; Search->INNO=1; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB | SEARCH_MASK_ISOA | SEARCH_MASK_INNO;
						break;
					case '8':	
						Search->CONT=0; Search->ISOB=1; Search->ISOA=0; 
						Search->TICK=1; Search->INNO=1; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB | SEARCH_MASK_TICK | SEARCH_MASK_INNO;
						break;
					case '9':	
						Search->CONT=0; Search->ISOB=1; Search->ISOA=1; 
						Search->TICK=1; Search->INNO=1; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB | SEARCH_MASK_ISOA | SEARCH_MASK_INNO | SEARCH_MASK_TICK;
						break;
					case 'a':	
					case 'A':	
						Search->CONT=1; Search->ISOB=1; Search->ISOA=1; 
						Search->TICK=1; Search->INNO=1; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB | SEARCH_MASK_ISOA | SEARCH_MASK_INNO | SEARCH_MASK_TICK | SEARCH_MASK_CONT;
						break;
					case 'b':	
					case 'B':	
						Search->CONT=0; Search->ISOB=0; Search->ISOA=1; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOA;
						break;
					case 'c':	
					case 'C':	
						Search->CONT=0; Search->ISOB=1; Search->ISOA=0; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_ISOB;
						break;
					case 'e' :
					case 'E' :
						Search->CONT=0; Search->ISOB=0; Search->ISOA=0; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=1;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_MIFARE;
						break;
					case 'f' :
					case 'F' :
						Search->CONT=0; Search->ISOB=0; Search->ISOA=0; 
						Search->TICK=0; Search->INNO=0; Search->MIFARE=1;
						Search->MV4k=0; Search->MV5k=0;
						search_mask=SEARCH_MASK_MIFARE;
						break;
					case 'g' :
					case 'G' :
						Search->CONT=1; Search->ISOB=1; Search->ISOA=1; 
						Search->TICK=1; Search->INNO=1; Search->MIFARE=1;
						Search->MV4k=1; Search->MV5k=1; Search->MONO=1;
						search_mask=SEARCH_MASK_CONT |
									SEARCH_MASK_INNO |
									SEARCH_MASK_ISOA |
									SEARCH_MASK_ISOB |
									SEARCH_MASK_MIFARE |
									SEARCH_MASK_MONO |
									SEARCH_MASK_MV4K |
									SEARCH_MASK_MV5K |
									SEARCH_MASK_TICK;
						break;

					default : 
						break;
					}



					if ((Choice == 'd') || (Choice == 'D') )
					{
						// old style search loop
						ret = CSC_CardStartSearch();
						if (ret != RCSC_Ok)	
						{
							printf("\nCardStartSearch Error: %04X",ret);
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						while(1)
						{
							DWORD x=GetTickCount();
							while ((GetTickCount()-x)<5000);
							ret = CSC_CardFound(tx,&ln);
							if (ret != RCSC_CardNotFound)	
								if (ret != RCSC_Ok)	
								{
									printf("\nCardFound Error: %04X",ret);
									CSC_AntennaOFF();
									CSC_Close();
									break;
								}
								else
								{
									break;
								}

							ret = CSC_CardStopSearch();
							if (ret != RCSC_Ok)	
							{
								printf("\nCardStopSearch Error: %04X",ret);
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							ret = CSC_CardStartSearch();
							if (ret != RCSC_Ok)	
							{
								printf("\nCardStartSearch Error: %04X",ret);
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							printf(".");
						}

						ret = CSC_CardEnd();
						if (ret != RCSC_Ok)	
						{
							printf("\nCardEnd Error: %04X",ret);
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}

						break;
					}

					if ((Choice == 'x') || (Choice == 'X') )
						break;

					// for multi-card detection
					if ((Choice == 'b') || (Choice == 'B') || (Choice == 'c') || (Choice == 'C')|| (Choice == 'f') || (Choice == 'F'))
					{
						ret = CSC_EHP_PARAMS(5, 1, 0, 0, 0);	// 5 cards, Wup, AFI, Slots, Div
						if (ret == RCSC_Ok)		
							printf(".");
						else 					
						{
							printf("\nError changing EHP param . code : %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}

						ret = CSC_SelectCID(1, &Result); //CID, *Status
						if (ret == RCSC_Ok)		
							printf(".");
						else 					
						{
							printf("\nError Selecting CID . code : %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}

						ret=CSC_SearchCardExt(Search,search_mask,0x01,100,&COM,&ln,tx);
						if (ret != RCSC_Ok)	
						{
							printf("\nSearchCard Error: %04X",ret);
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else
						{
							if(COM==0x6F)	
							{
								printf("\nSearch Card Time Out\n");
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else
							{
								printf(".");
							}
						}

						if ((Choice == 'f') || (Choice == 'F'))
						{ // Type A - MIFARE
							printf(".");
							ret=MIFARE_Select(tx+2,4,&StatusByte,tx+2);
							if ((ret!=RCSC_Ok) || (StatusByte!=0x00))
							{
								printf("\nerror in type A card selection\n");
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else
							{
								printf(".");
								printf("\nMulti type A MIFARE cards test finished successfully\n");
							}
						
						}
						if ((Choice == 'b') || (Choice == 'B'))
						{// type A ISO
						}
						if ((Choice == 'c') || (Choice == 'C')) 
						{ // Type B
							if (ln <0x20)
							{
								printf("\nless than two card detected\n");
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else		
								printf(".");
								printf("\nMulti type B cards test finished successfully\n");

							tx[0] = tx[5];
							tx[1] = tx[6];
							tx[2] = tx[7];
							tx[3] = tx[8];
							ret = CSC_SelectDIV(1, 0, tx, &Result);// Slot, Prot, *DIV, *Status
						}
						
					}
					else					// for multi-card detection
					{

						ret=CSC_SearchCardExt(Search,search_mask,0x01,100,&COM,&ln,tx);

						if (ret != RCSC_Ok)	
						{
							printf("\nCard Detection Error . code %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else
						{
							printf("COM : %02X",COM);
							if(COM==0x6F)	
							{
								printf("\nCard Detection Timout . code %d",ret);
								SetErrorTo1();
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else			
								printf(".");
						}
					}


					} while(1);

			case 'i':				
			case 'I':				
				do {
					_flushall();
					printf("\n  commands "); 
					printf("\n-------------------------------------------------------\n");
					printf("\n              -> system /searchCard -------------------\n");
					printf("\nWhich Test ?"); 
					printf("\n 1:Search ISO 14443 - A Protocol"); 
					printf("\n 2:Search ISO 14443 - B Protocol"); 
					printf("\n 3:Search INNOVATRON Protocol"); 
					printf("\n 4:Search CTx Protocol "); 
					printf("\n 5:Search Contact Protocol"); 
					printf("\n 6:Combined Search ISO A,B"); 
					printf("\n 7:Combined Search ISO A,B, INNO"); 
					printf("\n 8:Combined Search ISO B, Ctx, INNO"); 
					printf("\n 9:Combined Search ISO All but Contact"); 
					printf("\n A:Combined Search ISO All "); 
					printf("\n B:Multi-type A card Search"); 
					printf("\n C:Multi-type B card Search ");
					printf("\n D:Old Style card Search loop");
					printf("\n x:to exit\n");
					Choice=_getch();
					switch(Choice)
					{
					case '1':	
						SearchOld.CONT=0; SearchOld.ISOB=0; SearchOld.ISOA=1; 
						SearchOld.TICK=0; SearchOld.INNO=0;
						break;
					case '2':	
						SearchOld.CONT=0; SearchOld.ISOB=1; SearchOld.ISOA=0; 
						SearchOld.TICK=0; SearchOld.INNO=0;
						break;
					case '3':	
						SearchOld.CONT=0; SearchOld.ISOB=0; SearchOld.ISOA=0; 
						SearchOld.TICK=0; SearchOld.INNO=1;
						break;
					case '4':	
						SearchOld.CONT=0; SearchOld.ISOB=0; SearchOld.ISOA=1; 
						SearchOld.TICK=1; SearchOld.INNO=0;
						break;
					case '5':	
						SearchOld.CONT=1; SearchOld.ISOB=0; SearchOld.ISOA=0; 
						SearchOld.TICK=0; SearchOld.INNO=0;
						break;
					case '6':	
						SearchOld.CONT=0; SearchOld.ISOB=1; SearchOld.ISOA=1; 
						SearchOld.TICK=0; SearchOld.INNO=0;
						break;
					case '7':	
						SearchOld.CONT=0; SearchOld.ISOB=1; SearchOld.ISOA=1; 
						SearchOld.TICK=0; SearchOld.INNO=1;
						break;
					case '8':	
						SearchOld.CONT=0; SearchOld.ISOB=1; SearchOld.ISOA=0; 
						SearchOld.TICK=1; SearchOld.INNO=1;
						break;
					case '9':	
						SearchOld.CONT=0; SearchOld.ISOB=1; SearchOld.ISOA=1; 
						SearchOld.TICK=1; SearchOld.INNO=1;
						break;
					case 'a':	
					case 'A':	
						SearchOld.CONT=1; SearchOld.ISOB=1; SearchOld.ISOA=1; 
						SearchOld.TICK=1; SearchOld.INNO=1;
						break;
					case 'b':	
					case 'B':	
						SearchOld.CONT=0; SearchOld.ISOB=0; SearchOld.ISOA=1; 
						SearchOld.TICK=0; SearchOld.INNO=0;
						break;
					case 'c':	
					case 'C':	
						SearchOld.CONT=0; SearchOld.ISOB=1; SearchOld.ISOA=0; 
						SearchOld.TICK=0; SearchOld.INNO=0;
						break;
					default : 
						break;
					}



					if ((Choice == 'd') || (Choice == 'D') )
					{
						// old style search loop
						ret = CSC_CardStartSearch();
						if (ret != RCSC_Ok)	
						{
							printf("\nCardStartSearch Error: %04X",ret);
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						while(1)
						{
							DWORD x=GetTickCount();
							while ((GetTickCount()-x)<5000);
							ret = CSC_CardFound(tx,&ln);
							if (ret != RCSC_CardNotFound)	
								if (ret != RCSC_Ok)	
								{
									printf("\nCardFound Error: %04X",ret);
									CSC_AntennaOFF();
									CSC_Close();
									break;
								}
								else
								{
									break;
								}

							ret = CSC_CardStopSearch();
							if (ret != RCSC_Ok)	
							{
								printf("\nCardStopSearch Error: %04X",ret);
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							ret = CSC_CardStartSearch();
							if (ret != RCSC_Ok)	
							{
								printf("\nCardStartSearch Error: %04X",ret);
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							printf(".");
						}

						ret = CSC_CardEnd();
						if (ret != RCSC_Ok)	
						{
							printf("\nCardEnd Error: %04X",ret);
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}

						break;
					}

					if ((Choice == 'x') || (Choice == 'X') )
						break;

					// for multi-card detection
					if ((Choice == 'b') || (Choice == 'B') || (Choice == 'c') || (Choice == 'C'))
					{
						ret = CSC_EHP_PARAMS(5, 1, 0, 0, 0);	// 5 cards, Wup, AFI, Slots, Div
						if (ret == RCSC_Ok)		
							printf(".");
						else 					
						{
							printf("\nError changing EHP param . code : %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}

						ret = CSC_SelectCID(1, &Result); //CID, *Status
						if (ret == RCSC_Ok)		
							printf(".");
						else 					
						{
							printf("\nError Selecting CID . code : %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}

						ret=CSC_SearchCard(SearchOld,0x01,100,&COM,&ln,tx);
						if (ret != RCSC_Ok)	
						{
							printf("\nSearchCard Error: %04X",ret);
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else
						{
							if(COM==0x6F)	
							{
								printf("\nSearch Card Time Out\n");
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else
							{
								printf(".");
							}
						}

						if ((Choice == 'b') || (Choice == 'B'))
						{// type A ISO
						}
						if ((Choice == 'c') || (Choice == 'C')) 
						{ // Type B
							if (ln <0x20)
							{
								printf("\nless than two card detected\n");
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else		
								printf(".");
								printf("\nMulti type A cards test finished successfully\n");

							tx[0] = tx[5];
							tx[1] = tx[6];
							tx[2] = tx[7];
							tx[3] = tx[8];
							ret = CSC_SelectDIV(1, 0, tx, &Result);// Slot, Prot, *DIV, *Status
						}
						
					}
					else					// for multi-card detection
					{

						ret=CSC_SearchCard(SearchOld,0x01,100,&COM,&ln,tx);

						if (ret != RCSC_Ok)	
						{
							printf("\nCard Detection Error . code %d",ret);
							SetErrorTo1();
							CSC_AntennaOFF();
							CSC_Close();
							break;
						}
						else
						{
							printf("COM : %02X",COM);
							if(COM==0x6F)	
							{
								printf("\nCard Detection Timout . code %d",ret);
								SetErrorTo1();
								CSC_AntennaOFF();
								CSC_Close();
								break;
							}
							else			
								printf(".");
						}
					}


					} while(1);
					
			case 'j':
			case 'J':
				printf("\n oter toute carte du champ de l'antenne et frapper 'return'\n");
				fflush(stdin);
				getchar();
				Search->CONT=0; Search->ISOB=1; Search->ISOA=0; 
				Search->TICK=0; Search->INNO=0; Search->MIFARE=0;
				Search->MV4k=0; Search->MV5k=0;
				search_mask=SEARCH_MASK_ISOB;
				
				//-------- test valeur timout par défaut
				// par défaut, timout searchCardExt = 3000 ms = 300*10ms = 0x12C * 10ms
				//             timout fonctions cartes = 2000 ms = 0xC8 * 10 ms
				ret=CSC_SearchCardExt(Search, search_mask,1,0xFE,&COM,&ln,tx);
				if ((ret!=RCSC_Ok)||(COM!=0x6F))	// avec FE comme timout, la fonction
													//  doit retourner ret=RCSC_Ok, et COM = 0x6F
				{
					printf("\ntimeout error 1");
					SetErrorTo1();
					CSC_AntennaOFF();
					CSC_Close();
					break;
				}
				
				//-------- test nouvelles valeurs timout
				// timout searchCardExt = 200 ms = 0x14 * 10 ms
				// timout fonction = 200 ms
				// 20% de marge
				CSC_SetTimings(200,200,0);
				
				ret=CSC_SelectSAM(CONTACT_SLOT,0);

				timer=GetTimer(0);
				ret=CSC_ResetSAM(tx,&ln);	// without any SAM, the DLL will fail before the timeout has expired
				timer2=GetTimer(timer);
				if ((timer2<160)||(timer2>240)||(ret==RCSC_Ok))
				{
					printf("\ntimeout error 2");
					CSC_SetTimings(2000,3000,0);		//restore default timings
					ret=CSC_SelectSAM(SAM_SLOT_1,0);	//restore SAM
					SetErrorTo1();
					CSC_AntennaOFF();
					CSC_Close();
					break;
				}

				ret=CSC_SelectSAM(SAM_SLOT_1,0);	//restore SAM

				timer=GetTimer(0);
				while((GetTimer(timer))<1000)
				{
				}

				ret=CSC_SearchCardExt(Search, search_mask,1,0x10,&COM,&ln,tx);
				printf("\nln:%02X, com:%02X,ret:%02X - doivent etre : 6F et 8001\n",ln,COM,ret);
				
				if ((ret!=RCSC_Ok)||(COM!=0x6F))	// avec 10 commme timout, la fonction
													//  doit retourner ret=RCSC_Ok, et COM = 0x6F
													// (20% de marge)
				{
					printf("\ntimeout error 3");
					CSC_SetTimings(2000,3000,0);		//restore default timings
					SetErrorTo1();
					CSC_AntennaOFF();
					CSC_Close();
					break;
				}

				ret=CSC_SearchCardExt(Search, search_mask,1,0x18,&COM,&ln,tx);
				if (ret==RCSC_Ok)					// avec 18 comme timout, la fonction
													//  doit retourner ret!=RCSC_Ok
													// (20% de marge)
				{
					printf("\ntimeout error 4");
					CSC_SetTimings(2000,3000,0);		//restore default timings
					SetErrorTo1();
					CSC_AntennaOFF();
					CSC_Close();
					break;
				}

				CSC_SetTimings(2000,3000,0);		//restore default timings
				printf("\ntest finished succesfully...!");
				break;

			default :	
				break;
		}

	}
	while(Choice!=0x1B);
}




/****************************************************************/
void RS485Tests(void)
/*****************************************************************
Test of RS485 capabilities for a CSC address 6 and a CSC address 9

  INPUTS : None

  OUTPUTS : None

*****************************************************************/
{
	BYTE tx[256];
	DWORD ret;
	DWORD ln;
	BYTE COM, i;
	sCARD_SearchExt SearchStruct;
	DWORD search_mask;
	sCARD_SearchExt* Search=&SearchStruct;


	Search->CONT=0; Search->ISOB=0; Search->ISOA=0; 
	Search->TICK=0; Search->INNO=1; Search->MIFARE=0;
	Search->MV4k=0; Search->MV5k=0;
	search_mask=SEARCH_MASK_INNO;

	printf("\n Please connect the PC serial COM port 2 on the RS485 dispacher ");
	printf("\n                the CSC N° 6 and 9 should be present ");
	printf("\n                An Innovatron protocol compliant card will be seek \n");
	_getch();
	ret=CSC_Open("COM2");
	if(ret!=RCSC_Ok){
		Mess("Open CSC function fail. on serial port COM2 ",ret);
	}
	// CSC detection
	CSC_ChangeRS485Address(6);
	ret = CSC_VersionCSC(tx);
	if (ret != RCSC_Ok)	
	{
		SetErrorTo1();
		CSC_ChangeRS485Address(0);
		printf("\nError addressing CSC 6. code %d",ret);
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	CSC_ChangeRS485Address(9);
	ret = CSC_VersionCSC(tx);
	if (ret != RCSC_Ok)	
	{
		SetErrorTo1();
		CSC_ChangeRS485Address(0);
		printf("\nError addressing CSC 9. code %d",ret);
		SetErrorTo1();
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}

	// Card seek Activation 
	CSC_ChangeRS485Address(9);
	ret=CSC_SearchCardExt(Search,search_mask,0x01,00,&COM,&ln,tx);
	if (ret != RCSC_Ok)	
	{
		SetErrorTo1();
		CSC_ChangeRS485Address(0);
		printf("\nSearchCard Error: %04X",ret);
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
		if ((COM == 0x6F)||(COM == 0x7F))
			printf("\n no innovatron protocol card on CSC 9 ");
		else
			printf("\nCard found on CSC 9 ");

	CSC_ChangeRS485Address(6);
	ret=CSC_SearchCardExt(Search,search_mask,0x01,00,&COM,&ln,tx);
	if (ret != RCSC_Ok)	
	{
		SetErrorTo1();
		CSC_ChangeRS485Address(0);
		printf("\nSearchCard Error: %04X",ret);
		CSC_AntennaOFF();
		CSC_Close();
		return;
	}
	else
		if ((COM == 0x6F)||(COM == 0x7F))
			printf("\n no innovatron protocol card on CSC 6 ");
		else
			printf("\nCard found on CSC 6 ");

	// Hunt Phase Loop 
	for (i=0; i<50; i++)
	{
		// Look on CSC 6
		CSC_ChangeRS485Address(6);
		ret = CSC_CardFound(tx, &ln);
		if (ret == RCSC_CardNotFound)	
			printf("\n no innovatron protocol card on CSC 6 ");
		else if (ret == RCSC_Ok)	
			{printf("\nCard found on CSC 6 "); i=55;}
		else
		{
			SetErrorTo1();
			CSC_ChangeRS485Address(0);
			printf("\nError looking for card on CSC 6: %04X",ret);
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}

		// same on the CSC 9
		CSC_ChangeRS485Address(9);
		ret = CSC_CardFound(tx, &ln);
		if (ret == RCSC_CardNotFound)	
			printf("\n no innovatron protocol card on CSC 9 ");
		else if (ret == RCSC_Ok)	
			{printf("\nCard found on CSC 9 "); i=55;}
		else
		{
			SetErrorTo1();
			CSC_ChangeRS485Address(0);
			printf("\nError looking for card on CSC 9: %04X",ret);
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}

	}
		// End of card detection 
		CSC_ChangeRS485Address(6);
		ret = CSC_CardStopSearch();
		if (ret != RCSC_Ok)	
		{
			SetErrorTo1();
			CSC_ChangeRS485Address(0);
			printf("\nStop SearchCard Error on CSC 6: %04X",ret);
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}
		printf(".");

		CSC_ChangeRS485Address(9);
		ret = CSC_CardStopSearch();
		if (ret != RCSC_Ok)	
		{
			SetErrorTo1();
			CSC_ChangeRS485Address(0);
			printf("\nStop SearchCard Error on CSC 9: %04X",ret);
			CSC_AntennaOFF();
			CSC_Close();
			return;
		}
		printf(".");

	CSC_ChangeRS485Address(0);
	return;
}

/******************************************************************/
void ISO14443_256ByteFrames(BYTE* tx)
/*****************************************************************
Test of Desfire Sam class with a Genxx

  INPUTS : tx : buffer containing the answer to CSC_SearchCardExt

  OUTPUTS : None

*****************************************************************/
{
	#define ISO_LC	248

	BYTE Buffer[512];
	BYTE Rx[512];
	DWORD LnRx;
	DWORD ret;
	DWORD LnCRC; // length without CRC, then with CRC after CSC_AddCRC 
	BYTE i;

	ret=CSC_EHP_PARAMS_EXT(1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0);	// No Select Appli
	if (ret != RCSC_Ok)	
	{
		Mess("\nSearchCardParam Error ",ret);
	}

	memset (Buffer,0,sizeof (Buffer));	// clear buffer

	Buffer[0]=0x80;
	Buffer[1]=0xFF;
	Buffer[2]=ISO_LC+6+4-255;
	Buffer[3]=0x01;
	Buffer[4]=0x22;
	Buffer[5]=ISO_LC+6;
	Buffer[7]=0x00;
	Buffer[8]=0xA4;
	Buffer[9]=0x04;
	Buffer[10]=0x00;
	Buffer[11]=0xF8;
	for (i=1;i<=ISO_LC;i++)
		Buffer[11+i]=i;
	Buffer[i]=0x00;

	LnCRC=i + 11 + 1 + 1;
	CSC_AddCRC (Buffer,&LnCRC);

	printf("\nSEND = %s\n\n",BinToString(Buffer,LnCRC));	
	
	ret = CSC_SendReceive (1000,Buffer,LnCRC,Rx,&LnRx);

	printf("\nRECEIVE = %s\n\n",BinToString(Rx,LnRx));	

}

void MifareULClassTest()
{
	BYTE Buffer[512];
	DWORD dwLnRx;
	DWORD ret;
	WORD wStatus;
	BYTE bStatus;
	BYTE bLnRead;
	BYTE	COM;
	sCARD_SearchExt search;
	DWORD	search_mask;
 	printf("\nMifare UL Class Test\n");
	
	ret = CSC_ResetSAMExt (1,0,2,&dwLnRx,Buffer);		// reset SAM to PPS FI/DI
	if (ret != RCSC_Ok)	
	{
		Mess("\nCSC_ResetSAMExt Error ",ret);
		return;
	}
	ret = CSC_SetSAMBaudratePPS( 1, Buffer[2], &wStatus);

	if ((ret != RCSC_Ok)	|| (wStatus != 0))
	{
		Mess("\nCSC_SetSAMBaudratePPS Error ",ret);
		printf("\nCSC_SetSAMBaudratePPS Status 0x%X",wStatus);
	}

	ret = MFUL_Identify (0,&bStatus);

	if (ret != RCSC_Ok)
	{
		Mess("\nMFUL_Identify Error ",ret);
		printf("\nMFUL_Identify 0x%X",bStatus);
	}
	printf("\nIdentify= %X\n",bStatus);	
	
	switch (bStatus)
	{
	case 0x21:	// MFULC
		printf("\nMifare ULC, re-detect it...\n");	
		search.ISOA = 1;
		search_mask = SEARCH_MASK_ISOA;
		ret = CSC_SearchCardExt(&search,search_mask,1,0x10,&COM,&dwLnRx,Buffer);
		if ((ret != RCSC_Ok) || (COM != 0x08))
			printf("\nCard not detected\n");	

		printf("\nAuthenticate...\n");	
		ret = MFULC_Authenticate (7,1,0,NULL,&bStatus, &wStatus);

 		if ((ret != RCSC_Ok)	|| (bStatus != 0x02) || (wStatus != 0x9000))
		{
			Mess("\nMFULC_Authenticate Error ",ret);
			printf("\nMFULC_Authenticate Status 0x%X SAMStatus 0x%X",bStatus,wStatus);
		}

		printf("\nRead data...");	
		ret = MFUL_Read (0x10,16,&bStatus,&bLnRead,Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFUL_Read Error ",ret);
			printf("\nMFUL_Read Status 0x%X",bStatus);
		}
		printf("\nRead data= %s\n\n",BinToString(Buffer,bLnRead));	

		printf("\nWrite key from SAM...\n");	
		ret = MFULC_WriteKeyFromSAM (7,1,0,NULL,&bStatus, &wStatus);

 		if ((ret != RCSC_Ok)	|| (bStatus != 0x02) || (wStatus != 0x9000))
		{
			Mess("\nMFUL_Write Error ",ret);
			printf("\nMFUL_Write Status 0x%X SAMStatus 0x%X",bStatus,wStatus);
		}
		printf("\nMifare ULC, re-detect it after key change...\n");	
		search.ISOA = 1;
		search_mask = SEARCH_MASK_ISOA;
		ret = CSC_SearchCardExt(&search,search_mask,1,0x10,&COM,&dwLnRx,Buffer);
		if ((ret != RCSC_Ok) || (COM != 0x08))
			printf("\nCard not detected\n");	

		printf("\nAuthenticate...\n");	
		ret = MFULC_Authenticate (7,1,0,NULL,&bStatus, &wStatus);

 		if ((ret != RCSC_Ok)	|| (bStatus != 0x02) || (wStatus != 0x9000))
		{
			Mess("\nMFULC_Authenticate Error ",ret);
			printf("\nMFULC_Authenticate Status 0x%X SAMStatus 0x%X",bStatus,wStatus);
		}
		break;

	case 0x20:	// MFUL
	case 0x22:	// MFUL EV1 MFU0UL11
	case 0x23:	// MFUL EV1 MFU0UL21
		if (bStatus == 0x20)
			printf("\nMifare UL\n");	
		else if (bStatus == 0x22)
			printf("\nMFUL EV1 MFU0UL11\n");	
		else if (bStatus == 0x23)
			printf("\nMFUL EV1 MFU0UL21\n");	

		printf("\nRead data...");	
		ret = MFUL_Read (0x10,16,&bStatus,&bLnRead,Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))	
		{
			Mess("\nMFUL_Read Error ",ret);
			printf("\nMFUL_Read Status 0x%X",bStatus);
		}
		printf("\nRead data= %s\n\n",BinToString(Buffer,bLnRead));	

		printf("\nWrite data...");	
		ret = MFUL_Write (0x10,16,"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10",
							&bStatus,&bLnRead,Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFUL_Write Error ",ret);
			printf("\nMFUL_Write Status 0x%X",bStatus);
		}
		printf("\nWritten data= %s\n\n",BinToString(Buffer,bLnRead));	

		printf("\nWrite data...");	
		ret = MFUL_Write (0x10,16,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
							&bStatus,&bLnRead,Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFUL_Write Error ",ret);
			printf("\nMFUL_Write Status 0x%X",bStatus);
		}
		printf("\nWritten data= %s\n\n",BinToString(Buffer,bLnRead));	

		printf("\nPassword authenticate...");	
		ret = MFULEV1_PasswordAuthenticate ("\x11\x22\x33\x44",&bStatus,Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_PasswordAuthenticate Error ",ret);
			printf("\nMFULEV1_PasswordAuthenticate Status 0x%X",bStatus);
		}
		printf("\nPACK= %s\n\n",BinToString(Buffer,2));	
		
		printf("\nCreate Diversified password and PACK...");	
		ret = MFULEV1_CreateDiversifiedPasswordandPACK (9,1,1,"\x11",&wStatus,Buffer,Buffer+4);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_CreateDiversifiedPasswordandPACK Error ",ret);
			printf("\nMFULEV1_CreateDiversifiedPasswordandPACK wStatus 0x%X",wStatus);
		}
		printf("\nPassword= %s \n",BinToString(Buffer,4));	
		printf("PACK= %s\n\n",BinToString(Buffer+4,2));	

		printf("\nRead counter...");	
		ret = MFULEV1_ReadCounter (1,&bStatus,(DWORD *)Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_ReadCounter Error ",ret);
			printf("\nMFULEV1_ReadCounter bStatus 0x%X",bStatus);
		}
		printf("\nCounter value= %u \n",*((DWORD *)Buffer));	

		printf("\nIncrement counter...");	
		ret = MFULEV1_IncrementCounter (1,2,&bStatus);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_IncrementCounter Error ",ret);
			printf("\nMFULEV1_IncrementCounter bStatus 0x%X",bStatus);
		}

		printf("\nRead counter...");	
		ret = MFULEV1_ReadCounter (1,&bStatus,(DWORD *)Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_ReadCounter Error ",ret);
			printf("\nMFULEV1_ReadCounter bStatus 0x%X",bStatus);
		}
		printf("\nCounter value= %u \n",*((DWORD *)Buffer));	

		printf("\nCheck tearing event...");	
		ret = MFULEV1_CheckTearingEvent (1,&bStatus,Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_ReadCounter Error ",ret);
			printf("\nMFULEV1_ReadCounter bStatus 0x%X",bStatus);
		}
		printf("\nValid flag= %02X \n",*Buffer);	

		printf("\nGet version...");	
		ret = MFULEV1_GetVersion (&bStatus,&bLnRead, Buffer);

 		if ((ret != RCSC_Ok) || (bStatus != 0x02))
		{
			Mess("\nMFULEV1_ReadCounter Error ",ret);
			printf("\nMFULEV1_ReadCounter bStatus 0x%X",bStatus);
		}
		printf("\nVersion= %s \n",BinToString(Buffer,bLnRead));	

		break;

	default:
		printf("\nMFUL not recongnized\n");

	}
}

void CalypsoRev3ModeTest()
{
	BYTE Buffer[512];
	DWORD ret;
 	printf("\nCalypso Set/Reset/Get Test\n");
	
 	printf("\nGet Calypso Rev 3 Mode\n");
	ret = CalypsoRev3_GetMode (Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nCalypsoRev3_GetMode Error ",ret);
		return;
	}
	printf ("Mode %d\n",*Buffer);

 	printf("\nSet Calypso Rev 3 Mode\n");
	ret = CalypsoRev3_SetMode (1);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nCalypsoRev3_SetMode Error ",ret);
		return;
	}
 	printf("\nGet Calypso Rev 3 Mode\n");
	ret = CalypsoRev3_GetMode (Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nCalypsoRev3_GetMode Error ",ret);
		return;
	}
	printf ("Mode %d\n",*Buffer);

	printf("\nReset Calypso Rev 3 Mode\n");
	ret = CalypsoRev3_SetMode (0);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nCalypsoRev3_SetMode Error ",ret);
		return;
	}

	printf("\nGet Calypso Rev 3 Mode\n");
	ret = CalypsoRev3_GetMode (Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nCalypsoRev3_GetMode Error ",ret);
		return;
	}
	printf ("Mode %d\n",*Buffer);
}

void EMVCoFuntionsTest()
{
	BYTE Buffer[512];
	DWORD ret;
	BYTE bLnRead;
	BYTE bStatus;
	BYTE Parameter[8];
	DWORD 	LnOut;

 	printf("\nEMVCo Functions Test\n");
	
	printf("\nUser interface: ready to read\n");
	ret = EMVCo_UserInterface (0x03,Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_UserInterface Error ",ret);
		return;
	}
	printf ("Status %d\n",*Buffer);

	printf("\nEMVCo_Contactless: RF field off\n");
	ret = EMVCo_Contactless (0x00,"\x00",&bStatus,&bLnRead,Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_UserInterface Error ",ret);
		return;
	}
	printf ("Status %d\n",bStatus);

	printf("\nEMVCo_Contactless: RF field reset\n");
	ret = EMVCo_Contactless (0x01,"\x00",&bStatus,&bLnRead,Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_UserInterface Error ",ret);
		return;
	}
	printf ("Status %d\n",bStatus);

	printf("\nEMVCo_Contactless: Polling / Anti-collision / Activation\n");
	Parameter[0]=16; // 16 polling loops
	ret = EMVCo_Contactless (0x02,Parameter,&bStatus,&bLnRead,Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_UserInterface Error ",ret);
		return;
	}
	printf ("Status %d\n",bStatus);

	if ((bStatus == 0x01) || (bStatus == 0x02))	// ISOA or ISOB detected
	{ 	// select application			   //    2    P    A     Y     .     S     Y     S     .     D     D     F    0    1
		ret=CSC_ISOCommand("\x00\xA4\x04\x00\x0E\x32\x50\x41\x59\x2E\x53\x59\x53\x2E\x44\x44\x46\x30\x31\x00",20, Buffer,&LnOut);

		if (ret == RCSC_Ok)
		{
			printf("\nUser interface: card read successfuly\n");
			ret = EMVCo_UserInterface (0x11,Buffer);		
			if (ret != RCSC_Ok)	
			{
				Mess("\nEMVCo_UserInterface Error ",ret);
				return;
			}
			printf ("Status %d\n",*Buffer);
		}
	}

	printf("\nEMVCo_Contactless: card removal\n");
	ret = EMVCo_Contactless (0x03, Parameter, &bStatus, &bLnRead,Buffer);	// card removal
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_Contactless Error ",ret);
		return;
	}
	printf ("Status %d\n",bStatus);


	printf("\nUser interface: ready to read\n");
	ret = EMVCo_UserInterface (0x03,Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_UserInterface Error ",ret);
		return;
	}
	printf ("Status %d\n",*Buffer);

	printf ("\nInsert a card, then press a key\n");
	_getch ();

	printf("\nEMVCo_Contactless: Polling / Anti-collision / Activation with other technologies\n");
	Parameter[0]=16; // 16 polling loops
	memcpy (&Parameter[1],"\x40\x00\x00\x00\x11",5); // add INNO & CTS512B
	ret = EMVCo_Contactless (0x06,Parameter,&bStatus,&bLnRead,Buffer);		
	if (ret != RCSC_Ok)	
	{
		Mess("\nEMVCo_UserInterface Error ",ret);
		return;
	}
	printf ("Status %d\n",bStatus);
}

/******************************************************************/
// Main function test
void test(void)
{
	unsigned char tx[256];
	DWORD ret,Choice;
	BYTE COM;
	BYTE	status;
	DWORD tm, ln;
	sCARD_SearchExt SearchStruct;
	DWORD search_mask;
	sCARD_SearchExt* Search=&SearchStruct;

	printf("Test the specifics library functions...\n");
/*---- Test the CSC_Version function -----------*/	
	ret=CSC_VersionDLL(tx);
	printf("returned version by the DLL = %04X\n",ret); 
	printf("returned string by the DLL = %s\n",tx);

	do{
	printf("\n-------------------------------------------------------"); 
	printf("\nTest ASK Coupleur : Waiting...  ");

	_flushall();
	// ensure that serial link is not reserved by a previous test
	CSC_Close();

	Error=0;

	printf("\n-------------------------------------------------------");
	printf("\n--------------------- MAIN MENU -----------------------\n");
	printf("\nWhich Test ?"); 
	printf("\n 0:Detect Card");
	printf("\n 1:CD97 Test With CD97 Class      (PIN code 30 30 30 30)");
	printf("\n 2:GTML Test With GTML Class      (PIN code 30 30 30 30)"); 
	printf("\n 3:CD97 Test With Generic Class   (PIN code 30 30 30 30)"); 
	printf("\n 4:GTML Test With Generic Class   (PIN code 30 30 30 30)"); 
	printf("\n 5:CT2000 Test With Generic Class (PIN code 30 30 30 30)");
	printf("\n 6:ISO 14443-B GTML2 Tests ");
	printf("\n 7:System Test Class"); 
	printf("\n 8:CTS Test Class"); 
	printf("\n 9:SAM D3-4 Certificat Test Class"); 
	printf("\n A:MIFARE Class (need a Gen3x5 coupler"); 
	printf("\n B:RS485 Classe CSC address 6 and 9");
	printf("\n C:CTS512B Test Class (present a CTS512B)");
	printf("\n D:Detect MV4000");
	printf("\n E:Detect MV5000");
	printf("\n F:CTx512x Test Class (menu following)");
	printf("\n G:SAM memory Test (SAM in slot 2)");
	printf("\n H:transparent commands test (menu following)");
	printf("\n I:MIFARE - SAM NXP Class");
	printf("\n J:MIFARE Plus Class");
	printf("\n K:SRx Class");
	printf("\n L:DESFIRE Class");
	printf("\n M:DESFIRE SAM Class");
	printf("\n N:ISO14443 256-byte frames");
	printf("\n O:Mifare UL Class");
	printf("\n P:Calaypso Rev3 Mode");
	printf("\n Q:EMVCo Functions");
	printf("\n x:to Exit"); 
	printf("\n-------------------------------------------------------\n"); 

	Choice=_getch();
	switch (Choice)
	{
	case '0':
		Search->CONT = 0;
		Search->ISOB = 2;
		Search->ISOA = 3;
		Search->TICK = 2;
		Search->INNO = 1;
		Search->MIFARE = 0;
		Search->MV4k = 0;
		Search->MV5k = 0;
		search_mask = SEARCH_MASK_ISOB + SEARCH_MASK_ISOA + SEARCH_MASK_TICK + SEARCH_MASK_INNO;
		break;

	case 'A' :	// Type ISO14443 A or MIFARE
	case 'a' :
	case 'I' :	// Type MIFARE - SAM NXP
	case 'i' :
	case 'J' :	// Type MIFARE PLUS
	case 'j' :
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=1;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=1;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_MIFARE;
	break;

	case 'L' :	// Type ISO14443 A or Type DESFIRE
	case 'l' :
	case 'M' :	// Type DESFIRE
	case 'm' :
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=1;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_ISOA;
	break;

	case 'N' :	// Type ISO14443 A & B
	case 'n' :
	Search->CONT=0;
	Search->ISOB=1;
	Search->ISOA=1;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_ISOA|SEARCH_MASK_ISOB;
	break;

	case '8' :	// Ticket
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=0;
	Search->TICK=1;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_TICK;
	break;

	case '6' :	// ISO14443 B
	Search->CONT=0;
	Search->ISOB=1;
	Search->ISOA=0;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_ISOB;
	break;
	

	case 'd' :
	case 'D' :
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=0;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=1;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_MV4K;
	break;

	case 'e' :
	case 'E' :
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=0;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=1;
	search_mask=SEARCH_MASK_MV5K;
	break;


	case '1' :	// Mode innovatron
	case '2' :
	case '3' :
	case '4' :
	case '5' :
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=0;
	Search->TICK=0;
	Search->INNO=1;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=SEARCH_MASK_INNO;
	break;

	case 'x':	
	case 'X':	tm=GetTimer(0);
				CSC_AntennaOFF();
				CSC_Close();
				return;

	default :
	Search->CONT=0;
	Search->ISOB=0;
	Search->ISOA=0;
	Search->TICK=0;
	Search->INNO=0;
	Search->MIFARE=0;
	Search->MV4k=0;
	Search->MV5k=0;
	search_mask=0x0000;
	break;
	
	}

	tm = GetTimer(0);
	if (_toupper(Choice) !='B') 
	{
		if (_toupper(Choice) !='P')
		{
			/*---- Test the CSC_SearchCardExt functions -----------*/	
			printf("\nInsert a Card and press a key???  ");
			_getch();
		}
		printf("Test the system coupleur functions...\n");
		/*---- Test the CSC_Open, CSC_Close & CSC_SearchCSC functions -----------*/	
		// Open com on PC serial port 1
		ret=CSC_Open("COM1");
		if(ret!=RCSC_Ok){
			Mess("Open CSC function fail. on serial port COM1 ",ret);
		}
		CSC_Close();

		// Search the ASK CSC on PC serial port
		ret=CSC_SearchCSC();
		if(ret!=RCSC_Ok){
			Mess("Search CSC function fail.",ret);
		}

		ret = CSC_WriteSAMNumber(1,&status);
		if ((ret != RCSC_Ok) || (status != 0x01))
		{
			Mess("Write SAM nb failed.",ret);	
		}


		/*---- Test the CSC_ResetCSC & CSC_VersionCSC functions -----------*/	
		// reset the ASK CSC
		ret=CSC_ResetCSC();
		if(ret==RCSC_Ok){
			ret=CSC_VersionCSC(tx);
			if (ret == RCSC_Ok)		printf("Reset [ %s ]\n",tx);
			else 					printf("Reset Warning Version ! [ %s ]\n",tx);
		}
		else{
			Mess("Reset CSC function fail.",ret);
			CSC_Close();
			//return;
		}

		if ((_toupper (Choice) != 'O') && (_toupper (Choice) != 'P')  && (_toupper (Choice) != 'Q'))
		{
			/*---- Test the CSC_ResetSAM functions -----------*/	
			if ( (Choice == 'L') || (Choice == 'l') || (Choice == 'm') || (Choice == 'M'))	// DF : Desfire -> Reset SAM type2
				CSC_SelectSAM(1,0x02);	
			else if ( (Choice == 'I') || (Choice == 'i') || (Choice == 'J') || (Choice == 'j') )	// DF : MFP, Mifare SAM NXP-> Reset SAM type1
				CSC_SelectSAM(1,0x01);
			else
				CSC_SelectSAM(1,0x00);

			ret=CSC_ResetSAM(tx,&ln);
			if (ret != RCSC_Ok)		Mess("\nSAM not present.",ret);
			else		// if a SAM is found -> display the ATR card
			{
				printf("SAM ATR=%s",BinToString(tx,ln));
				KVCSAM = 0;
				/* To do before any Electronic Purse Operation : */
				/* first we need to know if the SAM is a S1 or anything else */
				/* SAM S1 answers 3B 6F 0000 80 5A 06 80 D2 08 30 UV SN SN SN SN 82 SW1 SW2 */
				/* D2 is the Application code for SAM S1*/
				if ((tx[8] == 0xD2) || (tx[8] == 0xD4) ) // SAM S1
				{
					printf(" SAMS1 ");
					/* Le KVC est donné par la commande Read Data suivante : 94.BE.00.A0.30 */
					/* qui rend les données 29 octets de data + P2 + NS NS NS NS + KIF + KVC + ALG + $800000*/
				}
				else //( MiniSAM or SAM S1R )
				if ((tx[8] == 0xD1) || (tx[8] == 0xD3) ) // SAM S1
				{
					printf(" SAMS1r ");
					KVCSAM = 0x02;
					/* le KVC du PME est donné par la commande Get Key*/
				}
				else
				{
					printf(" Other SAM ");
					KVCSAM = 0x02;
					/* le KVC du PME est donné par la commande Get Key*/
				}

				if ((_toupper (Choice) != 'L') && (_toupper (Choice) != 'M') &&	// SAM AV2
					(_toupper (Choice) != 'O') && (_toupper (Choice) != 'I') &&
					(_toupper (Choice) != 'J'))
				{
					// function SEND ISO TO SAM GIVE RANDOM
					ret=CSC_ISOCommandSAM("\x94\x86\x00\x00\x08,\0\1\2\3\4\5\6\7",13,tx,&ln);
					// function SEND ISO TO SAM READ DATA
					ret=CSC_ISOCommandSAM("\x94\xBE\0\xA0\x30",5,tx,&ln);
					ret=CSC_ISOCommandSAM("\x94\xBE\0\x81\x18",5,tx,&ln);
					if(ret!=RCSC_Ok){
						printf("\nError ISOCommandSAM. code: %d",ret);
						CSC_AntennaOFF();
						CSC_Close();
						return;
					}
					if (KVCSAM == 0)
					{
						printf("KVC=%02x",tx[0x24]);
						KVCSAM = tx[0x24];
					}
				}
			}
			CSC_AntennaOFF();

			if( (Choice == 'L') || (Choice == 'l') || (Choice == 'M') || (Choice == 'm'))	// DF : Enter Hunt Phase no Select Appli
			{
				ret=CSC_EHP_PARAMS_EXT(1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0);	// MaxCard = 1, Req = 1
				if (ret != RCSC_Ok)	
				{
					Mess("\nSearchCardParam Error ",ret);
				}
			}

			ret=CSC_SearchCardExt(Search,search_mask,0x01,100,&COM,&ln,tx);
			if (ret != RCSC_Ok)	
			{
				Mess("\nSearchCard Error ",ret);
			}
			else
			{
				if(COM==0x6F)	printf("\nSearch Card Time Out\n");
				else			printf("\nCARD ATR = %s\n",BinToString(tx,ln));
			}
		}
	} // != 'O'
	switch(Choice)
	{
		case '1':	tm=GetTimer(0);
					CD97ClassTest();
				 	printf("\nCD97 Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '2':	tm=GetTimer(0);
					GtmlClassTest();
					printf("\nGtml Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '3':	tm=GetTimer(0);
					GenClassTestCD97();
				 	printf("\nGeneric Class Test (CD97) Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '4':	tm=GetTimer(0);
					GenClassTestGTML();
				 	printf("\nGeneric Class Test (GTML) Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '5':	tm=GetTimer(0);
					GenClassTestCT2000();
				 	printf("\nGeneric Class Test (CT2000) Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '6':	tm=GetTimer(0);
					GenClassTestISO14443B();
				 	printf("\nGeneric Class Test (CT2000 TRANSCARTE) Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '7':	tm=GetTimer(0);
					SystemClassTest();
				 	printf("\nSystem Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '8':	tm=GetTimer(0);
					CTSClassTest();
				 	printf("\nCTS Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case '9':	tm=GetTimer(0);
					CertificatClassTest();
				 	printf("\nCertificat Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'a':	
		case 'A':	tm=GetTimer(0);
					MifareClassTest(tx);
				 	printf("\nMifare Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'b':	
		case 'B':	tm=GetTimer(0);
					RS485Tests();
				 	printf("\nRS485 Tests Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'c':
		case 'C':	tm=GetTimer(0);
					CTS512BClassTest();
				 	printf("\nCTM Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'd' :
		case 'D' :	if (COM==0x0A)
					{
						printf("\ndetection of MV4000 OK");
					}
					else
					{
						printf("\nMV4000 detection error");
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
					}
					break;
		case 'e' :
		case 'E' :	if (COM==0x0B)
					{
						printf("\ndetection of MV5000 OK");
					}
					else
					{
						printf("\nMV5000 detection error");
						SetErrorTo1();
						CSC_AntennaOFF();
						CSC_Close();
					}
					break;
		case 'f':
		case 'F':	tm=GetTimer(0);
					CTx512xClassTest();
				 	printf("\nCTx512x Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'g':
		case 'G':	tm=GetTimer(0);
					SAMmemoryTest();
				 	printf("\nSAM memory Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'h':
		case 'H':	tm=GetTimer(0);
					transparentCommandsTest();
				 	printf("\nTransparent commands test finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'i':
		case 'I':	tm=GetTimer(0);
					MifareSAMNXPClassTest(tx);
				 	printf("\nMifare - SAM NXP Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'j':
		case 'J':	tm=GetTimer(0);
					MFPSL3ClassTest(tx);
				 	printf("\nMifare Plus SL3 Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'k':
		case 'K':	tm=GetTimer(0);
					SRxClassTest(tx);
				 	printf("\nSRx Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'l':
		case 'L':	tm=GetTimer(0);
					DesfireClassTest(tx);
				 	printf("\nDesfire Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'm':
		case 'M':	tm=GetTimer(0);
					DesfireSamClassTest(tx);
				 	printf("\nDesfire Sam Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'N':
		case 'n':	tm=GetTimer(0);
					ISO14443_256ByteFrames(tx);
				 	printf("\nISO14443 256-byte frames Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'O':
		case 'o':	tm=GetTimer(0);
					MifareULClassTest();
				 	printf("\nMifare UL Class Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'P':
		case 'p':	tm=GetTimer(0);
					CalypsoRev3ModeTest();
				 	printf("\nCalypso Rev3 Mode Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		case 'Q':
		case 'q':	tm=GetTimer(0);
					EMVCoFuntionsTest();
				 	printf("\nEMVCo Funtions Test Finished. ( Time = %d ms )\n",GetTimer(tm));
					break;
		default :	
					break;
	}
	
	if (Error == 0) 
	{
		// function ANTENNA OFF
		CSC_AntennaOFF();

		// end of the test
		printf("\nTest Finish successfully( Time = %d ms )\n",GetTimer(tm));
	}

	CSC_Close();
	_getch();
	} while(1);

}

// ****************************
// main function 
void main(void)
{
//DWORD ret;
	// Search the ASK CSC on PC serial port
//	ret=CSC_SearchCSC();
//	if(ret!=RCSC_Ok){
//		Mess("Open CSC function fail.",ret); 
//		return;
//	}

	fopen_s(&trace,"trace.txt","w+");
	test();
	fclose (trace);
	printf("Press a Key.\n");
	_getch();
}


