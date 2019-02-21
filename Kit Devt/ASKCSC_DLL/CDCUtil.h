// CDCUtil.h
// 
//
#include "csc_def.h"    // CSC definition file
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL WINAPI InternalUsePortNameIsPresent(LPSTR ComName, BOOL AskForAll);
BOOL WINAPI CDCUtilPortNameIsPresent(LPSTR ComName);
BOOL WINAPI CDCUtilPortIsCDC(LPSTR ComName);
BOOL WINAPI CDCUtilRecoverCDCPort (LPSTR ComName,DWORD dwDisconnectTimeout, DWORD dwReconnectTimeout);


#ifdef __cplusplus
}
#endif

