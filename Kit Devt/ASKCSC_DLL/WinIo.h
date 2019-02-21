#ifndef WINIO_H
#define WINIO_H

#undef LIBRARY_LINK


#ifdef LIBRARY_LINK
	#ifdef WINIO_DLL
		#define WINIO_API _declspec(dllexport)
	#else
		#define WINIO_API _declspec(dllimport)
	#endif

	WINIO_API BOOL _stdcall InitializeWinIo();
	WINIO_API void _stdcall ShutdownWinIo();
	WINIO_API BOOL _stdcall GetPortVal(WORD wPortAddr, PDWORD pdwPortVal, BYTE bSize);
	WINIO_API BOOL _stdcall SetPortVal(WORD wPortAddr, DWORD dwPortVal, BYTE bSize);
#else
	BOOL  (_stdcall *InitializeWinIo)();
	void  (_stdcall *ShutdownWinIo)();
	BOOL  (_stdcall *GetPortVal)(WORD wPortAddr, PDWORD pdwPortVal, BYTE bSize);
	BOOL  (_stdcall *SetPortVal)(WORD wPortAddr, DWORD dwPortVal, BYTE bSize);
#endif

extern BOOL IsNT;
extern HANDLE hDriver;
extern BOOL IsWinIoInitialized;

BOOL _stdcall StartWinIoDriver();
BOOL _stdcall StopWinIoDriver();

#endif
