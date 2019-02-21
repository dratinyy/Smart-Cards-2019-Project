/*++

Copyright (c) 2004  ABC-Independants

ABC-Independants
3, rue Maurras
13016 Marseille FRANCE
Tel:+33 (0)495061217 Gsm:+33(0)663692723
http://www.abc-independants.com
mailto:h.abel@abc-independants.com

Module Name:

    Esc.h

Abstract:

    Smartcard Escape codes

Revision History:

--*/

#ifndef __ESC_H__
#define __ESC_H__


// Define:
// Specific Smartcard vendor IOCTL codes are in the 2048-4095 range:
//

// !! Reserved !!

//   - IOCTL_SMARTCARD_VENDOR_GET_ATTRIBUTE defines a Vendor specific IOCTL  
//      Reader to gets vendor attributes.
#define IOCTL_SMARTCARD_VENDOR_GET_ATTRIBUTE	SCARD_CTL_CODE(2048)

//   - IOCTL_SMARTCARD_VENDOR_SET_ATTRIBUTE defines a Vendor specific IOCTL 
//      Reader to sets vendor attributes.
#define IOCTL_SMARTCARD_VENDOR_SET_ATTRIBUTE	SCARD_CTL_CODE(2049)

// !! Reserved !!


//   - IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE defines a Vendor IOCTL Raw Exchange
//      Reader to exchange data with the reader without control of the driver.
//
//	 Parameters:
//
//	 (InBuffer,  InBufferSize)  describe the request to be send. 
//	 (OutBuffer, OutBufferSize) provide the storage for the coupler answer.
//   BytesReturned gives the number of bytes received from the coupler. 
#define IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE		SCARD_CTL_CODE(2050)


//   - IOCTL_SMARTCARD_VENDOR_SET_TIMEOUT
//      Sets the command timeout (in milliseconds). This parameter must be 
//		greater than RxTimeout (i.e. see Driver Registry). If it is not
//		the case, the command timeout is set to the value of RxTimeout
//		added with max(10 ms, FTDILatencyTimer).
//
//	 Parameters:
//
//	 (InBuffer,  InBufferSize)  describe the polling period (LONG value).
//	 (OutBuffer, OutBufferSize) not used.
//   BytesReturned not used. 
#define IOCTL_SMARTCARD_VENDOR_SET_TIMEOUT		SCARD_CTL_CODE(2051)

//   - IOCTL_SMARTCARD_VENDOR_CONTROL_POLLING
//      Sets the smartcard polling period (in milliseconds). This  
//		parameter must be in the 0-10000ms range. If it is not
//		the case, it is set to the default value (200 ms). If it is
//		0, the polling is stopped.
//
//	 Parameters:
//
//	 (InBuffer,  InBufferSize)  describe the timeout (LONG value).
//	 (OutBuffer, OutBufferSize) not used.
//   BytesReturned not used. 
#define IOCTL_SMARTCARD_VENDOR_CONTROL_POLLING  SCARD_CTL_CODE(2052)

//   - IOCTL_SMARTCARD_VENDOR_SET_LED_MODE
//      Sets the coupler LED mode:
//		  0 -> Normal Mode (I/O Transfert, Power On, Card Presence),
//		  1 -> Alternate Mode (Power On, Card Presence),
//		  2 -> Only Power On LED,
//		> 3 -> No signalization.
//
//	 Parameters:
//
//	 (InBuffer,  InBufferSize)  describe the LED mode (ULONG value).
//	 (OutBuffer, OutBufferSize) not used.
//   BytesReturned not used. 
#define IOCTL_SMARTCARD_VENDOR_SET_LED_MODE		SCARD_CTL_CODE(2053)

#define IOCTL_SMARTCARD_VENDOR_ENABLE_CRC		SCARD_CTL_CODE(2054)

#define IOCTL_SMARTCARD_VENDOR_SET_FTDI_LATENCY_TIMER	SCARD_CTL_CODE(2055)

#endif  //__ESC_H__


