// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>



// TODO: reference additional headers your program requires here


// Structures required to use functions in ICMP.DLL

typedef struct {
    unsigned char Ttl;                         // Time To Live
    unsigned char Tos;                         // Type Of Service
    unsigned char Flags;                       // IP header flags
    unsigned char OptionsSize;                 // Size in bytes of options data
    unsigned char *OptionsData;                // Pointer to options data
} IP_OPTION_INFORMATION, * PIP_OPTION_INFORMATION;



