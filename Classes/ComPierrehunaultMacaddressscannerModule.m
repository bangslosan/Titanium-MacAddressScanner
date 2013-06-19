/**
 * Your Copyright Here
 *
 * Appcelerator Titanium is Copyright (c) 2009-2010 by Appcelerator, Inc.
 * and licensed under the Apache Public License (version 2)
 */
#import "ComPierrehunaultMacaddressscannerModule.h"
#import "TiBase.h"
#import "TiHost.h"
#import "TiUtils.h"

@implementation ComPierrehunaultMacaddressscannerModule

#pragma mark Internal

// this is generated for your module, please do not change it
-(id)moduleGUID
{
	return @"098d30a9-5348-47d9-b573-37aa846e7dcc";
}

// this is generated for your module, please do not change it
-(NSString*)moduleId
{
	return @"com.pierrehunault.macaddressscanner";
}

#pragma mark Lifecycle

-(void)startup
{
	// this method is called when the module is first loaded
	// you *must* call the superclass
	[super startup];
	
	NSLog(@"[INFO] %@ loaded",self);
}

-(void)shutdown:(id)sender
{
	// this method is called when the module is being unloaded
	// typically this is during shutdown. make sure you don't do too
	// much processing here or the app will be quit forceably
	
	// you *must* call the superclass
	[super shutdown:sender];
}

#pragma mark Cleanup 

-(void)dealloc
{
	// release any resources that have been retained by the module
	[super dealloc];
}

#pragma mark Internal Memory Management

-(void)didReceiveMemoryWarning:(NSNotification*)notification
{
	// optionally release any resources that can be dynamically
	// reloaded once memory is available - such as caches
	[super didReceiveMemoryWarning:notification];
}

#pragma Public APIs
-(id)getMacAddresses:(id)args
{
	return [self ip2mac];
}

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include "if_types.h"
#include "route.h"
#include "if_ether.h"
#include <netinet/in.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>

#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// http://stackoverflow.com/questions/10395041/getting-arp-table-on-iphone-ipad
// http://stackoverflow.com/questions/11245280/implicit-declaration-of-function-ether-ntoa-is-invalid-in-c99
// http://stackoverflow.com/questions/2189200/get-router-mac-without-system-call-for-arp-in-objective-c
// http://stackoverflow.com/questions/2189200/get-router-mac-without-system-call-for-arp-in-objective-c
// http://stackoverflow.com/questions/2189200/get-router-mac-without-system-call-for-arp-in-objective-c
- (NSMutableArray*)ip2mac
{
    NSMutableArray *stringArray = [[NSMutableArray alloc] init];
    
    size_t needed;
    char *buf, *next;
    
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    
    int mib[6];
    
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;
    
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &needed, NULL, 0) < 0)
        err(1, "route-sysctl-estimate");
    
    if ((buf = (char*)malloc(needed)) == NULL)
        err(1, "malloc");
    
    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), buf, &needed, NULL, 0) < 0)
        err(1, "retrieval of routing table");
    
    for (next = buf; next < buf + needed; next += rtm->rtm_msglen) {
        
        rtm = (struct rt_msghdr *)next;
        sin = (struct sockaddr_inarp *)(rtm + 1);
        sdl = (struct sockaddr_dl *)(sin + 1);
        
        u_char *cp = (u_char*)LLADDR(sdl);
        
        NSString *mac_address = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]];
        if(![mac_address isEqualToString:@"00:00:00:00:00:00"] && ![mac_address isEqualToString:@"FF:FF:FF:FF:FF:FF"]){
            [stringArray addObject:mac_address];
        }
    }
    
    free(buf);
    return stringArray;
}

@end
