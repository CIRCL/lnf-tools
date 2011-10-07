/*
 *  Extended in 2011 by Gerard Wagener - CIRCL - Smile g.i.e.
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 *  $Author: haag $
 *
 *  $Id: nfreader.c 48 2010-01-02 08:06:27Z haag $
 *
 *  $LastChangedRevision: 48 $
 *
 *
 */

/*
 * nfreader is sample code for reading nfdump binary files.
 * It accepts the standard nfdump file select options -r, -M and -R
 * Therefore it allows you to loop over multiple files and process the netflow record.
 *
 * Insert your code in the process_data function after the call to ExpandRecord
 * To build the binary: first compile nfdump as usual.
 * Then compile nfreader:
 *
 * make nfreader
 *
 * This compiles this code and links the required nfdump files
 * If you do it by hand:
 *
 * gcc -c nfreader.c
 * gcc -o nfreader nfreader.o nffile.o flist.o util.o minilzo.o nfx.o libhiredis.a /usr/lib/libglib-2.0.a
 *
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "util.h"
#include "flist.h"
#include "hiredis.h"
#include "glib.h"
#include <sys/time.h>
#include <sys/resource.h>

#define BUFFSIZE 1048576
/* Maximal number of errors that are tolerated until the program aborts */
#define MAXERRORCNT 10
#define MAXSOFTLIM 536870912000
#define MAXHARDLIM 644245094400
struct tuple{
    unsigned long long l1;
    unsigned long long l2;
} typedef TUPLE;


#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

// module limited globals
extension_map_list_t extension_map_list;

/* Function Prototypes */
static void usage(char *name);

static void index_record(void* record, char *s );
void store_address(char* addr);

static void process_data(void);

/* Use global variables to avoid parameter passing */
char *g_filename;
unsigned long long g_index;
redisContext* g_rctx;
redisReply *reply;

int rbidx;
char dontcare = 0;
GHashTable* ght;
char* redis_server_address = "127.0.0.1";
int redis_server_port = 6379;
int cacheenable = 1;
int error_counter = 0;

/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
        printf("Create index in redis describing the relationship file  - IPaddress\n");
		printf("\nusage %s -r [options] \n", name);
		printf("\t-r\t\tread input from file\n");
        printf("\t[-s]\t\tspecify the redis server name or IP address\n");
        printf("\t[-p]\t\tspecify the redis server port\n");
        printf("\t[-c]\t\tDisable local cache. The local cache needs 500MB of memory.\n");
        printf("\nDESCRIPTION\n\n");
        printf("In redis keys are created such as n4:10.0.0.1. Each key has a set as value.\n");
        printf("An IP address always starts with n followed by 4 (IPv4) or by 6 (IPv6). This\n");
        printf("prefix is followed by the string representation of the IP address. The\n");
        printf("associated set contains numbers such as 1,2,3... where each number is the\n");
        printf("index of a file name. A set can be queried in redis with the SMEMBERS command.\n");
        printf("The associated filename can be queried with the command GET d:x where x is the\n");
        printf("index (number) in the queried set.\n");
        printf("\n\nAUTHORS\n\n");
        printf("Originally written by Peter Haag as example and extended with the indexing \n");
        printf("features by Gerard Wagener - CIRCL\n");
        printf("gerard dot wagener at circl.lu\n");
} /* usage */



static void process_data(void) {
data_block_header_t block_header;
master_record_t		master_record;
common_record_t     *flow_record, *in_buff;
uint32_t	buffer_size;
int 		i, rfd, done, ret;
char		*string;
#ifdef COMPAT15
int	v1_map_done = 0;
#endif

	// Get the first file handle
	rfd = GetNextFile(0, 0, 0, NULL);
	if ( rfd < 0 ) {
		if ( rfd == FILE_ERROR )
			perror("Can't open input file for reading");
		return;
	}

	// allocate buffer suitable for netflow version
	buffer_size = BUFFSIZE;
	in_buff = (common_record_t *) malloc(buffer_size);

	if ( !in_buff ) {
		perror("Memory allocation error");
		close(rfd);
		return;
	}

	done = 0;
	while ( !done ) {
		// get next data block from file
		ret = ReadBlock(rfd, &block_header, (void *)in_buff, &string);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT )
					fprintf(stderr, "Skip corrupt data file '%s': '%s'\n",GetCurrentFilename(), string);
				else
					fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF:
				rfd = GetNextFile(rfd, 0, 0, NULL);
				if ( rfd < 0 ) {
					if ( rfd == NF_ERROR )
						fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );

					// rfd == EMPTY_LIST
					done = 1;
				} // else continue with next file
				continue;

				break; // not really needed
		}

#ifdef COMPAT15
		if ( block_header.id == DATA_BLOCK_TYPE_1 ) {
			common_record_v1_t *v1_record = (common_record_v1_t *)in_buff;
			// create an extension map for v1 blocks
			if ( v1_map_done == 0 ) {
				extension_map_t *map = malloc(sizeof(extension_map_t) + 2 * sizeof(uint16_t) );
				if ( ! map ) {
					perror("Memory allocation error");
					exit(255);
				}
				map->type 	= ExtensionMapType;
				map->size 	= sizeof(extension_map_t) + 2 * sizeof(uint16_t);
				map->map_id = 0;
				map->ex_id[0]  = EX_IO_SNMP_2;
				map->ex_id[1]  = EX_AS_2;
				map->ex_id[2]  = 0;

				Insert_Extension_Map(&extension_map_list, map);

				v1_map_done = 1;
			}

			// convert the records to v2
			for ( i=0; i < block_header.NumRecords; i++ ) {
				common_record_t *v2_record = (common_record_t *)v1_record;
				Convert_v1_to_v2((void *)v1_record);
				// now we have a v2 record -> use size of v2_record->size
				v1_record = (common_record_v1_t *)((pointer_addr_t)v1_record + v2_record->size);
			}
			block_header.id = DATA_BLOCK_TYPE_2;
		}
#endif

		if ( block_header.id != DATA_BLOCK_TYPE_2 ) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", block_header.id);
			continue;
		}

		flow_record = in_buff;
		for ( i=0; i < block_header.NumRecords; i++ ) {
			char        string[1024];

			if ( flow_record->type == CommonRecordType ) {
				uint32_t map_id = flow_record->ext_map;
				if ( extension_map_list.slot[map_id] == NULL ) {
					snprintf(string, 1024, "Corrupt data file! No such extension map id: %u. Skip record", flow_record->ext_map );
					string[1023] = '\0';
				} else {
					ExpandRecord_v2( flow_record, extension_map_list.slot[flow_record->ext_map], &master_record);

					// update number of flows matching a given map
					extension_map_list.slot[map_id]->ref_count++;

                    index_record(&master_record, string);
				}

			} else if ( flow_record->type == ExtensionMapType ) {
				extension_map_t *map = (extension_map_t *)flow_record;

				if ( Insert_Extension_Map(&extension_map_list, map) ) {
					 // flush new map
				} // else map already known and flushed

			} else {
				fprintf(stderr, "Skip unknown record type %i\n", flow_record->type);
			}

			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);

		} // for all records

	} // while

	if ( rfd > 0 )
		close(rfd);

	free((void *)in_buff);

	PackExtensionMapList(&extension_map_list);

} // End of process_data

void connect_to_redisServer(void)
{
   struct timeval timeout = { 1, 500000 }; // 1.5 seconds
   g_rctx = redisConnectWithTimeout(redis_server_address, redis_server_port, timeout);

    if (g_rctx->err) {
        printf("Connection error: %s\n", g_rctx->errstr);
        exit(1);
    }
}


/*
 * Checks if the filename is already indexed.
 * @returns -1 if not index
 * @returns > 0 the index of the filename
 */

int check_filename_in_redis(char* filename)
{
    int val;
    val = -1;
    reply = redisCommand(g_rctx,"GET f:%s", filename);
    if (reply){
        if (reply->type == REDIS_REPLY_STRING){
            val = atoi(reply->str);
            freeReplyObject(reply);
        }
    }
    return val;
}

/*FIXME NULL seems not to be returned on errors and errstr is not set? */

void set_file_indexes(void)
{
    int idx;

    idx=check_filename_in_redis(g_filename);
    if (idx > 0)
        return;
    /* Get the next index value */
    reply = redisCommand(g_rctx,"INCR c:fid");
    if (!reply)
        goto error;
    g_index = reply->integer;
    freeReplyObject(reply);

    /* Set the file name index */
    reply = redisCommand(g_rctx,"SET f:%s %d", g_filename, g_index);
    if (!reply)
        goto error;
    freeReplyObject(reply);

    /* Put the reverse index */
    reply = redisCommand(g_rctx, "SET d:%d %s", g_index,g_filename);
    if (!reply)
        goto error;
    freeReplyObject(reply);

    return;

error:
    printf("Connection error: %s\n", g_rctx->errstr);
    exit(1);
}


/*
 * An address is composed of 128 including IPv4 and IPv6
 * Most of the traffic is IPv4 resulting that l1 is almost always 0.
 * Therefore, the l2 is returned to avoid linear scanning
 */
guint addrhash (gconstpointer key)
{
    TUPLE* t;
    t = (TUPLE*)key;
    guint out;
    out = (guint)t->l2;
    return out;
}



gboolean addreq(gconstpointer a, gconstpointer b)
{
    TUPLE *src;
    TUPLE *dst;
    src = (TUPLE*) a;
    dst = (TUPLE*) b;
    if ((src->l1 == dst->l1) && (src->l2 == dst->l2)){
        return TRUE;
    }
    return FALSE;

}


inline int isInHashTable(TUPLE* key)
{
    if (g_hash_table_lookup(ght,key))
        return 1;
    return 0;
}


/*
 * Put address in a local hash table in order to avoid redundant redis queries.
 * On errors the addresses are not enqueued locally
 */
inline void enqueue(unsigned long long l1, unsigned long long l2)
{
    TUPLE* addr;
    if (!cacheenable)
        return;
    addr = malloc(sizeof(TUPLE));
    if (addr){
        addr->l1 = l1;
        addr->l2 = l2;
        g_hash_table_insert(ght,addr,&dontcare);
        /* A char that is not used is used as value in the hash table */
    }
    /* If there is no memory it is simply not enqueued */
}

/*
 * Check the local hash for an address encoded by l1 and l2.
 * @Returns 0 if it is in the local cache
 * @Returns 1 if it is in the local cache
 */

inline int checkqueue(unsigned long long l1, unsigned long long l2)
{
    TUPLE *addr;
    if (!cacheenable)
        return 1;
    addr = malloc(sizeof(TUPLE));
    if (addr){
        addr->l1 = l1;
        addr->l2 = l2;
        if (isInHashTable(addr)){
            free(addr);
            return 0;
        }
    }
    /* FIXME Yep. The tuples in the hashtable are not freed except when the
     *       at the end of the processing where the process is cleaned up by
     *       the kernel
     */

    /* By default it is not found even if there is an error */
    return 1;
}

void store_address(char* addr)
{
    reply = redisCommand(g_rctx,"SADD n%s %d", addr, g_index);
   // printf("ADDR:%s\n",addr);
    if (reply){
          freeReplyObject(reply);
    }else{
        /* TODO syslog IP address and filename that could not indexed
         *      Take care to not overwhelm the system (i.e. check and
         *      compare error code)
         */
    fprintf(stderr,"Cannot store address: %s\n",addr);
    error_counter++;
        if (error_counter > MAXERRORCNT){
            fprintf(stderr,"Maximal error count reached, abort processing %s\n",
                    g_filename);
            exit(1);
        }
    }
}

/*
 * Addresses are stored with their human readable representation
 * in order to avoid parsing errors. An address starts with a
 * nx:yyy
 * x is either 4 or 6 (ipv4 or Ipv6)
 * y is the string representation of the address
 */

static void index_record(void* record, char *s )
{
    master_record_t *r = (master_record_t *)record;
    char srcaddr[128];
    char dstaddr[128];
    char buf[128];
    unsigned long long int sl1;
    unsigned long long int sl2;
    unsigned long long int dl1;
    unsigned long long int dl2;

    if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
        r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
        r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
        r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
        r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);

        inet_ntop(AF_INET6, r->v6.srcaddr, buf, sizeof(buf));
        snprintf((char*) &srcaddr, 128, "6:%s",buf);

        inet_ntop(AF_INET6, r->v6.dstaddr, buf, sizeof(buf));
        snprintf((char*) &dstaddr, 128, "6:%s",buf);

        sl1 = r->v6.srcaddr[0];
        sl2 = r->v6.srcaddr[1];
        dl1 = r->v6.dstaddr[0];
        dl2 = r->v6.dstaddr[1];

    } else { //IPv4
        r->v4.srcaddr = htonl(r->v4.srcaddr);
        r->v4.dstaddr = htonl(r->v4.dstaddr);

        inet_ntop(AF_INET, &r->v4.srcaddr, buf, sizeof(buf));
        snprintf((char*) &srcaddr, 128, "4:%s",buf);

        inet_ntop(AF_INET, &r->v4.dstaddr, buf, sizeof(buf));
        snprintf((char*) &dstaddr, 128, "4:%s",buf);

        sl1 = 0;
        sl2 = r->v4.srcaddr;
        dl1 = 0;
        dl2 = r->v4.dstaddr;
    }

    /* Store address in redis if needed */
    if (checkqueue(sl1,sl2))
        store_address(srcaddr);
    enqueue(sl1,sl2);
    if (checkqueue(dl1,dl2))
        store_address(dstaddr);
    enqueue(dl1,dl2);
}/* index record */


int main( int argc, char **argv ) {
char 		*rfile;
int			c;
struct rlimit rlim;

/* Limit the memory consumption of this process
 *  - soft limit 500 MB
 *  - hard limit 600 MB
 * If the limit is reached ENOMEM is returned and the throtteling mechanism
 * activated resulting in a program abortion
 */
rlim.rlim_cur = MAXSOFTLIM;
rlim.rlim_max = MAXHARDLIM;

if (setrlimit(RLIMIT_AS, &rlim) < 0){
    fprintf(stderr, "Resource limitation failed, abort %s\n",
            strerror(errno));
    exit(1);
}


	rfile =  NULL;
	while ((c = getopt(argc, argv, "p:hr:s:c")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 's':
                redis_server_address = optarg;
                break;
			case 'r':
				rfile = optarg;
				break;
			case 'p':
                redis_server_port = atoi(optarg);
			    break;
            case 'c':
                cacheenable=0;
                break;
            default:
				usage(argv[0]);
				exit(0);
		}
	}

    if (!rfile){
        fprintf(stderr, "Error: no nfcapd file was specified\n");
        usage(argv[0]);
        exit(1);
    }


    ght = g_hash_table_new(addrhash, addreq);
    /* Make filename global to accessing in the indexing function */
    g_filename = rfile;
    /* Connect to redis server  and set file indexes*/
    connect_to_redisServer();
    set_file_indexes();

	InitExtensionMaps(&extension_map_list);

	SetupInputFileSequence(NULL, rfile, NULL);

	process_data();


	return 0;
}
