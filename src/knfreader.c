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
#include <libgen.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "util.h"
#include "flist.h"
#include <kclangc.h>
#include "glib.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <syslog.h>
#define BUFFSIZE 1048576
/* Maximal number of errors that are tolerated until the program aborts */
#define MAXERRORCNT 10
#define MAXSOFTLIM 536870912000
#define MAXHARDLIM 644245094400

/* Error codes */
#define SUCCESS          0
#define ERROR_CONNECTION 1
#define ERROR_FILE_INDEX 2
#define ERROR_ADDRESS    3
#define ERROR_PID        4
#define ERROR_MEMORY     5
#define ERROR_RLIMIT     6
#define ERROR_PARAMETER  7

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
void cleanup(int exitcode);
static void index_record(void* record, char *s );
void store_address(char* addr);

static void process_data(void);

/* Use global variables to avoid parameter passing */
char *g_filename;
char gidx_buf[128];

int rbidx;
char dontcare = 0;
GHashTable* ght;
int cacheenable = 1;
int error_counter = 0;
char *database = NULL;
char* pidfile="/var/run/knfreader.pid";
KCDB* kdb;
/* Functions */

#include "nffile_inline.c"

static void usage(char *name) {
        printf("Create index in a Kyoto Cabinet database describing the relationship\nfile  - IPaddress\n");
		printf("\nusage %s -r [options] \n", name);
		printf("\t-r\t\tread input from file\n");
        printf("\t[-c]\t\tDisable local cache. The local cache needs 500MB of \n\t\t\tmemory.\n");
        printf("\t-d <db>       Specify the database filename where the keys are stored \n");
        printf("\t[-p <file>]   Specify the filename where the pid is stored\n");
        printf("\nDESCRIPTION\n\n");
        printf("In a database keys are created such as n4:10.0.0.1. Each key has a string \nas value.");
        printf("The value string is a comma separated list of numbers.\n");
        printf("An IP address always starts with n followed by 4 (IPv4) or by 6 (IPv6). This\n");
        printf("prefix is followed by the string representation of the IP address. The\n");
        printf("associated list contains numbers such as 1,2,3... where each number is the\n");
        printf("index of a file name.\n");

        printf("\n\nAUTHORS\n\n");
        printf("Originally written by Peter Haag as example and extended with the indexing \n");
        printf("features by Gerard Wagener - CIRCL\n");
        printf("gerard dot wagener at circl.lu\n");

        printf("\nBUGS\n\n");
        printf("- A value list always starts with a comma. This check has been omitted for \n  performance issues.");
        printf("\n- If a file is indexed twice a check on the filename is\n  done but duplicates could emerge in a");
        printf("  value list. Again a check is too\n  costly during the insert operations in order to reach a processing \n");
        printf("  1 million flows per second.\n");
        printf("\nERROR CODES\n\n");
        printf("SUCCESS\t\t\t0\n");
        printf("ERROR_CONNECTION\t1\n");
        printf("ERROR_FILE_INDEX\t2\n");
        printf("ERROR_ADDRESS\t\t3\n");
        printf("ERROR_PID\t\t4\n");
        printf("ERROR_MEMORY\t\t5\n");
        printf("ERROR_RLIMIT\t\t6\n");
        printf("ERROR_PARAMETER\t\t7\n");
        printf("BUS_ERROR\t\t135 (Implicitely returned by Kyotocabinet in case there\n\t\t\t     is not enough of space\n");


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
					syslog(LOG_ERR, "Skip corrupt data file '%s': '%s'\n",GetCurrentFilename(), string);
				else
					syslog(LOG_ERR, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF:
				rfd = GetNextFile(rfd, 0, 0, NULL);
				if ( rfd < 0 ) {
					if ( rfd == NF_ERROR )
						syslog(LOG_ERR, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );

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
					syslog(LOG_ERR,"Memory allocation error");
					exit(ERROR_MEMORY);
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
			syslog(LOG_ERR, "Can't process block type %u. Skip block.\n", block_header.id);
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
				syslog(LOG_ERR, "Skip unknown record type %i\n", flow_record->type);
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


/* Opens the Kyotocabinet file in append or create mode
 * If there is no file a new one is created
 * If there is one the exiting one is opened and the new keys/values are added
 */
void connect_to_kyoto_database(void)
{
    kdb = kcdbnew();
    /* open the database */
    if (!kcdbopen(kdb, database, KCOWRITER | KCOCREATE)) {
        syslog(LOG_ERR, "open error: %s\n", kcecodename(kcdbecode(kdb)));
        exit(ERROR_CONNECTION);
    }
}

/*
 * Checks if the filename is already indexed.
 * @returns 0 if not index
 * @returns > 0 the index of the filename
 */

unsigned int check_filename(char* filename)
{
    char key[256];
    size_t vs;
    char* idx;
    unsigned int nidx;

    nidx = 0;
    snprintf((char*)&key,256, "f:%s",filename);
    idx = kcdbget(kdb, key, strlen(key),&vs);
    if (idx)
        nidx = atoi(idx);

    return nidx;
}

/*
 * Get the next index for a given file name. The first value starts with 1,
 * the next 2, ...
 */
int get_next_index(void)
{
    char key[128];
    char value[128];
    char* val;
    size_t szv;
    snprintf((char*)&key, 128, "c:fid");
    val = kcdbget(kdb,key,strlen(key),&szv);
    if (!val){
        snprintf((char*)&value, 128, "%d",1);
        if (!kcdbset(kdb, key, strlen(key), value, strlen(value))){
            syslog(LOG_ERR, "Could not set the first c:fid value");
        }
        return 1;
    }
    return atoi(val)+1;
}


void set_file_indexes(void)
{
    unsigned int g_index;
    char key[128];
    char value[128];

    g_index=check_filename(g_filename);
    if (g_index > 0)
        goto out;

    /* Compute the next index value */
    g_index=get_next_index();

    /* Store the next index value */
    snprintf((char*)&key, 128, "%s","c:fid");
    snprintf((char*)&value, 128, "%d",g_index);
    if (!kcdbset(kdb, key, strlen(key), value, strlen(value)))
        goto errorsi;

    /* Store the filename index */
    snprintf((char*)&key,128,   "f:%s",g_filename);
    snprintf((char*)&value,128, "%d",g_index);
    if (!kcdbset(kdb, key, strlen(key), value, strlen(value)))
        goto errorsi;

    /* Store the reverse index */
    snprintf((char*)&key, 128, "d:%d",g_index);
    snprintf((char*)&value, 128, "%s",g_filename);
    if (!kcdbset(kdb, key, strlen(key), value, strlen(value)))
        goto errorsi;
    goto out;

errorsi:
    syslog(LOG_ERR, "Cannot get/set index key=%s, value=%s\n",key,value);
    cleanup(ERROR_FILE_INDEX);

out:
    /* Strore the index value as comma separated value */
    snprintf((char*)&gidx_buf, 128, ",%d",g_index);
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
    if (!kcdbappend(kdb,addr,strlen(addr), gidx_buf, strlen(gidx_buf))){
        syslog(LOG_ERR,"Cannot store address %s value=%s",addr, gidx_buf);
        cleanup(ERROR_ADDRESS);
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
        snprintf((char*) &srcaddr, 128, "n6:%s",buf);

        inet_ntop(AF_INET6, r->v6.dstaddr, buf, sizeof(buf));
        snprintf((char*) &dstaddr, 128, "n6:%s",buf);

        sl1 = r->v6.srcaddr[0];
        sl2 = r->v6.srcaddr[1];
        dl1 = r->v6.dstaddr[0];
        dl2 = r->v6.dstaddr[1];

    } else { //IPv4
        r->v4.srcaddr = htonl(r->v4.srcaddr);
        r->v4.dstaddr = htonl(r->v4.dstaddr);

        inet_ntop(AF_INET, &r->v4.srcaddr, buf, sizeof(buf));
        snprintf((char*) &srcaddr, 128, "n4:%s",buf);

        inet_ntop(AF_INET, &r->v4.dstaddr, buf, sizeof(buf));
        snprintf((char*) &dstaddr, 128, "n4:%s",buf);

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


void delete_pid_file(void)
{
    unlink(pidfile);
}

/* Generic routine to properly terminate the process. */
void cleanup(int exitcode)
{
    /* TODO implement a signal handler that invokes this routine */
    if (kdb)
        kcdbclose(kdb);
    delete_pid_file();
    closelog();
    exit(exitcode);
}

/*
 * Store the PID file in a file such that a monitor daemon can check the
 * the status of this program.
 */
void create_pidfile(void)
{
    FILE* fp;
    fp = fopen(pidfile,"w");
    if (fp){
        fprintf(fp,"%d",(int)getpid());
        fclose(fp);
        return;
    }
    /* An error occured */
    syslog(LOG_ERR, "Could not store pid at %s\n",pidfile);
    cleanup(ERROR_PID);
}


int main( int argc, char **argv ) {
char 		*rfile;
int			c;
struct rlimit rlim;


/* Establish syslog channel */
openlog(argv[0], LOG_PERROR | LOG_PID, LOG_DAEMON);
/* Limit the memory consumption of this process
 *  - soft limit 500 MB
 *  - hard limit 600 MB
 * If the limit is reached ENOMEM is returned and the throtteling mechanism
 * activated resulting in a program abortion
 */
rlim.rlim_cur = MAXSOFTLIM;
rlim.rlim_max = MAXHARDLIM;

if (setrlimit(RLIMIT_AS, &rlim) < 0){
    syslog(LOG_ERR, "Resource limitation failed, abort %s\n",
            strerror(errno));
    exit(ERROR_RLIMIT);
}


	rfile =  NULL;
	while ((c = getopt(argc, argv, "p:hr:cd:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(SUCCESS);
				break;
			case 'r':
				rfile = optarg;
				break;
            case 'c':
                cacheenable=0;
                break;
            case 'd':
                database = optarg;
                break;
            case 'p':
                pidfile = optarg;
                break;
            default:
				usage(argv[0]);
				exit(ERROR_PARAMETER);
		}
	}

    /* Check mandatory parameters */
    if (!rfile){
        syslog(LOG_ERR, "Error: no nfcapd file was specified");
        usage(argv[0]);
        exit(ERROR_PARAMETER);
    }
    if (!database){
        syslog(LOG_ERR, "Error: no database file name was specified");
        usage(argv[0]);
        exit(ERROR_PARAMETER);
    }


    ght = g_hash_table_new(addrhash, addreq);
    /* Store pid file */
    create_pidfile();
    /* Make filename global to accessing in the indexing function */
    g_filename = basename(rfile);
    connect_to_kyoto_database();

    set_file_indexes();

	InitExtensionMaps(&extension_map_list);

	SetupInputFileSequence(NULL, rfile, NULL);

	process_data();


    cleanup(SUCCESS);
    return 0;
}
