/*
 * The goal of this program is to hang in order to test the daemon behavior
 *
 * Copyright (C) 2011 CIRCL Computer Incident Response Center Luxembourg (smile gie)
 * Copyright (C) 2011 Gerard Wagener
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>
#include <hiredis.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    redisContext* g_rctx;
    redisReply *reply;

    struct timeval timeout = { 1, 500000 };
    g_rctx = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    reply = redisCommand(g_rctx,"SET nfpid %d",getpid());
    printf("%p\n",reply);
    while (1){
        sleep(10);
    }
}

