/*-
 * Copyright (c) 2007 Norman Brandinger <norm@goes.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>

int main (int argc, char *argv[]) {

FILE *fp = NULL;
const char *filename;

int ret;

if(argc < 2) {
  fprintf(stderr, "Specify filename for BER output\n");
} else {
  filename = argv[1];
  fp = fopen(filename, "wb");   /* for BER output */
  if(!fp) {
    perror(filename);
    return -1;
  }
}

//ret = access_attempt(fp);
//ret = access_accepted(fp);
//ret = access_failed(fp);
//ret = access_session_end(fp);
//ret = access_rejected(fp);
//ret = access_signaling_message_report(fp);
//ret = packet_data_session_start(fp);
//ret = packet_data_session_failed(fp);
//ret = packet_data_session_end(fp);
//ret = packet_data_session_already_established(fp);
//ret = packet_data_header_report(fp);
//ret = packet_data_summary_report(fp);
ret = ias_cc_apdu(fp);

if (fp) 
  fclose(fp);

return 0;

}

