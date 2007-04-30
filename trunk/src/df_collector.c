#include "common.h"
#include "calea.h"

/* Config Item: Program_Name */
char *prog_name = "df_collector";
/* Config Item: Syslog_Facility */
int syslog_facility = DEF_SYSLOG_FACILITY;

int main ( int argc, char *argv[] ) {

	HEADER *dfheader;

	setdebug( 5, "syslog", 1 );
	debug_5("df_collector starting",1);

	return 0;
}
