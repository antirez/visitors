#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sleep.h"

/* Open a file, seek at the end, and store in '*len' the file length */
static FILE *vi_openAtEnd(char *filename, long *len)
{
	FILE *fp = NULL;

	if ((fp = fopen(filename, "rb")) == NULL) goto err; /* open */
	if ((fseek(fp, 0, SEEK_END)) == -1) goto err; /* seek at end */
	if ((*len = ftell(fp)) == -1) goto err; /* read the file length */
	return fp;
err:
	if (fp != NULL) fclose(fp);
	return NULL;
}

/* Output 'len' bytes of file 'fp' starting from 'offset'.
 * The function returns 0 on success, -1 on error. */
#define TAILOUT_BUFLEN 1024
static int vi_tailOutput(FILE *fp, long offset, long len)
{
	char buf[TAILOUT_BUFLEN];
	if (fseek(fp, offset, SEEK_SET) == -1) return -1;
	while(len) {
		unsigned int min = (len > TAILOUT_BUFLEN) ? TAILOUT_BUFLEN : len;
		if (fread(buf, 1, min, fp) != min) return -1;
		fwrite(buf, 1, min, stdout);
		fflush(stdout);
		len -= min;
	}
	return 0;
}

/* An interation for the 'tail -f' simulation. Open the
 * file at every iteration in order to continue to work
 * when files are rotated. */
static void vi_tailIteration(char *filename, long *len)
{
	long newlen, datalen;
	FILE *fp = NULL;

	fp = vi_openAtEnd(filename, &newlen);
	if (fp != NULL) {
		if (*len == -1) {
			/* Initialization */
			*len = newlen;
		} else if (newlen < *len) {
			/* Shorter file condition */
			*len = 0; /* the next iteration will read
				     the new data */
		} else if (newlen > *len) {
			/* Data ready condition */
			datalen = newlen - *len;
			if (vi_tailOutput(fp, *len, datalen) != -1)
				*len = newlen;
		}
	}
	if (fp != NULL) fclose(fp);
}

void vi_tail(int filec, char **filev)
{
	long *len;
	int i;
	
	if (filec <= 0) {
		fprintf(stderr, "No files specified in tail-mode\n");
		exit(1);
	}
	len = malloc(filec);
	if (!len) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	for (i = 0; i < filec; i++)
		len[i] = -1;

	while(1) {
		for (i = 0; i < filec; i++)
			vi_tailIteration(filev[i], &len[i]);
		vi_sleep(1);
	}
}
