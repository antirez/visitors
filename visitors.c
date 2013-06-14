/* visitors -- very fast web logs analyzer.
 *
 * Copyright (C) 2004-2006 Salvatore Sanfilippo <antirez@invece.org>
 * All Rights Reserved.
 *
 * This software is released under the terms of the BSD license.
 * Read the COPYING file in this distribution for more details. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <locale.h>
#include <ctype.h>

#include "aht.h"
#include "antigetopt.h"
#include "sleep.h"
#include "blacklist.h"

/* Max length of an error stored in the visitors handle */
#define VI_ERROR_MAX 1024
/* Max length of a log line */
#define VI_LINE_MAX 4096
/* Max number of filenames in the command line */
#define VI_FILENAMES_MAX 1024
/* Max number of prefixes in the command line */
#define VI_PREFIXES_MAX 1024
/* Max number of --grep --exclude patterns in the command line */
#define VI_GREP_PATTERNS_MAX 1024
/* Abbreviation length for HTML outputs */
#define VI_HTML_ABBR_LEN 100
/* Version as a string */
#define VI_DATE_MAX 64
/* Max length of a log entry date */
#define VI_VERSION_STR "0.7"

/*------------------------------- data structures ----------------------------*/

/* visitors handle */
struct vih {
	int startt;
	int endt;
	int processed;
	int invalid;
        int blacklisted;
	int hour[24];
	int weekday[7];
	int weekdayhour[7][24]; /* hour and weekday combined data */
	int monthday[12][31]; /* month and day combined data */
	struct hashtable visitors;
	struct hashtable googlevisitors;
	struct hashtable pages;
	struct hashtable images;
	struct hashtable error404;
	struct hashtable pageviews;
	struct hashtable pageviews_grouped;
	struct hashtable referers;
	struct hashtable referersage;
	struct hashtable date;
	struct hashtable googledate;
        struct hashtable adsensed;
	struct hashtable month;
	struct hashtable googlemonth;
	struct hashtable agents;
	struct hashtable googled;
	struct hashtable googlevisits;
	struct hashtable googlekeyphrases;
	struct hashtable googlekeyphrasesage;
	struct hashtable trails;
	struct hashtable tld;
	struct hashtable os;
	struct hashtable browsers;
	struct hashtable robots;
        struct hashtable googlehumanlanguage;
        struct hashtable screenres;
        struct hashtable screendepth;
	char *error;
};

/* info associated with a line of log */
struct logline {
	char *host;
	char *date;
	char *hour;
	char *timezone;
	char *req;
	char *ref;
	char *agent;
	time_t time;
	struct tm tm;
};

/* output module structure. See below for the definition of
 * the text and html output modules. */
struct outputmodule {
	void (*print_header)(FILE *fp);
	void (*print_footer)(FILE *fp);
	void (*print_title)(FILE *fp, char *title);
	void (*print_subtitle)(FILE *fp, char *title);
	void (*print_numkey_info)(FILE *fp, char *key, int val);
	void (*print_keykey_entry)(FILE *fp, char *key1, char *key2, int num);
	void (*print_numkey_entry)(FILE *fp, char *key, int val, char *link,
			int num);
	void (*print_numkeybar_entry)(FILE *fp, char *key, int max, int tot,
			int this);
	void (*print_numkeycomparativebar_entry)(FILE *fp, char *key, int tot,
			int this);
	void (*print_bidimentional_map)(FILE *fp, int xlen, int ylen,
			char **xlabel, char **ylabel, int *value);
	void (*print_hline)(FILE *fp);
	void (*print_credits)(FILE *fp);
	void (*print_report_link)(FILE *fp, char *report);
};

/* Just a string with cached length */
struct vistring {
	char *str;
	int len;
};

/* Grep pattern for --grep --exclude */
#define VI_PATTERNTYPE_GREP 0
#define VI_PATTERNTYPE_EXCLUDE 1
struct greppat {
    int type;
    char *pattern;
};

/* ---------------------- global configuration parameters ------------------- */
int Config_debug = 0;
int Config_max_referers = 20;
int Config_max_referers_age = 20;
int Config_max_pages = 20;
int Config_max_images = 20;
int Config_max_error404 = 20;
int Config_max_agents = 20;
int Config_max_googled = 20;
int Config_max_adsensed = 20;
int Config_max_google_keyphrases = 20;
int Config_max_google_keyphrases_age = 20;
int Config_max_trails = 20;
int Config_max_tld = 20;
int Config_max_robots = 20;
int Config_process_agents = 0;
int Config_process_google = 0;
int Config_process_google_keyphrases = 0;
int Config_process_google_keyphrases_age = 0;
int Config_process_google_human_language = 0;
int Config_process_web_trails = 0;
int Config_process_weekdayhour_map = 0;
int Config_process_monthday_map = 0;
int Config_process_referers_age = 0;
int Config_process_tld = 0;
int Config_process_os = 0;
int Config_process_browsers = 0;
int Config_process_error404 = 0;
int Config_process_pageviews = 0;
int Config_process_monthly_visitors = 1;
int Config_process_robots = 0;
int Config_process_screen_info = 0;
int Config_graphviz_mode = 0;
int Config_graphviz_ignorenode_google = 0;
int Config_graphviz_ignorenode_external = 0;
int Config_graphviz_ignorenode_noreferer = 0;
int Config_tail_mode = 0;
int Config_stream_mode = 0;
int Config_update_every = 60*10; /* update every 10 minutes for default. */
int Config_reset_every = 0;	/* never reset for default */
int Config_time_delta = 0;	/* adjustable time difference */
int Config_filter_spam = 0;
int Config_ignore_404 = 0;
char *Config_output_file = NULL; /* stdout if not set. */
struct outputmodule *Output = NULL; /* intialized to 'text' in main() */

/* Prefixes */
int Config_prefix_num = 0;	/* number of set prefixes */
struct vistring Config_prefix[VI_PREFIXES_MAX];

/* Grep/Exclude array */
struct greppat Config_grep_pattern[VI_GREP_PATTERNS_MAX];
int Config_grep_pattern_num = 0;    /* number of set patterns */

/*----------------------------------- Tables ---------------------------------*/
static char *vi_wdname[7] = {"Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"};
#if 0
static int vi_monthdays[12] = {31, 29, 31, 30, 31, 30 , 31, 31, 30, 31, 30, 31};
#endif

/* -------------------------------- prototypes ------------------------------ */
void vi_clear_error(struct vih *vih);
void vi_tail(int filec, char **filev);

/*------------------- Options parsing help functions ------------------------ */
void ConfigAddGrepPattern(char *pattern, int type)
{
    char *s;
    int len = strlen(pattern);

    if (Config_grep_pattern_num == VI_GREP_PATTERNS_MAX) {
        fprintf(stderr, "Too many grep/exclude options specified\n");
        exit(1);
    }
    s = malloc(strlen(pattern)+3);
    s[0] = '*';
    memcpy(s+1, pattern, len);
    s[len+1] = '*';
    s[len+2] = '\0';
    Config_grep_pattern[Config_grep_pattern_num].type = type;
    Config_grep_pattern[Config_grep_pattern_num].pattern = s;
    Config_grep_pattern_num++;
}

/*------------------------------ support functions -------------------------- */
/* Returns non-zero if the link seems like a google link, zero otherwise.
 * Note that this function only checks for a prefix of www.google.<something>.
 * so may be fooled. */
int vi_is_google_link(char *s)
{
	return !strncmp(s, "http://www.google.", 18);
}

/* Returns non-zero if the user agent appears to be the GoogleBot. */
int vi_is_googlebot_agent(char *agent) {
	if (strstr(agent, "Googlebot") ||
            strstr(agent, "googlebot")) return 1;
        return 0;
}

/* Returns non-zero if the user agent appears to be the Mediapartners-Google. */
int vi_is_adsensebot_agent(char *agent) {
	if (strstr(agent, "Mediapartners-Google")) return 1;
        return 0;
}

int vi_is_yahoobot_agent(char *agent) {
        if (strstr(agent, "Yahoo! Slurp")) return 1;
        return 0;
}

int vi_is_msbot_agent(char *agent) {
        if (strstr(agent, "msn.com/msnbot.htm")) return 1;
        return 0;
}

/* Try to guess if a given agent string is about a crawler/bot
 * of some time. This function MUST be conservative, because
 * false negatives are acceptable while false positives arent. */
int vi_is_genericbot_agent(char *agent) {
        if (strstr(agent, "crawler") ||
            strstr(agent, "Crawler") ||
            strstr(agent, "bot/") ||
            strstr(agent, "Bot/") ||
            strstr(agent, "bot.htm") ||
            strstr(agent, "+http://")) return 1;
        return 0;
}

int vi_is_bot_agent(char *agent) {
    if (vi_is_googlebot_agent(agent) ||
        vi_is_adsensebot_agent(agent) ||
        vi_is_yahoobot_agent(agent) ||
        vi_is_msbot_agent(agent)) return 1;
    return 0;
}

/* Returns non-zero if the url matches some user-specified prefix.
 * being a link "internal" to the site. Otherwise zero is returned.
 *
 * When there is a match, the value returned is the length of
 * the matching prefix. */
int vi_is_internal_link(char *url)
{
	int i, l;

	if (!Config_prefix_num) return 0; /* no prefixes set? */
	l = strlen(url);
	for (i = 0; i < Config_prefix_num; i++) {
		if (Config_prefix[i].len <= l &&
		    !strncasecmp(url, Config_prefix[i].str,
			    Config_prefix[i].len))
		{
			return Config_prefix[i].len;
		}
	}
	return 0;
}

/* returns non-zero if the URL 's' seems an image or a CSS file. */
int vi_is_image(char *s)
{
	int l = strlen(s);
	char *end = s + l; /* point to the nul term */

	if (l < 5) return 0;
	if (!memcmp(end-4, ".css", 4) || 
	    !memcmp(end-4, ".jpg", 4) || 
	    !memcmp(end-4, ".gif", 4) ||
	    !memcmp(end-4, ".png", 4) ||
	    !memcmp(end-4, ".ico", 4) ||
	    !memcmp(end-4, ".swf", 4) ||
	    !memcmp(end-3, ".js", 3) ||
	    !memcmp(end-5, ".jpeg", 5) ||
	    !memcmp(end-4, ".CSS", 4) ||
	    !memcmp(end-4, ".JPG", 4) ||
	    !memcmp(end-4, ".GIF", 4) ||
	    !memcmp(end-4, ".PNG", 4) ||
	    !memcmp(end-4, ".ICO", 4) ||
	    !memcmp(end-4, ".SWF", 4) ||
	    !memcmp(end-3, ".JS", 3) ||
	    !memcmp(end-5, ".JPEG", 5)) return 1;
	return 0;
}

/* returns non-zero if the URL 's' seems a real page. */
int vi_is_pageview(char *s)
{
	int l = strlen(s);
	char *end = s + l; /* point to the nul term */
	char *dot, *slash;

	if (s[l-1] == '/') return 1;
	if (l >= 6 &&
	    (!memcmp(end-5, ".html", 5) || 
	    !memcmp(end-4, ".htm", 4) || 
	    !memcmp(end-4, ".php", 4) ||
	    !memcmp(end-4, ".asp", 4) ||
	    !memcmp(end-4, ".jsp", 4) ||
	    !memcmp(end-4, ".xdl", 4) ||
	    !memcmp(end-5, ".xhtml", 5) ||
	    !memcmp(end-4, ".xml", 4) ||
	    !memcmp(end-4, ".cgi", 4) ||
	    !memcmp(end-3, ".pl", 3) ||
	    !memcmp(end-6, ".shtml", 6) ||
	    !memcmp(end-5, ".HTML", 5) || 
	    !memcmp(end-4, ".HTM", 4) || 
	    !memcmp(end-4, ".PHP", 4) ||
	    !memcmp(end-4, ".ASP", 4) ||
	    !memcmp(end-4, ".JSP", 4) ||
	    !memcmp(end-4, ".XDL", 4) ||
	    !memcmp(end-6, ".XHTML", 6) ||
	    !memcmp(end-4, ".XML", 4) ||
	    !memcmp(end-4, ".CGI", 4) ||
	    !memcmp(end-3, ".PL", 3) ||
	    !memcmp(end-6, ".SHTML", 6))) return 1;
	dot = strrchr(s, '.');
	if (!dot) return 1;
	slash = strrchr(s, '/');
	if (slash && slash > dot) return 1;
	return 0;
}

/* returns non-zero if 'ip' seems a string representing an IP address
 * like "1.2.3.4". Note that 'ip' is always an IP or an hostname
 * so this function actually test if the string pointed by 'ip' only
 * contains characters in the "[0-9.]" set */
int vi_is_numeric_address(char *ip)
{
	unsigned int l = strlen(ip);
	return strspn(ip, "0123456789.") == l;
}

/* returns the time converted into a time_t value.
 * On error (time_t) -1 is returned.
 * Note that this function is specific for the following format:
 * "10/May/2004:04:15:33". Works if the month is not an abbreviation, or if the
 * year is abbreviated to only the last two digits.
 * The time can be omitted like in "10/May/2004". */
time_t parse_date(char *s, struct tm *tmptr)
{
	struct tm tm;
	time_t t;
	char *months[] = {
		"jan", "feb", "mar", "apr", "may", "jun",
		"jul", "aug", "sep", "oct", "nov", "dec",
	};
	char *day, *month, *year, *time = NULL;
	char monthaux[32];
	int i, len;

	/* make a copy to mess with it */
	len = strlen(s);
	if (len >= 32) goto fmterr;
	memcpy(monthaux, s, len);
	monthaux[len] = '\0';

	/* Inizialize the tm structure. We just fill three fields */
	tm.tm_sec = 0;
	tm.tm_min = 0;
	tm.tm_hour = 0;
	tm.tm_mday = 0;
	tm.tm_mon = 0;
	tm.tm_year = 0;
	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = -1;

	/* search delimiters */
	day = monthaux;
	if ((month = strchr(day, '/')) == NULL) goto fmterr;
	*month++ = '\0';
	if ((year = strchr(month, '/')) == NULL) goto fmterr;
	*year++ = '\0';
	/* time, optional for this parser. */
	if ((time = strchr(year, ':')) != NULL) {
		*time++ = '\0';
	}
	/* convert day */
	tm.tm_mday = atoi(day);
	if (tm.tm_mday < 1 || tm.tm_mday > 31) goto fmterr;
	/* convert month */
	if (strlen(month) < 3) goto fmterr;
	month[0] = tolower(month[0]);
	month[1] = tolower(month[1]);
	month[2] = tolower(month[2]);
	for (i = 0; i < 12; i++) {
		if (memcmp(month, months[i], 3) == 0) break;
	}
	if (i == 12) goto fmterr;
	tm.tm_mon = i;
	/* convert year */
	tm.tm_year = atoi(year);
	if (tm.tm_year > 100) {
		if (tm.tm_year < 1900 || tm.tm_year > 2500) goto fmterr;
		tm.tm_year -= 1900;
	} else {
		/* if the year is in two-digits form, the 0 - 68 range
		 * is converted to 2000 - 2068 */
		if (tm.tm_year < 69)
			tm.tm_year += 100;
	}
	/* convert time */
	if (time) { /* format is HH:MM:SS */
		if (strlen(time) < 8) goto fmterr;
		tm.tm_hour = ((time[0]-'0')*10)+(time[1]-'0');
		if (tm.tm_hour < 0 || tm.tm_hour > 23) goto fmterr;
		tm.tm_min = ((time[3]-'0')*10)+(time[4]-'0');
		if (tm.tm_min < 0 || tm.tm_min > 59) goto fmterr;
		tm.tm_sec = ((time[6]-'0')*10)+(time[7]-'0');
		if (tm.tm_sec < 0 || tm.tm_sec > 60) goto fmterr;
	}
	t = mktime(&tm);
	if (t == (time_t)-1) goto fmterr;
	t += (Config_time_delta*3600);
	if (tmptr) {
		struct tm *auxtm;

		if ((auxtm = localtime(&t)) != NULL)
			*tmptr = *auxtm;
	}
	return t;

fmterr: /* format error */
	return (time_t) -1;
}

/* returns 1 if the given date is Saturday or Sunday.
 * Zero is otherwise returned. */
int vi_is_weekend(char *s)
{
	struct tm tm;

	if (parse_date(s, &tm) != (time_t)-1) {
		if (tm.tm_wday == 0 || tm.tm_wday == 6)
			return 1;
	}
	return 0;
}

#if 0
/* Returns true if 'year' is a leap year. */
int isleap(int year)
{
	int conda, condb, condc;

	conda = (year%4) == 0;
	condb = (year%100) == 0;
	condc = (year%400) == 0;
	return conda && !(condb && !condc);
}
#endif

/* URL decoding and white spaces trimming function.
 * Input: the encoded string 's'.
 * Output: the decoded string written at 'd' that has room for at least 'n'
 * bytes of data. */
void vi_urldecode(char *d, char *s, int n)
{
	char *start = d;
	if (n < 1) return;
	while(*s && n > 1) {
		int c = *s;
		switch(c) {
		case '+': c = ' '; break;
		case '%':
			  if (*(s+1) && *(s+2)) {
				  int high = toupper(*(s+1));
				  int low = toupper(*(s+2));

				  if (high <= '9') high -= '0';
				  else high = (high - 'A') + 10;
				  if (low <= '9') low -= '0';
				  else low = (low - 'A') + 10;
				  c = (high << 4)+low;
				  s += 2;
			  }
			  break;
		}
		if (c != ' ' || d != start) {
			*d++ = c;
			n--;
		}
		s++;
	}
	/* Right trim */
	*d = '\0';
	d--;
	while (d >= start && *d == ' ') {
		*d = '\0';
		d--;
	}
}

/* URL encoding function
 * Input: the unencoded string 's'.
 * Output: the url-encoded string written at 'd' that has room for at least 'n'
 * bytes of data. */
void vi_urlencode(char *d, char *s, int n)
{
	if (n < 1) return;
	n--;
	while(*s && n > 0) {
		int c = *s;
		if ((c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9'))
		{
			*d++ = c;
			n--;
		} else if (c == ' ') {
			*d++ = '+';
			n--;
		} else if (c == '\n') {
			if (n < 6) break;
			memcpy(d, "%0d%0a", 6);
			d += 6;
			n -= 6;
		} else {
			unsigned int t;
			char *hexset = "0123456789abcdef";

			if (n < 3) break;
			t = (unsigned) c;
			*d++ = '%';
			*d++ = hexset [(t & 0xF0) >> 4];
			*d++ = hexset [(t & 0x0F)];
			n -= 3;
		}
		s++;
	}
	*d = '\0';
}

/* Convert a nul-term string to lowercase in place */
void vi_strtolower(char *s)
{
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

/* Note: the following function strlcat and strlcpy are (possibly) modified
 * version of OpenBSD's functions. Original copyright notice:
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * Originally under the BSD license. */
int vi_strlcpy(char *dst, char *src, int siz)
{
        char *d = dst;
        const char *s = src;
        int n = siz;

        /* Copy as many bytes as will fit */
        if (n != 0 && --n != 0) {
                do {
                        if ((*d++ = *s++) == 0)
                                break;
                } while (--n != 0);
        }
        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';              /* NUL-terminate dst */
                while (*s++)
                        ;
        }
        return(s - src - 1);    /* count does not include NUL */
}

int vi_strlcat(char *dst, const char *src, int siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz;
        size_t dlen;

        /* Find the end of dst and adjust bytes left but don't go past end */
        while (n-- != 0 && *d != '\0')
                d++;
        dlen = d - dst;
        n = siz - dlen;

        if (n == 0)
                return(dlen + strlen(s));
        while (*s != '\0') {
                if (n != 1) {
                        *d++ = *s;
                        n--;
                }
                s++;
        }
        *d = '\0';

        return(dlen + (s - src));       /* count does not include NUL */
}

/* Returns non-zero if the url matches one of the keywords in
 * blacklist.h, otherwise zero is returned. Warning!!! This function
 * run time is proportional to the size of blacklist.h, so it is
 * very slow. */
int vi_is_blacklisted_url(struct vih *vih, char *url)
{
    unsigned int i;

    for (i = 0; i < VI_BLACKLIST_LEN; i++) {
        if (strstr(url, vi_blacklist[i])) {
            vih->blacklisted++;
            return 1;
        }
    }
    return 0;
}

/* Glob-style pattern matching. */
int vi_match_len(const char *pattern, int patternLen,
        const char *string, int stringLen, int nocase)
{
    while(patternLen) {
        switch(pattern[0]) {
        case '*':
            while (pattern[1] == '*') {
                pattern++;
                patternLen--;
            }
            if (patternLen == 1)
                return 1; /* match */
            while(stringLen) {
                if (vi_match_len(pattern+1, patternLen-1,
                            string, stringLen, nocase))
                    return 1; /* match */
                string++;
                stringLen--;
            }
            return 0; /* no match */
            break;
        case '?':
            if (stringLen == 0)
                return 0; /* no match */
            string++;
            stringLen--;
            break;
        case '[':
        {
            int not, match;

            pattern++;
            patternLen--;
            not = pattern[0] == '^';
            if (not) {
                pattern++;
                patternLen--;
            }
            match = 0;
            while(1) {
                if (pattern[0] == '\\') {
                    pattern++;
                    patternLen--;
                    if (pattern[0] == string[0])
                        match = 1;
                } else if (pattern[0] == ']') {
                    break;
                } else if (patternLen == 0) {
                    pattern--;
                    patternLen++;
                    break;
                } else if (pattern[1] == '-' && patternLen >= 3) {
                    int start = pattern[0];
                    int end = pattern[2];
                    int c = string[0];
                    if (start > end) {
                        int t = start;
                        start = end;
                        end = t;
                    }
                    if (nocase) {
                        start = tolower(start);
                        end = tolower(end);
                        c = tolower(c);
                    }
                    pattern += 2;
                    patternLen -= 2;
                    if (c >= start && c <= end)
                        match = 1;
                } else {
                    if (!nocase) {
                        if (pattern[0] == string[0])
                            match = 1;
                    } else {
                        if (tolower((int)pattern[0]) == tolower((int)string[0]))
                            match = 1;
                    }
                }
                pattern++;
                patternLen--;
            }
            if (not)
                match = !match;
            if (!match)
                return 0; /* no match */
            string++;
            stringLen--;
            break;
        }
        case '\\':
            if (patternLen >= 2) {
                pattern++;
                patternLen--;
            }
            /* fall through */
        default:
            if (!nocase) {
                if (pattern[0] != string[0])
                    return 0; /* no match */
            } else {
                if (tolower((int)pattern[0]) != tolower((int)string[0]))
                    return 0; /* no match */
            }
            string++;
            stringLen--;
            break;
        }
        pattern++;
        patternLen--;
        if (stringLen == 0) {
            while(*pattern == '*') {
                pattern++;
                patternLen--;
            }
            break;
        }
    }
    if (patternLen == 0 && stringLen == 0)
        return 1;
    return 0;
}

/* Like vi_match_len but more handly if used against nul-term strings. */
int vi_match(const char *pattern, const char *string, int nocase)
{
    int patternLen = strlen(pattern);
    int stringLen = strlen(string);
    return vi_match_len(pattern, patternLen, string, stringLen, nocase);
}

/*-------------------------- visitors handler functions --------------------- */
/* Init the hashtable with methods suitable for an "occurrences counter" */
void vi_ht_init(struct hashtable *ht)
{
	ht_init(ht);
	ht_set_hash(ht, ht_hash_string);
	ht_set_key_destructor(ht, ht_destructor_free);
	ht_set_val_destructor(ht, ht_no_destructor);
	ht_set_key_compare(ht, ht_compare_string);
}

/* Reset the weekday/hour info in the visitors handler. */
void vi_reset_combined_maps(struct vih *vih)
{
	int i, j;

	for (i = 0; i < 24; i++) {
		vih->hour[i] = 0;
		for (j = 0; j < 7; j++)
			vih->weekdayhour[j][i] = 0;
	}
	for (i = 0; i < 7; i++) vih->weekday[i] = 0;
	for (i = 0; i < 31; i++)
		for (j = 0; j < 12; j++)
			vih->monthday[j][i] = 0;
}

/* Reset the hashtables from the handler, that are left
 * in a reusable state (but all empty). */
void vi_reset_hashtables(struct vih *vih)
{
	ht_destroy(&vih->visitors);
	ht_destroy(&vih->googlevisitors);
	ht_destroy(&vih->pages);
	ht_destroy(&vih->images);
	ht_destroy(&vih->error404);
	ht_destroy(&vih->pageviews);
	ht_destroy(&vih->pageviews_grouped);
	ht_destroy(&vih->referers);
	ht_destroy(&vih->referersage);
	ht_destroy(&vih->agents);
	ht_destroy(&vih->googled);
	ht_destroy(&vih->adsensed);
	ht_destroy(&vih->googlekeyphrases);
	ht_destroy(&vih->googlekeyphrasesage);
	ht_destroy(&vih->googlevisits);
	ht_destroy(&vih->trails);
	ht_destroy(&vih->tld);
	ht_destroy(&vih->os);
	ht_destroy(&vih->browsers);
	ht_destroy(&vih->date);
	ht_destroy(&vih->googledate);
	ht_destroy(&vih->month);
	ht_destroy(&vih->googlemonth);
	ht_destroy(&vih->robots);
	ht_destroy(&vih->googlehumanlanguage);
	ht_destroy(&vih->screenres);
	ht_destroy(&vih->screendepth);
}

/* Reset handler informations to support --reset option in
 * stream mode. */
void vi_reset(struct vih *vih)
{
	vi_reset_combined_maps(vih);
	vi_reset_hashtables(vih);
}

/* Return a new visitors handle.
 * On out of memory NULL is returned.
 * The handle obtained with this call must be released with vi_free()
 * when no longer useful. */
struct vih *vi_new(void)
{
	struct vih *vih;

	if ((vih = malloc(sizeof(*vih))) == NULL)
		return NULL;
	/* Initialization */
	vih->startt = vih->endt = time(NULL);
	vih->processed = 0;
	vih->invalid = 0;
        vih->blacklisted = 0;
	vi_reset_combined_maps(vih);
	vih->error = NULL;
	vi_ht_init(&vih->visitors);
	vi_ht_init(&vih->googlevisitors);
	vi_ht_init(&vih->pages);
	vi_ht_init(&vih->images);
	vi_ht_init(&vih->error404);
	vi_ht_init(&vih->pageviews);
	vi_ht_init(&vih->pageviews_grouped);
	vi_ht_init(&vih->referers);
	vi_ht_init(&vih->referersage);
	vi_ht_init(&vih->agents);
	vi_ht_init(&vih->googled);
	vi_ht_init(&vih->adsensed);
	vi_ht_init(&vih->googlevisits);
	vi_ht_init(&vih->googlekeyphrases);
	vi_ht_init(&vih->googlekeyphrasesage);
	vi_ht_init(&vih->trails);
	vi_ht_init(&vih->tld);
	vi_ht_init(&vih->os);
	vi_ht_init(&vih->browsers);
	vi_ht_init(&vih->date);
	vi_ht_init(&vih->month);
	vi_ht_init(&vih->googledate);
	vi_ht_init(&vih->googlemonth);
	vi_ht_init(&vih->robots);
	vi_ht_init(&vih->googlehumanlanguage);
	vi_ht_init(&vih->screenres);
	vi_ht_init(&vih->screendepth);
	return vih;
}

/* Free an handle created with vi_new(). */
void vi_free(struct vih *vih)
{
	if (!vih) return;
	vi_reset_hashtables(vih);
	vi_clear_error(vih);
	free(vih);
}

/* Add a new entry in the counter hashtable. If the key does not
 * exists creates a new entry with "1" as number of hits, otherwise
 * increment the old value.
 *
 * Return the value of hits after the increment or creation. If the
 * returned value is greater than one, the key was already seen.
 *
 * Return 0 on out of memory.
 *
 * NOTE: the pointer of the "value" part of the hashtable entry is
 * used as a counter casting it to a "long" integer. */
int vi_counter_incr(struct hashtable *ht, char *key)
{
	char *k;
	unsigned int idx;
	int r;
	long val;
	
	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		k = strdup(key);
		if (k == NULL) return 0;
		if (ht_add(ht, k, (void*)1) != HT_OK) {
			free(k);
			return 0;
		}
		return 1;
	} else {
		val = (long) ht_value(ht, idx);
		val++;
		ht_value(ht, idx) = (void*) val;
		return val;
	}
}

/* Similar to vi_counter_incr, but only read the old value of
 * the counter without to alter it. If the specified key does not
 * exists zero is returned. */
int vi_counter_val(struct hashtable *ht, char *key)
{
	unsigned int idx;
	int r;
	long val;
	
	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		return 0;
	} else {
		val = (long) ht_value(ht, idx);
		return val;
	}
}

/* Set a key/value pair inside the hash table with
 * a create-else-replace semantic.
 *
 * Return non-zero on out of memory. */
int vi_replace(struct hashtable *ht, char *key, char *value)
{
	char *k, *v;

	k = strdup(key);
	v = strdup(value);
	if (!k || !v) goto err;
	if (ht_replace(ht, k, v) != HT_OK)
		goto err;
	return 0;
err:
	if (k) free(k);
	if (v) free(v);
	return 1;
}

/* Replace the time value of the given key with the new one if this
 * is newer/older of the old one. If the key is new, it's just added
 * to the hash table with the specified time as value.
 *
 * If the 'ifolder' flag is set, values are replaced with older one,
 * otherwise with newer.
 * This function is only used by wrappers replace_if_older() and
 * replace_if_newer().
 *
 * Return 0 on success, non-zero on out of memory. */
int vi_replace_time(struct hashtable *ht, char *key, time_t time, int ifolder)
{
	char *k = NULL;
	unsigned int idx;
	int r;

	r = ht_search(ht, key, &idx);
	if (r == HT_NOTFOUND) {
		k = strdup(key);
		if (!k) goto err;
		if (ht_add(ht, k, (void*)time) != HT_OK) goto err;
	} else {
		time_t oldt = (time_t) ht_value(ht, idx);
		/* Update the date if this one is older/nwer. */
		if (ifolder) {
			if (time < oldt)
				ht_value(ht, idx) = (void*) time;
		} else {
			if (time > oldt)
				ht_value(ht, idx) = (void*) time;
		}
	}
	return 0;
err:
	if (k) free(k);
	return 1;
}

/* see vi_replace_time */
int vi_replace_if_older(struct hashtable *ht, char *key, time_t time)
{
	return vi_replace_time(ht, key, time, 1);
}

/* see vi_replace_time */
int vi_replace_if_newer(struct hashtable *ht, char *key, time_t time)
{
	return vi_replace_time(ht, key, time, 0);
}

/* Set an error in the visitors handle */
void vi_set_error(struct vih *vih, char *fmt, ...)
{
	va_list ap;
	char buf[VI_ERROR_MAX];

	va_start(ap, fmt);
	vsnprintf(buf, VI_ERROR_MAX, fmt, ap);
	buf[VI_ERROR_MAX-1] = '\0';
	free(vih->error);
	vih->error = strdup(buf);
	va_end(ap);
}

/* Get the error */
char *vi_get_error(struct vih *vih)
{
	if (!vih->error) {
		return "No error";
	}
	return vih->error;
}

/* Clear the error */
void vi_clear_error(struct vih *vih)
{
	free(vih->error);
	vih->error = NULL;
}

/*----------------------------------- parsing   ----------------------------- */
/* Parse a line of log, and fill the logline structure with
 * appropriate values. On error (bad line format) non-zero is returned. */
int vi_parse_line(struct logline *ll, char *l)
{
	char *date, *hour, *timezone, *host, *agent, *req, *ref, *p;
	char *agent_start = NULL, *req_end = NULL, *ref_end = NULL;
        int agent_without_parens = 0;

	/* Seek the start of the different components */

	/* host */
	host = l;
	/* date */
	if ((date = strchr(l, '[')) == NULL) return 1;
	date++;
	/* Identify user-agent start char. */
	if ((agent = strchr(l, '(')) == NULL) {
                /* Bad... user agent without (...) string, makes
                 * the detection a bit slower and guessworkish. */

                /* Check if the count of '"' chars in the string
                 * is equal to six. If so, it's very likely that the
                 * last field inside "" is the User Agent string, so
                 * we get it. */
                char *aux = l, *last = NULL;
                int count = 0;
               
                /* Count '"' chars, save the last occurence found. */
                while (*aux) {
                    if (*aux == '"') {
                        count++;
                        last = aux;
                    }
                    aux++;
                }

                if (count == 6) {
                    /* Ok! it seems like Combined log format.
                     * Set a flag and get it later when the
                     * rest of the log file is splitted. Now it's
                     * too early to add \0 chars inside the line. */
                    agent_without_parens = 1;
                    agent_start = last-1;
                    while(*agent_start != '"')
                        agent_start--;
                } else {
                    /* No way... no user agent detected in this line. */
		    agent = "";
                }
	} else {
                /* User agent with () inside. Simple to detect, just
                 * search the left and the right '"' chars enclosing
                 * it. */
		p = agent;
		while (p >= l) {
			if (*p == '"') {
				agent_start = p;
				break;
			}
			p--;
		}
	}
	/* req */
	if ((req = strstr(l, "\"GET")) != NULL ||
	    (req = strstr(l, "\"POST")) != NULL ||
	    (req = strstr(l, "\"HEAD")) != NULL ||
	    (req = strstr(l, "\"get")) != NULL ||
	    (req = strstr(l, "\"post")) != NULL ||
	    (req = strstr(l, "\"head")) != NULL)
	{
		req++;
	} else {
		req = "";
	}
	/* ref */
	if ((ref = strstr(l, "\"http")) != NULL ||
	    (ref = strstr(l, "\"HTTP")) != NULL)
	{
		ref++;
	} else {
		ref = "";
	}

	/* Nul-term the components */

	/* host */
	if ((p = strchr(host, ' ')) == NULL) return 1;
	*p = '\0';
	/* date */
	if ((p = strchr(date, ']')) == NULL) return 1;
	*p = '\0';
	ll->time = parse_date(date, &ll->tm);
	if (ll->time == (time_t)-1) return 1;
	/* hour */
	if ((p = strchr(date, ':')) == NULL) return 1;
	hour = p+1;
	*p = '\0';
	/* timezone */
	if ((p = strchr(hour, ' ')) == NULL) return 1;
	timezone = p+1;
	*p = '\0';
	/* req */
	if ((p = strchr(req, '"')) == NULL) {
		req = "";
	} else {
		req_end = p;
		*p = '\0';
		if ((p = strchr(req, ' ')) != NULL) {
			req = p+1;
			if ((p = strchr(req, ' ')) != NULL)
				*p = '\0';
		}
	}
	/* ref */
	if ((p = strchr(ref, '"')) == NULL) {
		ref = "";
	} else {
		ref_end = p;
		*p = '\0';
	}
	/* agent */
        if (agent_without_parens) {
            /* User agent without (...) inside in a string with six '"' chars.
             * Just search for the end. */
            char *aux = strchr(agent_start+1, '"');
            if (!aux) {
                /* No way! */
                agent = "";
            } else {
                *aux = '\0';
                agent = agent_start+1;
            }
        } else if ((p = strchr(agent, ')')) == NULL) {
		agent = "";
	} else {
		char *aux;

		aux = strchr(p, '"');
		if (aux)
			*aux = '\0';
		else
			*(p+1) = '\0';
		if (agent_start) {
			if ((!req_end || (req_end != agent_start)) &&
			    (!ref_end || (ref_end != agent_start))) {
				agent = agent_start+1;
			}
		}
	}

	/* Fill the struture */
	ll->host = host;
	ll->date = date;
	ll->hour = hour;
	ll->timezone = timezone;
	ll->agent = agent;
	ll->req = req;
	ll->ref = ref;
	return 0;
}

/* process the weekday and hour information */
void vi_process_date_and_hour(struct vih *vih, int weekday, int hour)
{
	/* Note, the following sanity check is useless in theory. */
	if (weekday < 0 || weekday > 6 || hour < 0 || hour > 23) return;
	vih->weekday[weekday]++;
	vih->hour[hour]++;
	/* store the combined info. We always compute this information
	 * even if the report is disabled because it's cheap. */
	vih->weekdayhour[weekday][hour]++;
}

/* process the month and day information */
void vi_process_month_and_day(struct vih *vih, int month, int day)
{
	if (month < 0 || month > 11 || day < 0 || day > 30) return;
	vih->monthday[month][day]++;
}

/* Process unique visitors populating the relative hash table.
 * Return non-zero on out of memory. This is also used to populate
 * the hashtable used for the "pageviews per user" statistics.
 *
 * Note that the last argument 'seen', is an integer passed by reference
 * that is set to '1' if this is not a new visit (otherwise it's set to zero) */
int vi_process_visitors_per_day(struct vih *vih, char *host, char *agent, char *date, char *ref, char *req, int *seen)
{
	char visday[VI_LINE_MAX], *p, *month = "fixme if I'm here!";
        char buf[64];
	int res, host_len, agent_len, date_len, hash_len;
        unsigned long h;

        /* Ignore visits from Bots */
        if (vi_is_bot_agent(agent)) {
            if (seen != NULL) seen = 0;
            return 0;
        }

        /* Build an unique identifier for this visit
         * adding together host, date and hash(user agent) */
	host_len = strlen(host);
	agent_len = strlen(agent);
	date_len = strlen(date);
        h = djb_hash((unsigned char*) agent, agent_len);
        sprintf(buf, "%lu", h);
        hash_len = strlen(buf);
	if (host_len+agent_len+date_len+4 > VI_LINE_MAX)
		return 0;
	p = visday;
	memcpy(p, host, host_len); p += host_len;
	*p++ = '|';
	memcpy(p, date, date_len); p += date_len;
	*p++ = '|';
	memcpy(p, buf, hash_len); p += hash_len;
	*p = '\0';
        /* fprintf(stderr, "%s\n", visday); */

	if (Config_process_monthly_visitors) {
		/* Skip the day number. */
		month = strchr(date, '/');
		if (!month) return 0; /* should never happen */
		month++;
	}

	/* Visits with Google as referer are also stored in another hash
	 * table. */
	if (vi_is_google_link(ref)) {
		res = vi_counter_incr(&vih->googlevisitors, visday);
		if (res == 0) return 1; /* out of memory */
		if (res == 1) { /* new visit! */
			res = vi_counter_incr(&vih->googledate, date);
			if (res == 0) return 1; /* out of memory */
			if (Config_process_monthly_visitors) {
				res = vi_counter_incr(&vih->googlemonth, month);
				if (res == 0) return 1; /* out of memory */
			}
		}
	}
	/* Populate the 'pageviews per visitor' hash table */
	if (Config_process_pageviews && vi_is_pageview(req)) {
		res = vi_counter_incr(&vih->pageviews, visday);
		if (res == 0) return 1; /* out of memory */
	}
	/* Mark the visit in the non-google-specific hashtable */
	res = vi_counter_incr(&vih->visitors, visday);
	if (res == 0) return 1; /* out of memory */
	if (res > 1) {
		if (seen) *seen = 1;
		return 0; /* visit alredy seen. */
	}
	if (seen) *seen = 0; /* new visitor */
	res = vi_counter_incr(&vih->date, date);
	if (res == 0) return 1;
	if (Config_process_monthly_visitors) {
		res = vi_counter_incr(&vih->month, month);
		if (res == 0) return 1;
	}
	return 0;
}

/* Process referers populating the relative hash tables.
 * Return non-zero on out of memory. */
int vi_process_referer(struct vih *vih, char *ref, time_t age)
{
	int res;

        /* Check the url against the blacklist if needed
         * this can be very slow... */
        if (Config_filter_spam && vi_is_blacklisted_url(vih, ref))
            return 0;
	/* Don't count internal referer (specified by the user
	 * using --prefix options), nor google referers. */
	if (vi_is_internal_link(ref))
		return !vi_counter_incr(&vih->referers, "Internal Link");
	if (vi_is_google_link(ref))
		return !vi_counter_incr(&vih->referers, "Google Search Engine");
	res = vi_counter_incr(&vih->referers, ref);
	if (res == 0) return 1;
	/* Process the referers age if enabled */
	if (Config_process_referers_age) {
		if (vi_replace_if_older(&vih->referersage, ref, age)) return 1;
	}
	return 0;
}

/* Process requested URLs. Split the entries in two hash tables,
 * one for pages and one for images.
 * Return non-zero on out of memory. */
int vi_process_page_request(struct vih *vih, char *url)
{
	int res;
	char urldecoded[VI_LINE_MAX];

	vi_urldecode(urldecoded, url, VI_LINE_MAX);
	if (vi_is_image(url))
		res = vi_counter_incr(&vih->images, urldecoded);
	else
		res = vi_counter_incr(&vih->pages, urldecoded);
	if (res == 0) return 1;
	return 0;
}

/* Process log lines for 404 errors report. */
int vi_process_error404(struct vih *vih, char *l, char *url, int *is404)
{
	char urldecoded[VI_LINE_MAX];

        if (is404) *is404 = 0;
	vi_urldecode(urldecoded, url, VI_LINE_MAX);
	if (strstr(l, " 404 ") && !strstr(l, " 200 ")) {
                if (is404) *is404 = 1;
		return !vi_counter_incr(&vih->error404, urldecoded);
        }
	return 0;
}

/* Process agents populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_agents(struct vih *vih, char *agent)
{
	int res;

	res = vi_counter_incr(&vih->agents, agent);
	if (res == 0) return 1;
	return 0;
}

/* Match the list of keywords 't' against the string 's', and if
 * a match is found increment the matching keyword in the hashtable.
 * Return zero on success, non-zero on out of memory . */
int vi_counter_incr_matchtable(struct hashtable *ht, char *s, char **t)
{
	while(*t) {
		int res;
		if ((*t)[0] == '\0' || strstr(s, *t) != NULL) {
			char *key = *(t+1) ? *(t+1) : *t;
			res = vi_counter_incr(ht, key);
			if (res == 0) return 1;
			return 0;
		}
		t += 2;
	}
	return 0;
}

/* Process Operating Systems populating the relative hash table.
 * Return non-zero on out of memory. */
int vi_process_os(struct vih *vih, char *agent)
{
	/* Order may matter. */
	char *oslist[] = {
		"Windows Phone OS", "Windows Phone",
		"Windows", NULL,
		"Win98", "Windows",
		"Win95", "Windows",
		"WinNT", "Windows",
		"Win32", "Windows",
		"Linux", NULL,
		"-linux-", "Linux",
		"Macintosh", NULL,
		"Mac_PowerPC", "Macintosh",
		"Darwin", "Macintosh",
		"iPad", "iOS",
		"iPhone", "iOS",
		"iPod", "iOS",
		"SunOS", NULL,
		"FreeBSD", NULL,
		"OpenBSD", NULL,
		"NetBSD", NULL,
		"BEOS", NULL,
		"", "Unknown",
		NULL, NULL,
	};
	return vi_counter_incr_matchtable(&vih->os, agent, oslist);
}

/* Process browsers information. */
int vi_process_browsers(struct vih *vih, char *agent)
{
	/* Note that the order matters. For example Safari
	 * send an user agent where there is the string "Gecko"
	 * so it must be before Gecko. */
	char *browserslist[] = {
	    "Chrome", NULL,
		"Opera", NULL,
		"IEMobile/7.0", "Mobile Internet Explorer 7.0",
		"IEMobile/8.0", "Mobile Internet Explorer 8.0",
		"IEMobile/9.0", "Mobile Internet Explorer 9.0",
		"IEMobile/10.0", "Mobile Internet Explorer 10.0",
		"IEMobile", "Mobile Internet Explorer unknown version",
		"MSIE 4", "Explorer 4.x",
		"MSIE 5", "Explorer 5.x",
		"MSIE 6", "Explorer 6.x",
		"MSIE 7", "Explorer 7.x",
		"MSIE 8", "Explorer 8.x",
		"MSIE 9", "Explorer 9.x",
		"MSIE 10", "Explorer 10.x",
		"MSIE", "Explorer unknown version",
		"Safari", NULL,
		"Konqueror", NULL,
		"Galeon", NULL,
		"Iceweasel", NULL,
		"Firefox", NULL,
		"MultiZilla", NULL,
		"Gecko", "Other Mozilla based",
		"wget", NULL,
		"Wget", "wget",
		"Lynx", NULL,
		"Links ", "Links",
		"ELinks ", "Links",
		"Elinks ", "Links",
		"Liferea", NULL,
		"w3m", "W3M",
		"NATSU-MICAN", NULL,
		"msnbot", "MSNbot",
		"Slurp", "Yahoo Slurp",
		"Jeeves", "Ask Jeeves",
		"ZyBorg", NULL,
		"asteria", NULL,
		"contype", "Explorer",
		"Gigabot", NULL,
		"Windows-Media-Player", "Windows-MP",
		"NSPlayer", NULL,
		"Googlebot", "GoogleBot",
		"googlebot", "GoogleBot",
		"yacybot", "YaCy-Bot",
		"Sogou", "Sogou.com Bot",
		"psbot", "Picsearch.com Bot",
		"sosospider", "Soso.com Bot",
		"Baiduspider+", "Baidu.com Bot",
		"Yandex", "Yandex.com Bot",
		"Yeti", "Nava.com Bot",
		"APT-HTTP", "Apt",
		"git", "Git",
		"curl", NULL,
		"", "Unknown",
		NULL, NULL,
	};
	return vi_counter_incr_matchtable(&vih->browsers, agent, browserslist);
}

/* Process req/agents to get information about pages retrivied by Google.
 * Return non-zero on out of memory. */
int vi_process_googled(struct vih *vih, char *req, char *agent, time_t age)
{
        if (vi_is_googlebot_agent(agent)) {
	    return vi_replace_if_newer(&vih->googled, req, age);
        } else if (vi_is_adsensebot_agent(agent)) {
	    return vi_replace_if_newer(&vih->adsensed, req, age);
        }
        return 0;
}

/* Process screen resolution and color depth info, if the javascript
 * code needed was inserted in the pages (see the README file). */
int vi_process_screen_info(struct vih *vih, char *req) {
    char *p;

    if ((p = strstr(req, "visitors-screen-res-check.jpg?"))) {
        char buf[64];

        p += 30;
        if (p[0] == '\0' || strstr(p, "undefined")) goto parseerror;
        vi_strlcpy(buf, p, 64);
        /* The string is somethink like: 1024x768x32, so we
         * search for the second 'x' char. */
        p = strchr(buf,'x'); if (!p) goto parseerror;
        p = strchr(p+1,'x'); if (!p) goto parseerror;
        *p = '\0'; p++;
        /* Populate the screen resolution hash table */
        if (vi_counter_incr(&vih->screenres, buf) == 0)
            return 1;
        /* ... and the screen color depth one. */
        if (vi_counter_incr(&vih->screendepth, p) == 0)
            return 1;
    }
parseerror:
    return 0;
}

/* Process accesses with the referer from google.
 * This is used to populate the keyphrases hashtable.
 * TODO: url decoding */
int vi_process_google_keyphrases(struct vih *vih, char *ref, time_t age)
{
	char *s, *p, *e;
	int res, page;
	char urldecoded[VI_LINE_MAX];
	char buf[64];

	if (!vi_is_google_link(ref)) return 0;
        /* Try to process gogoe human language info first. */
        if (Config_process_google_human_language) {
            s = strstr(ref+18, "&hl=");
            if (s == NULL) s = strstr(ref+18, "?hl=");
            if (s && s[4] && s[5]) {
                buf[0] = s[4];
                buf[1] = s[5];
                buf[2] = '\0';
	        if (vi_counter_incr(&vih->googlehumanlanguage, buf) == 0)
                    return 1;
            }
        }

	/* It's possible to start the search for the query 18 chars
	 * after the start of the referer because all the
	 * google links will start with "http://www.google.". */
	if ((s = strstr(ref+18, "?q=")) == NULL &&
	    (s = strstr(ref+18, "&q=")) == NULL) return 0;
	if ((p = strstr(ref+18, "&start=")) == NULL)
		p = strstr(ref+18, "?start=");
	if ((e = strchr(s+3, '&')) != NULL)
		*e = '\0';
	if (p && (e = strchr(p+7, '&')) != NULL)
		*e = '\0';
	if (!strncmp(s+3, "cache:", 6))
		return !vi_counter_incr(&vih->googlekeyphrases, "Google Cache Access");
	vi_urldecode(urldecoded, s+3, VI_LINE_MAX);
	vi_strtolower(urldecoded);
	page = p ? (1+(atoi(p+7)/10)) : 1;
	snprintf(buf, 64, " (page %d)", page);
	buf[63] = '\0';
	vi_strlcat(urldecoded, buf, VI_LINE_MAX);
	res = vi_counter_incr(&vih->googlekeyphrases, urldecoded);
	if (e) *e = '&';
	if (res == 0) return 1;
	/* Process keyphrases by first time */
	if (Config_process_google_keyphrases_age) {
		if (vi_replace_if_older(&vih->googlekeyphrasesage,
					urldecoded, age)) return 1;
	}
	return 0;
}

/* Process robots information. For visitors every client accessing
 * to robots.txt is considered a robot.
 * Returns 1 on out of memory, otherwise zero is returned. */
int vi_process_robots(struct vih *vih, char *req, char *agent)
{
	if (strncmp(req, "/robots.txt", 11) != 0) return 0;
	if (strstr(agent, "MSIECrawler")) return 0;
	return !vi_counter_incr(&vih->robots, agent);
}

/* Process referer -> request pairs for web trails */
int vi_process_web_trails(struct vih *vih, char *ref, char *req)
{
	int res, plen, google;
	char buf[VI_LINE_MAX];
	char *src;

	if (vi_is_image(req)) return 0;
	plen = vi_is_internal_link(ref);
	google = vi_is_google_link(ref);
	if (plen) {
		src = (ref[plen] == '\0') ? "/" : ref+plen;
	} else if (google) {
		if (Config_graphviz_ignorenode_google) return 0;
		src = "Google";
	} else if (ref[0] != '\0') {
		if (Config_graphviz_ignorenode_external) return 0;
		src = "External Link";
	} else {
		if (Config_graphviz_ignorenode_noreferer) return 0;
		src = "No Referer";
	}
	if (!strcmp(src, req)) return 0; /* avoid self references */

	snprintf(buf, VI_LINE_MAX, "%s -> %s", src, req);
	buf[VI_LINE_MAX-1] = '\0';
	res = vi_counter_incr(&vih->trails, buf);
	if (res == 0) return 1;
	return 0;
}

/* Process Top Level Domains.
 * Returns zero on success. Non zero is returned on out of memory. */
int vi_process_tld(struct vih *vih, char *hostname)
{
	char *tld;
	int res;

	if (vi_is_numeric_address(hostname)) {
		tld = "numeric IP";
	} else {
		tld = strrchr(hostname, '.');
		if (!tld) return 0;
		tld++;
	}
	res = vi_counter_incr(&vih->tld, tld);
	if (res == 0) return 1;
	return 0;
}

/* Match a log line against --grep and --exclude patters to check
 * if the line must be processed or not. */
int vi_match_line(char *line)
{
    int i;

    for (i = 0; i < Config_grep_pattern_num; i++) {
        char *pattern = Config_grep_pattern[i].pattern;
        int nocase = 1;

        /* Patterns starting with 'cs:' are matched in a case-sensitive
         * way after the 'cs:' prefix is discarded. */
        if (pattern[0] == 'c' && pattern[1] == 's' && pattern[2] == ':') {
            nocase = 0;
            pattern += 3;
        }
        if (vi_match(Config_grep_pattern[i].pattern, line, nocase)) {
            if (Config_grep_pattern[i].type == VI_PATTERNTYPE_EXCLUDE)
                return 0;
        } else {
            if (Config_grep_pattern[i].type == VI_PATTERNTYPE_GREP)
                return 0;
        }
    }
    return 1;
}

/* Process a line of log. Returns non-zero on error. */
int vi_process_line(struct vih *vih, char *l)
{
	struct logline ll;
	char origline[VI_LINE_MAX];

        /* Test the line against --grep --exclude patterns before
         * to process it. */
        if (Config_grep_pattern_num) {
            if (vi_match_line(l) == 0)
                return 0; /* No match? skip. */
        }

	vih->processed++;
	/* Take a copy of the original log line before to
	 * copy it. Will be useful for some processing.
	 * Do it only if required in order to speedup. */
	if (Config_process_error404 || Config_debug)
		vi_strlcpy(origline, l, VI_LINE_MAX);
	/* Split the line and run all the selected processing. */
	if (vi_parse_line(&ll, l) == 0) {
		int seen, is404;

                /* We process 404 errors first, in order to skip
                 * all the other reports if --ignore-404 option is active. */
		if (Config_process_error404 &&
		    vi_process_error404(vih, origline, ll.req, &is404))
                        goto oom;
                /* Process screen info if needed. */
                if (Config_process_screen_info && is404)
                    if (vi_process_screen_info(vih, ll.req)) goto oom;
                /* 404 error AND --ignore-404? Stop processing of this line. */
                if (Config_ignore_404 && is404)
                    return 0;

                /* Now it's time to process unique visitors. The 'save'
                 * local var saves if this log line is about a new visit
                 * or not. Some report is generated only against the first
                 * line of every visitor, other reports are generated
                 * for every single log line. */
		if (vi_process_visitors_per_day(vih, ll.host, ll.agent,
					ll.date, ll.ref, ll.req, &seen))
			goto oom;

		/* The following are processed for every log line */
		if (vi_process_page_request(vih, ll.req)) goto oom;
		if (Config_process_google &&
		    vi_process_googled(vih, ll.req, ll.agent, ll.time))
			goto oom;
		if (Config_process_web_trails &&
		    vi_process_web_trails(vih, ll.ref, ll.req)) goto oom;
		if (Config_process_google_keyphrases &&
		    vi_process_google_keyphrases(vih, ll.ref, ll.time))
			goto oom;

		/* The following are processed only for new visits */
		if (seen) return 0;
		vi_process_date_and_hour(vih, (ll.tm.tm_wday+6)%7,
				ll.tm.tm_hour);
		vi_process_month_and_day(vih, ll.tm.tm_mon, ll.tm.tm_mday-1);
		if (vi_process_referer(vih, ll.ref, ll.time)) goto oom;
		if (Config_process_agents &&
		    vi_process_agents(vih, ll.agent)) goto oom;
		if (Config_process_os &&
		    vi_process_os(vih, ll.agent)) goto oom;
		if (Config_process_browsers &&
		    vi_process_browsers(vih, ll.agent)) goto oom;
		if (Config_process_tld &&
		    vi_process_tld(vih, ll.host)) goto oom;
		if (Config_process_robots &&
		    vi_process_robots(vih, ll.req, ll.agent)) goto oom;
		return 0;
	} else {
		vih->invalid++;
                if (Config_debug)
                    fprintf(stderr, "Invalid line: %s\n", origline);
		return 0;
	}
oom:
	vi_set_error(vih, "Out of memory processing data");
	return 1;
}

/* Process the specified log file. Returns zero on success.
 * On error non zero is returned and an error is set in the handle. */
int vi_scan(struct vih *vih, char *filename)
{
	FILE *fp;
	char buf[VI_LINE_MAX];
	int use_stdin = 0;

	if (filename[0] == '-' && filename[1] == '\0') {
		/* If we are in stream mode, just return. Stdin
		 * is implicit in this mode and will be read
		 * after all the other files are processed. */
		if (Config_stream_mode) return 0;
		fp = stdin;
		use_stdin = 1;
	} else {
		if ((fp = fopen(filename, "r")) == NULL) {
			vi_set_error(vih, "Unable to open '%s': '%s'", filename, strerror(errno));
			return 1;
		}
	}
	while (fgets(buf, VI_LINE_MAX, fp) != NULL) {
		if (vi_process_line(vih, buf)) {
			fclose(fp);
			fprintf(stderr, "%s: %s\n", filename, vi_get_error(vih));
			return 1;
		}
	}
	if (!use_stdin)
		fclose(fp);
	vih->endt = time(NULL);
	return 0;
}

/* Postprocessing of pageviews per visit data.
 * The source hashtable entries are in the form: uniqe-visitor -> pageviews.
 * After the postprocessing we obtain another hashtable in the form:
 * pageviews-range -> quantity. This hashtable can be used directly
 * with generic output functions to generate the output. */
int vi_postprocess_pageviews(struct vih *vih)
{
	void **table;
	int len = ht_used(&vih->pageviews), i;

	if ((table = ht_get_array(&vih->pageviews)) == NULL) {
		fprintf(stderr, "Out of memory in vi_postprocess_pageviews()\n");
		return 1;
	}
	/* Run the hashtable in order to populate 'pageviews_grouped' */
	for (i = 0; i < len; i++) {
		int pv = (long) table[(i*2)+1]; /* pageviews of visit */
		int res;
		char *key;

		if (pv == 1) key = "1";
		else if (pv == 2) key = "2";
		else if (pv == 3) key = "3";
		else if (pv == 4) key = "4";
		else if (pv == 5) key = "5";
		else if (pv == 6) key = "6";
		else if (pv == 7) key = "7";
		else if (pv == 8) key = "8";
		else if (pv == 9) key = "9";
		else if (pv == 10) key = "10";
		else if (pv >= 11 && pv <= 20) key = "11-20";
		else if (pv >= 21 && pv <= 30) key = "21-30";
		else key = "> 30";

		res = vi_counter_incr(&vih->pageviews_grouped, key);
		if (res == 0) {
			free(table);
			return 1; /* out of memory */
		}
	}
	free(table);
	return 0;
}

/* This function is called from vi_print_report() in order to
 * run some postprocessing to raw data collected needed to generate reports. */
int vi_postprocess(struct vih *vih)
{
	if (vi_postprocess_pageviews(vih)) goto oom;
	return 0;
oom:
	vi_set_error(vih, "Out of memory");
	return 1;
}

/* ---------------------------- text output module -------------------------- */
void om_text_print_header(FILE *fp)
{
	fp = fp;
	return;
}

void om_text_print_footer(FILE *fp)
{
	fp = fp;
	return;
}

void om_text_print_title(FILE *fp, char *title)
{
	fprintf(fp, "=== %s ===\n", title);
}

void om_text_print_subtitle(FILE *fp, char *subtitle)
{
	fprintf(fp, "--- %s\n", subtitle);
}

void om_text_print_numkey_info(FILE *fp, char *key, int val)
{
	fprintf(fp, "* %s: %d\n", key, val);
}

void om_text_print_keykey_entry(FILE *fp, char *key1, char *key2, int num)
{
	fprintf(fp, "%d)    %s: %s\n", num, key1, key2);
}

void om_text_print_numkey_entry(FILE *fp, char *key, int val, char *link,
		int num)
{
	link = link; /* avoid warning. Text output don't use this argument. */
	fprintf(fp, "%d)    %s: %d\n", num, key, val);
}

/* Print a bar, c1 and c2 are the colors of the left and right parts.
 * Max is the maximum value of the bar, the bar length is printed
 * to be porportional to max. tot is the "total" needed to compute
 * the precentage value. */
void om_text_print_bar(FILE *fp, int max, int tot, int this, int cols,
		char c1, char c2)
{
	int l;
	float p;
	char *bar;
	if (tot == 0) tot++;
	if (max == 0) max++;
	l = ((float)(cols*this))/max;
	p = ((float)(100*this))/tot;
	bar = malloc(cols+1);
	if (!bar) return;
	memset(bar, c2, cols+1);
	memset(bar, c1, l);
	bar[cols] = '\0';
	fprintf(fp, "%s %02.1f%%", bar, p);
	free(bar);
}

void om_text_print_numkeybar_entry(FILE *fp, char *key, int max, int tot, int this)
{
	fprintf(fp, "   %-12s: %-9d |", key, this);
	om_text_print_bar(fp, max, tot, this, 44, '#', ' ');
	fprintf(fp, "\n");
}

void om_text_print_numkeycomparativebar_entry(FILE *fp, char *key, int tot, int this)
{
	fprintf(fp, "   %s: %-10d |", key, this);
	om_text_print_bar(fp, tot, tot, this, 44, '#', '.');
	fprintf(fp, "\n");
}

void om_text_print_bidimentional_map(FILE *fp, int xlen, int ylen,
			char **xlabel, char **ylabel, int *value)
{
	char *asciipal = " .-+#";
	int pallen = strlen(asciipal);
	int x, y, l, max = 0;

	/* Get the max value */
	l = xlen*ylen;
	for (x = 0; x < l; x++)
		if (max < value[x])
			max = value[x];
	if (max == 0) max++; /* avoid division by zero */
	/* print the map */
	for (y = 0; y < ylen; y++) {
		fprintf(fp, "%15s: ", ylabel[y]);
		for (x = 0; x < xlen; x++) {
			int coloridx;
			int val = value[(y*xlen)+x];

			coloridx = ((pallen-1)*val)/max;
			fputc(asciipal[coloridx], fp);
		}
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
	/* print the x-labels in vertical */
	{
		char **p = malloc(sizeof(char*)*xlen);
		/* The 'p' pointers array is initialized at the
		 * start of all the x-labels. */
		for (x = 0; x < xlen; x++)
			p[x] = xlabel[x];
		while(1) {
			int sentinel = 0;
			fprintf(fp, "%15s  ", "");
			for (x = 0; x < xlen; x++) {
				if (*(p[x]) != '\0') {
					fputc(*(p[x]), fp);
					p[x]++;
					sentinel++;
				} else {
					fputc(' ', fp);
				}
			}
			fputc('\n', fp);
			if (sentinel == 0) break;
		}
		free(p);
	}
}

void om_text_print_hline(FILE *fp)
{
	fprintf(fp, "\n");
}

void om_text_print_credits(FILE *fp)
{
	fprintf(fp, "Statistics generated with VISITORS version %s\n"
	       "http://www.hping.org/visitors for more information\n",
	       VI_VERSION_STR);
}

void om_text_print_report_link(FILE *fp, char *report)
{
	fprintf(fp, "-> %s\n", report);
	return;
}

struct outputmodule OutputModuleText = {
	om_text_print_header,
	om_text_print_footer,
	om_text_print_title,
	om_text_print_subtitle,
	om_text_print_numkey_info,
	om_text_print_keykey_entry,
	om_text_print_numkey_entry,
	om_text_print_numkeybar_entry,
	om_text_print_numkeycomparativebar_entry,
	om_text_print_bidimentional_map,
	om_text_print_hline,
	om_text_print_credits,
	om_text_print_report_link,
};

/* ---------------------------- html output module -------------------------- */
/* Use html entities for special chars. Abbreviates at 'maxlen' if needed. */
void om_html_entities_abbr(FILE *fp, char *s, int maxlen)
{
	while(*s) {
		if (maxlen-- == 0) {
			fprintf(fp, "...");
			break;
		}
		switch(*s) {
		case '\'': fprintf(fp, "&#39;"); break;
		case '"': fprintf(fp, "&#34;"); break;
		case '&': fprintf(fp, "&amp;"); break;
		case '<': fprintf(fp, "&lt;"); break;
		case '>': fprintf(fp, "&gt;"); break;
		default: fputc(*s, fp); break;
		}
		s++;
	}
}

/* A wrapper to om_html_entities_abbr() with a fixed abbreviation length */
void om_html_entities(FILE *fp, char *s)
{
	om_html_entities_abbr(fp, s, VI_HTML_ABBR_LEN);
}

void om_html_print_header(FILE *fp)
{
	fprintf(fp,
"<html>\n"
"<head>\n"
"<style>\n"
"BODY, TD, B, LI, U, DIV, SPAN {\n"
"	background-color: #ffffff;\n"
"	color: #000000;\n"
"	font-family: Verdana, Arial, Helvetica, Sans-Serif;\n"
"	font-size: 10px;\n"
"}\n"
"A {\n"
"	color: #0066ff;\n"
"	text-decoration: none;\n"
"}\n"
"A:visited {\n"
"	color: #000099;\n"
"	text-decoration: none;\n"
"}\n"
"A:active {\n"
"	color: #26a0be;\n"
"	text-decoration: none;\n"
"}\n"
"A:hover {\n"
"	color: #ffffff;\n"
"	text-decoration: none;\n"
"	background-color: #26a0be;\n"
"}\n"
".barfill {\n"
"	background-color: #96ef94;\n"
"	border-left: 1px;\n"
"	border-right: 1px;\n"
"	border-top: 1px;\n"
"	border-bottom: 1px;\n"
"	border-color: #4c934a;\n"
"	border-style: solid;\n"
"	font-size: 10px;\n"
"	height: 3px;\n"
"	line-height: 4px;\n"
"}\n"
".barempty {\n"
"	font-size: 10px;\n"
"	line-height: 4px;\n"
"}\n"
".barleft {\n"
"	background-color: #ff9696;\n"
"	border-left: 1px;\n"
"	border-right: 1px;\n"
"	border-top: 1px;\n"
"	border-bottom: 1px;\n"
"	border-color: #4c934a;\n"
"	border-style: solid;\n"
"	font-size: 10px;\n"
"	height: 3px;\n"
"	line-height: 4px;\n"
"}\n"
".barright {\n"
"	background-color: #f8f8f8;\n"
"	border-left: 0px;\n"
"	border-right: 1px;\n"
"	border-top: 1px;\n"
"	border-bottom: 1px;\n"
"	border-color: #4c934a;\n"
"	border-style: solid;\n"
"	font-size: 10px;\n"
"	height: 3px;\n"
"	line-height: 4px;\n"
"}\n"
".title {\n"
"	background-color: #007f9e;\n"
"	font-size: 12px;\n"
"	font-weight: bold;\n"
"	padding: 3px;\n"
"	color: #ffffff;\n"
"}\n"
".reportlink {\n"
"	background-color: #ffffff;\n"
"	font-size: 12px;\n"
"	font-weight: bold;\n"
"	color: #000000;\n"
"	padding-left: 3px;\n"
"}\n"
".subtitle {\n"
"	background-color: #007f9e;\n"
"	font-size: 12px;\n"
"	font-weight: normal;\n"
"	padding: 3px;\n"
"	color: #ffffff;\n"
"}\n"
".info {\n"
"	background-color: #badfee;\n"
"	font-size: 12px;\n"
"	padding-left: 3px;\n"
"	padding-right: 3px;\n"
"}\n"
".keyentry {\n"
"	font-size: 10px;\n"
"	padding-left: 2px;\n"
"	border-bottom: 1px dashed #bcbcbc;\n"
"}\n"
".keyentrywe {\n"
"	background-color: #f0f090;\n"
"	font-size: 10px;\n"
"	padding-left: 2px;\n"
"	border-bottom: 1px dashed #bcbcbc;\n"
"}\n"
".valueentry {\n"
"	font-size: 10px;\n"
"	padding-left: 2px;\n"
"	color: #905d14;\n"
"	border-bottom: 1px dashed #f6c074;\n"
"}\n"
".credits {\n"
"	font-size: 12px;\n"
"	font-weight: bold;\n"
"}\n"
".maintable {\n"
"	border-style: solid;\n"
"	border-color: #0b4b5b;\n"
"	border-width: 1px;\n"
"}\n"
"</style>\n"
"</head>\n"
"<body><table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" class=\"maintable\">\n"
	);
}

void om_html_print_footer(FILE *fp)
{
	fprintf(fp, "</table></body></html>\n");
}

void om_html_print_title(FILE *fp, char *title)
{
	fprintf(fp, "<tr><td align=\"center\" class=\"title\" colspan=\"3\"><a name=\"%s\"></a>", title);
	om_html_entities(fp, title);
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_subtitle(FILE *fp, char *subtitle)
{
	fprintf(fp, "<tr><td align=\"center\" class=\"subtitle\" colspan=\"3\">");
	om_html_entities(fp, subtitle);
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_numkey_info(FILE *fp, char *key, int val)
{
	fprintf(fp, "<tr><td align=\"left\" colspan=\"3\" class=\"info\">");
	om_html_entities(fp, key);
	fprintf(fp, " %d", val);
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_keykey_entry(FILE *fp, char *key1, char *key2, int num)
{
	fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	fprintf(fp, "%d)", num);
	fprintf(fp, "<td align=\"left\" class=\"valueentry\">");
	om_html_entities(fp, key1);
	fprintf(fp, "</td><td align=\"left\" class=\"keyentry\">");
	if (!strncmp(key2, "http://", 7)) {
		fprintf(fp, "<a class=\"url\" href=\"%s\">", key2);
		om_html_entities(fp, key2);
		fprintf(fp, "</a>");
	} else {
		om_html_entities(fp, key2);
	}
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_numkey_entry(FILE *fp, char *key, int val, char *link,
		int num)
{
	fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	fprintf(fp, "%d)", num);
	fprintf(fp, "<td align=\"left\" class=\"valueentry\">");
	fprintf(fp, "%d", val);
	fprintf(fp, "</td><td align=\"left\" class=\"keyentry\">");
	if (link != NULL) {
		fprintf(fp, "<a class=\"url\" href=\"%s\">", link);
		om_html_entities(fp, key);
		fprintf(fp, "</a>");
	} else if (!strncmp(key, "http://", 7)) {
		fprintf(fp, "<a class=\"url\" href=\"%s\">", key);
		om_html_entities(fp, key);
		fprintf(fp, "</a>");
	} else {
		om_html_entities(fp, key);
	}
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_bar(FILE *fp, int l, char *leftclass, char *rightclass)
{
	fprintf(fp, "<table cellpadding=\"0\" cellspacing=\"0\" width=\"400\" border=\"0\">\n");
	fprintf(fp, "<tr><td align=\"center\" class=\"%s\" width=\"%d%%\">%s</td>\n", leftclass, l, l ? "&nbsp;" : "");
	fprintf(fp, "<td align=\"center\" class=\"%s\" width=\"%d%%\">%s</td></tr>\n", rightclass, 100-l, (l!=100) ? "&nbsp;" : "");
	fprintf(fp, "</table>\n");
}

void om_html_print_numkeybar_entry(FILE *fp, char *key, int max, int tot, int this)
{
	int l, weekend;
	float p;

	if (tot == 0) tot++;
	if (max == 0) max++;
	l = ((float)(100*this))/max;
	p = ((float)(100*this))/tot;
	weekend = vi_is_weekend(key);

	if (weekend)
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentrywe\">");
	else
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	om_html_entities(fp, key);
	fprintf(fp, "&nbsp;&nbsp;&nbsp;</td><td align=\"left\" class=\"valueentry\">");
	fprintf(fp, "%d (%02.1f%%)", this, p);
	fprintf(fp, "</td><td align=\"left\" class=\"bar\">");
	om_html_print_bar(fp, l, "barfill", "barempty");
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_numkeycomparativebar_entry(FILE *fp, char *key, int tot, int this)
{
	int l, weekend;
	float p;

	if (tot == 0) tot++;
	p = ((float)(100*this))/tot;
	l = (int) p;
	weekend = vi_is_weekend(key);

	if (weekend)
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentrywe\">");
	else
		fprintf(fp, "<tr><td align=\"left\" class=\"keyentry\">");
	om_html_entities(fp, key);
	fprintf(fp, "&nbsp;&nbsp;&nbsp;</td><td align=\"left\" class=\"valueentry\">");
	fprintf(fp, "%d (%02.1f%%)", this, p);
	fprintf(fp, "</td><td align=\"left\" class=\"bar\">");
	om_html_print_bar(fp, l, "barleft", "barright");
	fprintf(fp, "</td></tr>\n");
}

void om_html_print_bidimentional_map(FILE *fp, int xlen, int ylen,
			char **xlabel, char **ylabel, int *value)
{
	int x, y, l, max = 0;

	/* Get the max value */
	l = xlen*ylen;
	for (x = 0; x < l; x++)
		if (max < value[x])
			max = value[x];
	if (max == 0) max++; /* avoid division by zero */
	/* print the map */
	fprintf(fp, "<tr><td colspan=\"3\" align=\"center\">");
	fprintf(fp, "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">");
	for (y = 0; y < ylen; y++) {
		fprintf(fp, "<tr>");
		fprintf(fp, "<td class=\"valueentry\">%s</td>", ylabel[y]);
		for (x = 0; x < xlen; x++) {
			int r, g, b;
			int val = value[(y*xlen)+x];

			r = (0xAA*val)/max;
			g = (0xBB*val)/max;
			b = (0xFF*val)/max;
			fprintf(fp, "<td style=\"background-color: #%02X%02X%02X;\" title=\"%d\">&nbsp;</td>\n", r, g, b, val);
		}
		fprintf(fp, "</tr>\n");
	}
	fprintf(fp, "<tr><td>&nbsp;</td>");
	for (x = 0; x < xlen; x++) {
		fprintf(fp, "<td class=\"keyentry\">%s</td>", xlabel[x]);
	}
	fprintf(fp, "</tr></table></td></tr>");
}

void om_html_print_hline(FILE *fp)
{
	fprintf(fp, "<tr><td colspan=\"3\">&nbsp;</td></tr>");
}

void om_html_print_credits(FILE *fp)
{
	fprintf(fp, "<tr><td colspan=\"3\" align=\"center\" class=\"credits\">Statistics generated with <a href=\"http://www.hping.org/visitors\">VISITORS Web Log Analyzer</a> version %s\n</td></tr>", VI_VERSION_STR);
}

void om_html_print_report_link(FILE *fp, char *report)
{
	fprintf(fp, "<tr><td align=\"left\" class=\"reportlink\" colspan=\"3\"><a href=\"#%s\">", report);
	om_html_entities(fp, report);
	fprintf(fp, "</a></td></tr>\n");
	return;
}

struct outputmodule OutputModuleHtml = {
	om_html_print_header,
	om_html_print_footer,
	om_html_print_title,
	om_html_print_subtitle,
	om_html_print_numkey_info,
	om_html_print_keykey_entry,
	om_html_print_numkey_entry,
	om_html_print_numkeybar_entry,
	om_html_print_numkeycomparativebar_entry,
	om_html_print_bidimentional_map,
	om_html_print_hline,
	om_html_print_credits,
	om_html_print_report_link,
};


/* ---------------------------------- output -------------------------------- */
void vi_print_statistics(struct vih *vih)
{
	time_t elapsed = vih->endt - vih->startt;

	if (elapsed == 0) elapsed++;
	fprintf(stderr, "--\n%d lines processed in %ld seconds\n"
	       "%d invalid lines, %d blacklisted referers\n",
			vih->processed, (long) elapsed,
			vih->invalid, vih->blacklisted);
}

void vi_print_hours_report(FILE *fp, struct vih *vih)
{
	int i, max = 0, tot = 0;
	for (i = 0; i < 24; i++) {
		if (vih->hour[i] > max)
			max = vih->hour[i];
		tot += vih->hour[i];
	}
	Output->print_title(fp, "Hours distribution");
	Output->print_subtitle(fp, "Percentage of hits in every hour of the day");
	for (i = 0; i < 24; i++) {
		char buf[8];
		sprintf(buf, "%02d", i);
		Output->print_numkeybar_entry(fp, buf, max, tot, vih->hour[i]);
	}
}

void vi_print_weekdays_report(FILE *fp, struct vih *vih)
{
	int i, max = 0, tot = 0;
	for (i = 0; i < 7; i++) {
		if (vih->weekday[i] > max)
			max = vih->weekday[i];
		tot += vih->weekday[i];
	}
	Output->print_title(fp, "Weekdays distribution");
	Output->print_subtitle(fp, "Percentage of hits in every day of the week");
	for (i = 0; i < 7; i++) {
		Output->print_numkeybar_entry(fp, vi_wdname[i], max, tot, vih->weekday[i]);
	}
}

/* Generic function for qsort(3) called to sort a table.
 * this function is actually only used by the following wrappers. */
int qsort_cmp_dates_generic(const void *a, const void *b, int off, int mul)
{
	time_t ta, tb;
	void **A = (void**) a;
	void **B = (void**) b;
	char *dateA = (char*) *(A+off);
	char *dateB = (char*) *(B+off);

	ta = parse_date(dateA, NULL);
	tb = parse_date(dateB, NULL);
	if (ta == (time_t)-1 && tb == (time_t)-1) return 0;
	if (ta == (time_t)-1) return 1*mul;
	if (tb == (time_t)-1) return -1*mul;
	if (ta > tb) return 1*mul;
	if (ta < tb) return -1*mul;
	return 0;
}

/* Compare dates in the log format: hashtable key part version */
int qsort_cmp_dates_key(const void *a, const void *b)
{
	return qsort_cmp_dates_generic(a, b, 0, 1);
}

/* Compare dates (only the month/year part) in the log format:
 * hashtable key part version */
int qsort_cmp_months_key(const void *a, const void *b)
{
	int ret;
	char dateA[VI_DATE_MAX];
	char dateB[VI_DATE_MAX];
	void *savedA, *savedB; /* backups of the original pointers */
	void **A = (void**) a;
	void **B = (void**) b;

	/* We use an hack here, in order to call qsort_cmp_dates_generic
	 * even in this case, we substitute the hashtable entries
	 * with versions of the strings prefixed with "01", so they
	 * will be parseble by parse_date().
	 * In pratice for "May/2004" we instead put "01/May/2004" and so on. */
	savedA = *A;
	savedB = *B;
	dateA[0] = dateB[0] = '0';
	dateA[1] = dateB[1] = '1';
	dateA[2] = dateB[2] = '/';
	dateA[3] = dateB[3] = '\0';
	vi_strlcat(dateA, (char*)*A, VI_DATE_MAX);
	vi_strlcat(dateB, (char*)*B, VI_DATE_MAX);
	*A = dateA;
	*B = dateB;
	ret = qsort_cmp_dates_generic(a, b, 0, 1);
	/* Restore */
	*A = savedA;
	*B = savedB;
	return ret;
}

/* Compare dates in the log format: hashtable value part version.
 * this sorts in reverse order, more recent dates first. */
int qsort_cmp_dates_value(const void *a, const void *b)
{
	return qsort_cmp_dates_generic(a, b, 1, -1);
}

int qsort_cmp_long_value(const void *a, const void *b)
{
	void **A = (void**) a;
	void **B = (void**) b;
	long la = (long) *(A+1);
	long lb = (long) *(B+1);
	if (la > lb) return -1;
	if (lb > la) return 1;
	return 0;
}

int qsort_cmp_time_value(const void *a, const void *b)
{
	void **A = (void**) a;
	void **B = (void**) b;
	time_t ta = (time_t) *(A+1);
	time_t tb = (time_t) *(B+1);
	if (ta > tb) return -1;
	if (tb > ta) return 1;
	return 0;
}

void vi_print_visits_report(FILE *fp, struct vih *vih)
{
	int days = ht_used(&vih->date), i, tot = 0, max = 0;
	int months;
	void **table;

	Output->print_title(fp, "Unique visitors in each day");
	Output->print_subtitle(fp, "Multiple hits with the same IP, user agent and access day, are considered a single visit");
	Output->print_numkey_info(fp, "Number of unique visitors",
			ht_used(&vih->visitors));
	Output->print_numkey_info(fp, "Different days in logfile",
			ht_used(&vih->date));
	
	if ((table = ht_get_array(&vih->date)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_visits_report()\n");
		return;
	}
	qsort(table, days, sizeof(void*)*2, qsort_cmp_dates_key);
	for (i = 0; i < days; i++) {
		long value = (long) table[(i*2)+1];
		if (value > max)
			max = value;
		tot += value;
	}
	for (i = 0; i < days; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);
        Output->print_hline(fp);

	/* Montly */
	if (Config_process_monthly_visitors == 0) return;
	tot = max = 0;
	months = ht_used(&vih->month);
	Output->print_title(fp, "Unique visitors in each month");
	Output->print_subtitle(fp, "Multiple hits with the same IP, user agent and access day, are considered a single visit");
	Output->print_numkey_info(fp, "Number of unique visitors",
			ht_used(&vih->visitors));
	Output->print_numkey_info(fp, "Different months in logfile",
			ht_used(&vih->month));
	
	if ((table = ht_get_array(&vih->month)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_visits_report()\n");
		return;
	}
	qsort(table, months, sizeof(void*)*2, qsort_cmp_months_key);
	for (i = 0; i < months; i++) {
		long value = (long) table[(i*2)+1];
		if (value > max)
			max = value;
		tot += value;
	}
	for (i = 0; i < months; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);
}

/* A report to compare visits originating from google VS all the rest. */
void vi_print_googlevisits_report(FILE *fp, struct vih *vih)
{
	int days = ht_used(&vih->date), i, months;
	void **table;

	Output->print_title(fp, "Unique visitors from Google in each day");
	Output->print_subtitle(fp, "The red part of the bar expresses the percentage of visits originated from Google");
	Output->print_numkey_info(fp, "Number of unique visitors",
			ht_used(&vih->visitors));
	Output->print_numkey_info(fp, "Number of unique visitors from google",
			ht_used(&vih->googlevisitors));
	Output->print_numkey_info(fp, "Different days in logfile",
			ht_used(&vih->date));
	
	if ((table = ht_get_array(&vih->date)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_visits_report()\n");
		return;
	}
	qsort(table, days, sizeof(void*)*2, qsort_cmp_dates_key);
	for (i = 0; i < days; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		long googlevalue;

		googlevalue = vi_counter_val(&vih->googledate, key);
		Output->print_numkeycomparativebar_entry(fp, key, value, googlevalue);
	}
	free(table);
        Output->print_hline(fp);

	/* Montly */
	if (Config_process_monthly_visitors == 0) return;
	months = ht_used(&vih->month);
	Output->print_title(fp, "Unique visitors from Google in each month");
	Output->print_subtitle(fp, "The red part of the bar expresses the percentage of visits originated from Google");
	Output->print_numkey_info(fp, "Number of unique visitors",
			ht_used(&vih->visitors));
	Output->print_numkey_info(fp, "Number of unique visitors from google",
			ht_used(&vih->googlevisitors));
	Output->print_numkey_info(fp, "Different months in logfile",
			ht_used(&vih->month));
	
	if ((table = ht_get_array(&vih->month)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_visits_report()\n");
		return;
	}
	qsort(table, months, sizeof(void*)*2, qsort_cmp_months_key);
	for (i = 0; i < months; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		long googlevalue;

		googlevalue = vi_counter_val(&vih->googlemonth, key);
		Output->print_numkeycomparativebar_entry(fp, key, value, googlevalue);
	}
	free(table);
}

void vi_print_generic_keyval_report(FILE *fp, char *title, char *subtitle,
		char *info, int maxlines,
		struct hashtable *ht,
		int(*compar)(const void *, const void *))
{
	int items = ht_used(ht), i;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out of memory in print_generic_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		if (i >= maxlines) break;
		if (key[0] == '\0')
			Output->print_numkey_entry(fp, "none", value, NULL,
					i+1);
		else
			Output->print_numkey_entry(fp, key, value, NULL, i+1);
	}
	free(table);
}

void vi_print_generic_keyvalbar_report(FILE *fp, char *title, char *subtitle,
		char *info, int maxlines,
		struct hashtable *ht,
		int(*compar)(const void *, const void *))
{
	int items = ht_used(ht), i, max = 0, tot = 0;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out of memory in print_generic_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		long value = (long) table[(i*2)+1];
		tot += value;
		if (value > max) max = value;
	}
	for (i = 0; i < items; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		if (i >= maxlines) break;
		if (key[0] == '\0')
			Output->print_numkeybar_entry(fp, "none", max, tot, value);
		else
			Output->print_numkeybar_entry(fp, key, max, tot, value);
	}
	free(table);
}

/* This is similar to the generic key/val report, but
 * different enough to be better served by a specific function. */
void vi_print_keyphrases_report(FILE *fp, char *title, char *subtitle,
		char *info, int maxlines,
		struct hashtable *ht,
		int(*compar)(const void *, const void *))
{
	int items = ht_used(ht), i;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out of memory in print_keyphrases_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		char *key = table[i*2];
		long value = (long) table[(i*2)+1];
		if (i >= maxlines) break;
		if (key[0] == '\0')
			Output->print_numkey_entry(fp, "none", value, NULL,
					i+1);
		else {
			char *p;
			char link[VI_LINE_MAX];
			char aux[VI_LINE_MAX];
			char encodedkey[VI_LINE_MAX];

			vi_strlcpy(link, "http://www.google.com/search?q=", VI_LINE_MAX);
			vi_strlcpy(aux, key, VI_LINE_MAX);
			p = strrchr(aux, '(');
			if (p) {
				if (p > aux) p--; /* seek the space on left */
				*p = '\0';
			}
			vi_urlencode(encodedkey, aux, VI_LINE_MAX);
			vi_strlcat(link, encodedkey, VI_LINE_MAX);
			Output->print_numkey_entry(fp, key, value, link, i+1);
		}
	}
	free(table);
}

void vi_print_referers_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"Referers",
			"Referers ordered by visits (google excluded)",
			"Different referers",
			Config_max_referers,
			&vih->referers,
			qsort_cmp_long_value);
}

void vi_print_pages_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"Requested pages",
			"Page requests ordered by hits",
			"Different pages requested",
			Config_max_pages,
			&vih->pages,
			qsort_cmp_long_value);
}

void vi_print_error404_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"404 Errors",
			"Requests for missing documents",
			"Different missing documents requested",
			Config_max_error404,
			&vih->error404,
			qsort_cmp_long_value);
}

void vi_print_pageviews_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyvalbar_report(
			fp,
			"Pageviews per visit",
			"Number of pages requested per visit",
			"Only documents are counted (not images). Reported ranges:",
			100,
			&vih->pageviews_grouped,
			qsort_cmp_long_value);
}

void vi_print_images_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"Requested images and CSS",
			"Images and CSS requests ordered by hits",
			"Different images and CSS requested",
			Config_max_images,
			&vih->images,
			qsort_cmp_long_value);
}

void vi_print_agents_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"User agents",
			"The entire user agent string ordered by visits",
			"Different agents",
			Config_max_agents,
			&vih->agents,
			qsort_cmp_long_value);
}

void vi_print_os_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyvalbar_report(
			fp,
			"Operating Systems",
			"Operating Systems by visits",
			"Different operating systems listed",
			100,
			&vih->os,
			qsort_cmp_long_value);
}

void vi_print_browsers_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyvalbar_report(
			fp,
			"Browsers",
			"Browsers used by visits",
			"Different browsers listed",
			100,
			&vih->browsers,
			qsort_cmp_long_value);
}

void vi_print_trails_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"Web trails",
			"Referer -> Target common moves",
			"Total number of trails",
			Config_max_trails,
			&vih->trails,
			qsort_cmp_long_value);
}

void vi_print_google_keyphrases_report(FILE *fp, struct vih *vih)
{
	vi_print_keyphrases_report(
			fp,
			"Google Keyphrases",
			"Keyphrases used in google searches ordered by visits",
			"Total number of keyphrases",
			Config_max_google_keyphrases,
			&vih->googlekeyphrases,
			qsort_cmp_long_value);
}

void vi_print_tld_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyvalbar_report(
			fp,
			"Domains",
			"Top Level Domains sorted by visits",
			"Total number of Top Level Domains",
			Config_max_tld,
			&vih->tld,
			qsort_cmp_long_value);
}

void vi_print_robots_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"Robots and web spiders",
			"Agents requesting robots.txt. MSIECrawler excluded.",
			"Total number of different robots",
			Config_max_robots,
			&vih->robots,
			qsort_cmp_long_value);
}

/* Print a generic report where the two report items are strings
 * (usually url and date). Used to print the 'googled' and 'referers age'
 * reports. */
void vi_print_generic_keytime_report(FILE *fp, char *title, char *subtitle,
		char *info, int maxlines,
		struct hashtable *ht,
		int(*compar)(const void *, const void *))
{
	int items = ht_used(ht), i;
	void **table;

	Output->print_title(fp, title);
	Output->print_subtitle(fp, subtitle);
	Output->print_numkey_info(fp, info, items);
	if ((table = ht_get_array(ht)) == NULL) {
		fprintf(stderr, "Out Of Memory in print_generic_keytime_report()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, compar);
	for (i = 0; i < items; i++) {
		struct tm *tm;
		char ftime[1024];
		char *url = table[i*2];
		time_t time = (time_t) table[(i*2)+1];
		if (i >= maxlines) break;
		tm = localtime(&time);
		if (tm) {
			ftime[0] = '\0';
			strftime(ftime, 1024, "%d/%b/%Y", tm);
			Output->print_keykey_entry(fp, ftime,
					(url[0] == '\0') ? "none" : url, i+1);
		}
	}
	free(table);
}

void vi_print_googled_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keytime_report(
			fp,
			"Googled pages",
			"Pages accessed by the Google crawler, last access reported",
			"Number of pages googled",
			Config_max_googled,
			&vih->googled,
			qsort_cmp_time_value);
}

void vi_print_adsensed_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keytime_report(
			fp,
			"Adsensed pages",
			"Pages accessed by the Adsense crawler, last access reported",
			"Number of pages adsensed",
			Config_max_adsensed,
			&vih->adsensed,
			qsort_cmp_time_value);
}

void vi_print_referers_age_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keytime_report(
			fp,
			"Referers by first time",
			"Referers ordered by first time date, newer on top (referers from google excluded)",
			"Different referers",
			Config_max_referers_age,
			&vih->referersage,
			qsort_cmp_time_value);
}

void vi_print_google_keyphrases_age_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keytime_report(
			fp,
			"Google Keyphrases by first time",
			"Keyphrases ordered by first time date, newer on top",
			"Different referers",
			Config_max_google_keyphrases_age,
			&vih->googlekeyphrasesage,
			qsort_cmp_time_value);
}

void vi_print_google_human_language_report(FILE *fp, struct vih *vih)
{
	vi_print_generic_keyval_report(
			fp,
			"Google Human Language",
			"The 'hl' field in the query string of google searches",
			"Different human languages",
			1000,
			&vih->googlehumanlanguage,
			qsort_cmp_long_value);
}

void vi_print_screen_res_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyval_report(
			fp,
			"Screen resolution",
			"user screen width x height resolution",
			"Different resolutions",
			1000,
			&vih->screenres,
			qsort_cmp_long_value);
}

void vi_print_screen_depth_report(FILE *fp, struct vih *vih) {
	vi_print_generic_keyval_report(
			fp,
			"Screen color depth",
			"user screen color depth in bits per pixel",
			"Different color depths",
			1000,
			&vih->screendepth,
			qsort_cmp_long_value);
}

void vi_print_information_report(FILE *fp, struct vih *vih)
{
	char buf[VI_LINE_MAX];
	time_t now = time(NULL);
	snprintf(buf, VI_LINE_MAX, "Generated: %s", ctime(&now));
	Output->print_title(fp, "General information");
	Output->print_subtitle(fp, "Information about analyzed log files");
	Output->print_subtitle(fp, buf);
	Output->print_numkey_info(fp, "Number of entries processed", vih->processed);
	Output->print_numkey_info(fp, "Number of invalid entries", vih->invalid);
	Output->print_numkey_info(fp, "Processing time in seconds", (vih->endt)-(vih->startt));
}

void vi_print_report_links(FILE *fp)
{
	void *l[] = {
	"Unique visitors in each day", NULL,
	"Unique visitors in each month", &Config_process_monthly_visitors,
	"Unique visitors from Google in each day", NULL,
	"Unique visitors from Google in each month", &Config_process_monthly_visitors,
	"Pageviews per visit", &Config_process_pageviews,
	"Weekday-Hour combined map", &Config_process_weekdayhour_map,
	"Month-Day combined map", &Config_process_monthday_map,
	"Requested pages", NULL,
	"Requested images and CSS", NULL,
	"Referers", NULL,
	"Referers by first time", &Config_process_referers_age,
	"Robots and web spiders", &Config_process_robots,
	"User agents", &Config_process_agents,
	"Operating Systems", &Config_process_os,
	"Browsers", &Config_process_browsers,
	"404 Errors", &Config_process_error404,
	"Domains", &Config_process_tld,
	"Googled pages", &Config_process_google,
	"Adsensed pages", &Config_process_google,
	"Google Keyphrases", &Config_process_google_keyphrases,
	"Google Keyphrases by first time", &Config_process_google_keyphrases_age,
	"Google Human Language", &Config_process_google_human_language,
        "Screen resolution", &Config_process_screen_info,
        "Screen color depth", &Config_process_screen_info,
	"Web trails", &Config_process_web_trails,
	"Weekday distribution", NULL,
	"Hours distribution", NULL,
	};
	unsigned int i, num = 0;

	Output->print_title(fp, "Generated reports");
	Output->print_subtitle(fp, "Click on the report name you want to see");
	for (i = 0; i < sizeof(l)/sizeof(void*); i += 2) {
		int active = l[i+1] == NULL ? 1 : *((int*)l[i+1]);
		if (active) num++;
	}
	Output->print_numkey_info(fp, "Number of reports generated", num);
	for (i = 0; i < sizeof(l)/sizeof(void*); i += 2) {
		int active = l[i+1] == NULL ? 1 : *((int*)l[i+1]);
		if (active)
			Output->print_report_link(fp, (char*)l[i]);
	}
}

void vi_print_weekdayhour_map_report(FILE *fp, struct vih *vih)
{
	char *xlabel[24] = {
		"00", "01", "02", "03", "04", "05", "06", "07",
		"08", "09", "10", "11", "12", "13", "14", "15",
		"16", "17", "18", "19", "20", "21", "22", "23"};
	char **ylabel = vi_wdname;
	int j, minj = 0, maxj = 0;
	int *hw = (int*) vih->weekdayhour;
	char buf[VI_LINE_MAX];

	/* Check idexes of minimum and maximum in the array. */
	for (j = 0; j < 24*7; j++) {
		if (hw[j] > hw[maxj])
			maxj = j;
		if (hw[j] < hw[minj])
			minj = j;
	}

	Output->print_title(fp, "Weekday-Hour combined map");
	Output->print_subtitle(fp, "Brighter means higher level of hits");
	snprintf(buf, VI_LINE_MAX, "Hour with max traffic starting at %s %s:00 with hits",
			ylabel[maxj/24], xlabel[maxj%24]);
	Output->print_numkey_info(fp, buf, hw[maxj]);
	snprintf(buf, VI_LINE_MAX, "Hour with min traffic starting at %s %s:00 with hits",
			ylabel[minj/24], xlabel[minj%24]);
	Output->print_numkey_info(fp, buf, hw[minj]);
	Output->print_hline(fp);
	Output->print_bidimentional_map(fp, 24, 7, xlabel, ylabel, hw);
}

void vi_print_monthday_map_report(FILE *fp, struct vih *vih)
{
	char *xlabel[31] = {
		"01", "02", "03", "04", "05", "06", "07", "08",
		"09", "10", "11", "12", "13", "14", "15", "16",
		"17", "18", "19", "20", "21", "22", "23", "24",
		"25", "26", "27", "28", "29", "30", "31"};
	char *ylabel[12] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};
	int j, minj = 0, maxj = 0;
	int *md = (int*) vih->monthday;
	char buf[VI_LINE_MAX];

	/* Check idexes of minimum and maximum in the array. */
	for (j = 0; j < 12*31; j++) {
		if (md[j] > md[maxj])
			maxj = j;
		if (md[j] != 0 && (md[j] < md[minj] || md[minj] == 0))
			minj = j;
	}

	Output->print_title(fp, "Month-Day combined map");
	Output->print_subtitle(fp, "Brighter means higher level of hits");
	snprintf(buf, VI_LINE_MAX, "Day with max traffic is %s %s with hits",
			ylabel[maxj/31], xlabel[maxj%31]);
	Output->print_numkey_info(fp, buf, md[maxj]);
	snprintf(buf, VI_LINE_MAX, "Day with min traffic is %s %s with hits",
			ylabel[minj/31], xlabel[minj%31]);
	Output->print_numkey_info(fp, buf, md[minj]);
	Output->print_hline(fp);
	Output->print_bidimentional_map(fp, 31, 12, xlabel, ylabel, md);
}

void vi_print_hline(FILE *fp)
{
	Output->print_hline(fp);
}

void vi_print_credits(FILE *fp)
{
	Output->print_credits(fp);
}

void vi_print_header(FILE *fp)
{
	Output->print_header(fp);
}

void vi_print_footer(FILE *fp)
{
	Output->print_footer(fp);
}

/* Generate the report writing it to the output file 'of'.
 * If op is NULL, output the report to standard output.
 * On success zero is returned. Otherwise the function returns
 * non-zero and set an error in the vih handler. */
int vi_print_report(char *of, struct vih *vih)
{
	FILE *fp;

	if (of == NULL) {
		fp = stdout;
	} else {
		fp = fopen(of, "w");
		if (fp == NULL) {
			vi_set_error(vih, "Writing the report to '%s': %s",
					of, strerror(errno));
			return 1;
		}
	}

        /* Disable specific reports when there is no data. */
        if (ht_used(&vih->screenres) == 0)
                Config_process_screen_info = 0;
	/* Do some data postprocessing needed to generate reports */
	if (vi_postprocess(vih))
		return 1;
	/* Report generation */
	vi_print_header(fp);
	vi_print_credits(fp);
	vi_print_hline(fp);
	vi_print_information_report(fp, vih);
	vi_print_hline(fp);
	vi_print_report_links(fp);
	vi_print_hline(fp);
	vi_print_visits_report(fp, vih);
	vi_print_hline(fp);
	vi_print_googlevisits_report(fp, vih);
	vi_print_hline(fp);
	if (Config_process_weekdayhour_map) {
		vi_print_weekdayhour_map_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_monthday_map) {
		vi_print_monthday_map_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_pageviews) {
		vi_print_pageviews_report(fp, vih);
		vi_print_hline(fp);
	}
	vi_print_pages_report(fp, vih);
	vi_print_hline(fp);
	vi_print_images_report(fp, vih);
	vi_print_hline(fp);
	vi_print_referers_report(fp, vih);
	vi_print_hline(fp);
	if (Config_process_referers_age) {
		vi_print_referers_age_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_robots) {
		vi_print_robots_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_agents) {
		vi_print_agents_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_os) {
		vi_print_os_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_browsers) {
		vi_print_browsers_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_error404) {
		vi_print_error404_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_tld) {
		vi_print_tld_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_google) {
		vi_print_googled_report(fp, vih);
		vi_print_hline(fp);
		vi_print_adsensed_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_google_keyphrases) {
		vi_print_google_keyphrases_report(fp, vih);
		vi_print_hline(fp);
	}
	if (Config_process_google_keyphrases) {
		vi_print_google_keyphrases_age_report(fp, vih);
		vi_print_hline(fp);
	}
        if (Config_process_google_human_language) {
		vi_print_google_human_language_report(fp, vih);
		vi_print_hline(fp);
        }
        if (Config_process_screen_info) {
                vi_print_screen_res_report(fp, vih);
                vi_print_hline(fp);
                vi_print_screen_depth_report(fp, vih);
                vi_print_hline(fp);
        }
	if (Config_process_web_trails) {
		vi_print_trails_report(fp, vih);
		vi_print_hline(fp);
	}
	vi_print_weekdays_report(fp, vih);
	vi_print_hline(fp);
	vi_print_hours_report(fp, vih);
	vi_print_hline(fp);
	vi_print_credits(fp);
	vi_print_hline(fp);
	vi_print_footer(fp);
	if (of != NULL)
		fclose(fp);
	return 0;
}

/* ------------------------- graphviz graph generation ---------------------- */
void vi_print_graphviz(struct vih *vih)
{
	int items = ht_used(&vih->trails), i, max = 0, tot = 0;
	void **table;

	printf("digraph webtrails {\n");
	printf("\tgraph [splines=true overlap=false rankdir=LR]\n");
	printf("\tnode [color=lightblue2,style=\"filled\"]\n");
	printf("\tedge [style=bold]\n");
	if ((table = ht_get_array(&vih->trails)) == NULL) {
		fprintf(stderr, "Out of memory in vi_print_graphviz()\n");
		return;
	}
	qsort(table, items, sizeof(void*)*2, qsort_cmp_long_value);
	for (i = 0; i < items; i++) {
		long value = (long) table[(i*2)+1];
		tot += value;
		if (i > Config_max_trails) continue;
		if (max < value)
			max = value;
	}
	if (max == 0) max = 1; /* avoid division by zero */
	if (tot == 0) tot = 1;
	for (i = 0; i < items; i++) {
		int color;
		char *key = table[i*2];
		char *t;
		long value = (long) table[(i*2)+1];
		float percentage = ((float)value/tot)*100;
		if (i > Config_max_trails) break;
		color = (value*255)/max;
		t = strstr(key, " -> ");
		*t = '\0'; /* alter */
		printf("\t\"%s\" -> \"%s\" [color=\"#%02X00%02X\" label=\"%.2f\"]\n", key, t+4, color, 255-color, percentage);
		*t = ' '; /* restore */
	}
	if (!Config_graphviz_ignorenode_google)
		printf("\tGoogle [color=\"#c0ffc0\"]\n");
	if (!Config_graphviz_ignorenode_external)
		printf("\t\"External Link\" [color=\"#c0ffc0\"]\n");
	if (!Config_graphviz_ignorenode_noreferer)
		printf("\t\"No Referer\" [color=\"#c0ffc0\"]\n");
	free(table);
	printf("}\n");
}

/* -------------------------------- stream mode ----------------------------- */
void vi_stream_mode(struct vih *vih)
{
	time_t lastupdate_t, lastreset_t, now_t;

	lastupdate_t = lastreset_t = time(NULL);
	while(1) {
		char buf[VI_LINE_MAX];

		if (fgets(buf, VI_LINE_MAX, stdin) == NULL) {
			vi_sleep(1);
			continue;
		}
		if (vi_process_line(vih, buf)) {
			fprintf(stderr, "%s\n", vi_get_error(vih));
		}
		now_t = time(NULL);
		/* update */
		if ((now_t - lastupdate_t) >= Config_update_every) {
			lastupdate_t = now_t;
			if (vi_print_report(Config_output_file, vih)) {
				fprintf(stderr, "%s\n", vi_get_error(vih));
			}
		}
		/* reset */
		if (Config_reset_every &&
		    ((now_t - lastreset_t) >= Config_reset_every))
		{
			lastreset_t = now_t;
			vi_reset(vih);
		}
	}
}

/* ----------------------------------- main --------------------------------- */

/* command line switche IDs */
enum { OPT_MAXREFERERS, OPT_MAXPAGES, OPT_MAXIMAGES, OPT_USERAGENTS, OPT_ALL, OPT_MAXLINES, OPT_GOOGLE, OPT_MAXGOOGLED, OPT_MAXUSERAGENTS, OPT_OUTPUT, OPT_VERSION, OPT_HELP, OPT_PREFIX, OPT_TRAILS, OPT_GOOGLEKEYPHRASES, OPT_GOOGLEKEYPHRASESAGE, OPT_MAXGOOGLEKEYPHRASES, OPT_MAXGOOGLEKEYPHRASESAGE, OPT_MAXTRAILS, OPT_GRAPHVIZ, OPT_WEEKDAYHOUR_MAP, OPT_MONTHDAY_MAP, OPT_REFERERSAGE, OPT_MAXREFERERSAGE, OPT_TAIL, OPT_TLD, OPT_MAXTLD, OPT_STREAM, OPT_OUTPUTFILE, OPT_UPDATEEVERY, OPT_RESETEVERY, OPT_OS, OPT_BROWSERS, OPT_ERROR404, OPT_MAXERROR404, OPT_TIMEDELTA, OPT_PAGEVIEWS, OPT_ROBOTS, OPT_MAXROBOTS, OPT_GRAPHVIZ_ignorenode_GOOGLE, OPT_GRAPHVIZ_ignorenode_EXTERNAL, OPT_GRAPHVIZ_ignorenode_NOREFERER, OPT_GOOGLEHUMANLANGUAGE, OPT_FILTERSPAM, OPT_MAXADSENSED, OPT_GREP, OPT_EXCLUDE, OPT_IGNORE404, OPT_DEBUG, OPT_SCREENINFO};

/* command line switches definition:
 * the rule with short options is to take upper case the
 * 'special' options (the option a normal user should not use) */
static struct ago_optlist visitors_optlist[] = {
	{ 'A',  "all",			OPT_ALL,		AGO_NOARG},
	{ 'T',  "trails",		OPT_TRAILS,		AGO_NOARG},
	{ 'G',	"google",		OPT_GOOGLE,		AGO_NOARG},
	{ 'K',	"google-keyphrases",	OPT_GOOGLEKEYPHRASES,	AGO_NOARG},
	{ 'Z',	"google-keyphrases-age", OPT_GOOGLEKEYPHRASESAGE, AGO_NOARG},
        { 'H',  "google-human-language", OPT_GOOGLEHUMANLANGUAGE, AGO_NOARG},
	{ 'U',	"user-agents",		OPT_USERAGENTS,		AGO_NOARG},
	{ 'W',  "weekday-hour-map",	OPT_WEEKDAYHOUR_MAP,	AGO_NOARG},
	{ 'M',  "month-day-map",	OPT_MONTHDAY_MAP,	AGO_NOARG},
	{ 'R',  "referers-age",		OPT_REFERERSAGE,	AGO_NOARG},
	{ 'D',  "domains",		OPT_TLD,		AGO_NOARG},
	{ 'O',  "operating-systems",	OPT_OS,			AGO_NOARG},
	{ 'B',  "browsers",		OPT_BROWSERS,		AGO_NOARG},
	{ 'X',  "error404",		OPT_ERROR404,		AGO_NOARG},
	{ 'Y',  "pageviews",		OPT_PAGEVIEWS,		AGO_NOARG},
	{ 'S',	"robots",		OPT_ROBOTS,		AGO_NOARG},
	{ '\0',	"screen-info",		OPT_SCREENINFO,		AGO_NOARG},
	{ '\0', "stream",		OPT_STREAM,		AGO_NOARG},
	{ '\0', "update-every",		OPT_UPDATEEVERY,	AGO_NEEDARG},
	{ '\0',	"reset-every",		OPT_RESETEVERY,		AGO_NEEDARG},
	{ 'f',	"output-file",		OPT_OUTPUTFILE,		AGO_NEEDARG},
	{ 'm',	"max-lines",		OPT_MAXLINES,		AGO_NEEDARG},
	{ 'r',	"max-referers",		OPT_MAXREFERERS,	AGO_NEEDARG},
	{ 'p',	"max-pages",		OPT_MAXPAGES,		AGO_NEEDARG},
	{ 'i',	"max-images",		OPT_MAXIMAGES,		AGO_NEEDARG},
	{ 'x',	"max-error404",		OPT_MAXERROR404,	AGO_NEEDARG},
	{ 'u',	"max-useragents",	OPT_MAXUSERAGENTS,	AGO_NEEDARG},
	{ 't',	"max-trails",		OPT_MAXTRAILS,		AGO_NEEDARG},
	{ 'g',	"max-googled",		OPT_MAXGOOGLED,		AGO_NEEDARG},
	{ '\0',	"max-adsensed",		OPT_MAXADSENSED,	AGO_NEEDARG},
	{ 'k',	"max-google-keyphrases",OPT_MAXGOOGLEKEYPHRASES,AGO_NEEDARG},
	{ 'z',	"max-google-keyphrases-age",OPT_MAXGOOGLEKEYPHRASESAGE,
		AGO_NEEDARG},
	{ 'a',	"max-referers-age",	OPT_MAXREFERERSAGE,	AGO_NEEDARG},
	{ 'd',	"max-domains",		OPT_MAXTLD,		AGO_NEEDARG},
	{ 's',	"max-robots",		OPT_MAXROBOTS,		AGO_NEEDARG},
        { '\0', "grep",                 OPT_GREP,               AGO_NEEDARG},
        { '\0', "exclude",              OPT_EXCLUDE,            AGO_NEEDARG},
	{ 'P',  "prefix",		OPT_PREFIX,		AGO_NEEDARG},
	{ 'o',  "output",		OPT_OUTPUT,		AGO_NEEDARG},
	{ 'V',  "graphviz",		OPT_GRAPHVIZ,		AGO_NOARG},
	{ '\0', "graphviz-ignorenode-google", OPT_GRAPHVIZ_ignorenode_GOOGLE,
		AGO_NOARG},
	{ '\0', "graphviz-ignorenode-external", OPT_GRAPHVIZ_ignorenode_EXTERNAL,
		AGO_NOARG},
	{ '\0', "graphviz-ignorenode-noreferer", OPT_GRAPHVIZ_ignorenode_NOREFERER,
		AGO_NOARG},
	{ 'v',  "version",		OPT_VERSION,		AGO_NOARG},
	{ '\0', "tail",			OPT_TAIL,		AGO_NOARG},
	{ '\0', "time-delta",		OPT_TIMEDELTA,		AGO_NEEDARG},
        { '\0', "filter-spam",          OPT_FILTERSPAM,         AGO_NOARG},
        { '\0', "ignore-404",           OPT_IGNORE404,          AGO_NOARG},
	{ '\0',	"debug",		OPT_DEBUG,		AGO_NOARG},
	{ 'h',	"help",			OPT_HELP,		AGO_NOARG},
	AGO_LIST_TERM
};

void visitors_show_help(void)
{
	int i;

	printf("Usage: visitors [options] <filename> [<filename> ...]\n");
	printf("Available options:\n");
	for (i = 0; visitors_optlist[i].ao_long != NULL; i++) {
		if (visitors_optlist[i].ao_short != '\0') {
			printf("  -%c ", visitors_optlist[i].ao_short);
		} else {
			printf("     ");
		}
		printf("--%-30s %s\n",
				visitors_optlist[i].ao_long,
				(visitors_optlist[i].ao_flags & AGO_NEEDARG) ?
					"<argument>" : "");
	}
        printf("\nNOTE: --filter-spam can be *very* slow. Use with care.\n\n");
	printf("For more information visit http://www.hping.org/visitors\n"
	       "Visitors is Copyright(C) 2004-2006 Salvatore Sanfilippo <antirez@invece.org>\n");
}

int main(int argc, char **argv)
{
	int i, o;
	struct vih *vih;
	char *filenames[VI_FILENAMES_MAX];
	int filenamec = 0;

	/* Handle command line options */
	while((o = antigetopt(argc, argv, visitors_optlist)) != AGO_EOF) {
		switch(o) {
		case AGO_UNKNOWN:
		case AGO_REQARG:
		case AGO_AMBIG:
			ago_gnu_error("visitors", o);
			visitors_show_help();
			exit(1);
			break;
		case OPT_HELP:
			visitors_show_help();
			exit(0);
			break;
		case OPT_VERSION:
			printf("Visitors %s\n", VI_VERSION_STR);
			exit(0);
		case OPT_MAXREFERERS:
			Config_max_referers = atoi(ago_optarg);
			break;
		case OPT_MAXPAGES:
			Config_max_pages = atoi(ago_optarg);
			break;
		case OPT_MAXIMAGES:
			Config_max_images = atoi(ago_optarg);
			break;
		case OPT_MAXERROR404:
			Config_max_error404 = atoi(ago_optarg);
			break;
		case OPT_MAXUSERAGENTS:
			Config_max_agents = atoi(ago_optarg);
			break;
		case OPT_MAXTRAILS:
			Config_max_trails = atoi(ago_optarg);
			break;
		case OPT_MAXGOOGLED:
			Config_max_googled = atoi(ago_optarg);
			break;
		case OPT_MAXADSENSED:
			Config_max_adsensed = atoi(ago_optarg);
			break;
		case OPT_MAXGOOGLEKEYPHRASES:
			Config_max_google_keyphrases = atoi(ago_optarg);
			break;
		case OPT_MAXGOOGLEKEYPHRASESAGE:
			Config_max_google_keyphrases_age = atoi(ago_optarg);
			break;
		case OPT_MAXREFERERSAGE:
			Config_max_referers_age = atoi(ago_optarg);
			break;
		case OPT_MAXTLD:
			Config_max_tld = atoi(ago_optarg);
			break;
		case OPT_MAXROBOTS:
			Config_max_robots = atoi(ago_optarg);
			break;
		case OPT_USERAGENTS:
			Config_process_agents = 1;
			break;
		case OPT_GOOGLE:
			Config_process_google = 1;
			break;
		case OPT_GOOGLEKEYPHRASES:
			Config_process_google_keyphrases = 1;
			break;
		case OPT_GOOGLEKEYPHRASESAGE:
			Config_process_google_keyphrases_age = 1;
			break;
		case OPT_GOOGLEHUMANLANGUAGE:
                        Config_process_google_keyphrases = 1;
			Config_process_google_human_language = 1;
			break;
		case OPT_TLD:
			Config_process_tld = 1;
			break;
		case OPT_OS:
			Config_process_os = 1;
			break;
		case OPT_BROWSERS:
			Config_process_browsers = 1;
			break;
		case OPT_ERROR404:
			Config_process_error404 = 1;
			break;
		case OPT_PAGEVIEWS:
			Config_process_pageviews = 1;
			break;
		case OPT_ROBOTS:
			Config_process_robots = 1;
			break;
		case OPT_ALL:
			Config_process_agents = 1;
			Config_process_google = 1;
			Config_process_google_keyphrases = 1;
			Config_process_google_keyphrases_age = 1;
			Config_process_google_human_language = 1;
			Config_process_weekdayhour_map = 1;
			Config_process_monthday_map = 1;
			Config_process_referers_age = 1;
			Config_process_tld = 1;
			Config_process_os = 1;
			Config_process_browsers = 1;
			Config_process_error404 = 1;
			Config_process_pageviews = 1;
			Config_process_robots = 1;
                        Config_process_screen_info = 1;
			break;
		case OPT_PREFIX:
			if (Config_prefix_num < VI_PREFIXES_MAX) {
				Config_prefix[Config_prefix_num].str = ago_optarg;
				Config_prefix[Config_prefix_num].len = strlen(ago_optarg);
				Config_prefix_num++;
			} else {
				fprintf(stderr, "Error: too many prefixes specified\n");
				exit(1);
			}
			break;
		case OPT_TRAILS:
			Config_process_web_trails = 1;
			break;
		case OPT_MAXLINES:
			{
				int aux = atoi(ago_optarg);
				Config_max_referers = aux;
				Config_max_pages = aux;
				Config_max_images = aux;
				Config_max_error404 = aux;
				Config_max_agents = aux;
				Config_max_googled = aux;
				Config_max_adsensed = aux;
				Config_max_trails = aux;
				Config_max_google_keyphrases = aux;
				Config_max_google_keyphrases_age = aux;
				Config_max_referers_age = aux;
				Config_max_tld = aux;
				Config_max_robots = aux;
			}
			break;
		case OPT_OUTPUT:
			if (!strcasecmp(ago_optarg, "text"))
				Output = &OutputModuleText;
			else if (!strcasecmp(ago_optarg, "html"))
				Output = &OutputModuleHtml;
			else {
				fprintf(stderr, "Unknown output module '%s'\n",
						ago_optarg);
				exit(1);
			}
			break;
		case OPT_GRAPHVIZ:
			Config_graphviz_mode = 1;
			Config_process_web_trails = 1;
			break;
		case OPT_GRAPHVIZ_ignorenode_GOOGLE:
			Config_graphviz_ignorenode_google = 1;
			break;
		case OPT_GRAPHVIZ_ignorenode_EXTERNAL:
			Config_graphviz_ignorenode_external= 1;
			break;
		case OPT_GRAPHVIZ_ignorenode_NOREFERER:
			Config_graphviz_ignorenode_noreferer = 1;
			break;
		case OPT_TAIL:
			Config_tail_mode = 1;
			break;
		case OPT_WEEKDAYHOUR_MAP:
			Config_process_weekdayhour_map = 1;
			break;
		case OPT_MONTHDAY_MAP:
			Config_process_monthday_map = 1;
			break;
		case OPT_REFERERSAGE:
			Config_process_referers_age = 1;
			break;
		case OPT_STREAM:
			Config_stream_mode = 1;
			break;
		case OPT_OUTPUTFILE:
			Config_output_file = ago_optarg;
			break;
		case OPT_UPDATEEVERY:
			Config_update_every = atoi(ago_optarg);
			break;
		case OPT_RESETEVERY:
			Config_reset_every = atoi(ago_optarg);
			break;
		case OPT_TIMEDELTA:
			Config_time_delta = atoi(ago_optarg);
			break;
                case OPT_FILTERSPAM:
                        Config_filter_spam = 1;
                        break;
                case OPT_GREP:
                        ConfigAddGrepPattern(ago_optarg, VI_PATTERNTYPE_GREP);
                        break;
                case OPT_EXCLUDE:
                        ConfigAddGrepPattern(ago_optarg, VI_PATTERNTYPE_EXCLUDE);
                        break;
                case OPT_IGNORE404:
                        Config_ignore_404 = 1;
                        break;
                case OPT_DEBUG:
                        Config_debug = 1;
                        break;
                case OPT_SCREENINFO:
                        Config_process_screen_info = 1;
                        break;
		case AGO_ALONE:
			if (filenamec < VI_FILENAMES_MAX)
				filenames[filenamec++] = ago_optarg;
			break;
		}
	}
	/* If the user specified the 'tail' mode, we
	 * just emulate a "tail -f" for the specified files. */
	if (Config_tail_mode) {
		vi_tail(filenamec, filenames);
		return 0;
	}
	/* Check if at least one file was specified */
	if (filenamec == 0 && !Config_stream_mode) {
		fprintf(stderr, "No logfile specified\n");
		visitors_show_help();
		exit(1);
	}
	/* If the prefix was not set, but the user asks for
	 * web trails, notify it and exit. */
	if (Config_process_web_trails && !Config_prefix_num) {
		fprintf(stderr, "At least one prefix must be specified (using --prefix) for web trails\nExample: --prefix http://your.site.org\n");
		exit(1);
	}
        /* If screen-info is enabled, error 404 must be too, auto-enable it. */
        if (Config_process_screen_info && !Config_process_error404) {
            fprintf(stderr, "Note: 404 error processing enabled for screen-info report\n");
            Config_process_error404 = 1;
        }
	/* If stream-mode is enabled, --output-file should be specified. */
	if (Config_stream_mode && Config_output_file == NULL) {
		fprintf(stderr, "--stream requires --output-file\n");
		exit(1);
	}
	/* Set the default output module */
	if (Output == NULL)
		Output = &OutputModuleHtml;
	/* Change to "C" locale for date/time related functions */
	setlocale(LC_ALL, "C");
	/* Process all the log files specified. */
	vih = vi_new();
	for (i = 0; i < filenamec; i++) {
		if (vi_scan(vih, filenames[i])) {
			fprintf(stderr, "%s: %s\n", filenames[i], vi_get_error(vih));
			exit(1);
		}
	}
	if (Config_graphviz_mode) {
		vi_print_graphviz(vih);
	} else {
		if (vi_print_report(Config_output_file, vih)) {
			fprintf(stderr, "%s\n", vi_get_error(vih));
			exit(1);
		}
		if (Config_stream_mode) {
			vi_stream_mode(vih);
		}
	}
	vi_print_statistics(vih);
        /* The following is commented in releases as to free the hashtable
         * memory is very slow, it's better to just exit the program.
         * Still it is important to be able to re-enable a good cleanup
         * in order to run visitors against valgrind to check for memory
         * leaks. */
        /* vi_free(vih); */
	return 0;
}
