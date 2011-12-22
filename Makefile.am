
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@

cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=srv_yara.la

srv_yara_la_LIBADD = @MODULES_LIBADD@ @yaralib@ -lyara
srv_yara_la_CFLAGS=  -I../../include/ @yarainc@
srv_yara_la_LDFLAGS=  -module -avoid-version
srv_yara_la_SOURCES = srv_yara.c

install-data-local:
	$(INSTALL) srv_yara.conf $(DESTDIR)$(CONFIGDIR)/srv_yara.conf
	$(INSTALL) yara_rules $(DESTDIR)$(CONFIGDIR)/yara_rules

EXTRA_DIST = srv_yara.h srv_yara.conf yara_rules
