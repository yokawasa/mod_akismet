MOD_AKISMET = mod_akismet akismet\

HEADER = akismet.h \

mod_akismet.la: mod_akismet.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version mod_akismet.lo

DISTCLEAN_TARGETS = modules.mk

shared =  mod_akismet.la

