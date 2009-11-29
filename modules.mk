MOD_AKISMET = mod_akismet akismet

HEADER = akismet.h

${MOD_AKISMET:=.slo}: ${HEADER}
${MOD_AKISMET:=.lo}: ${HEADER}
${MOD_AKISMET:=.o}: ${HEADER}

mod_akismet.la: ${MOD_AKISMET:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_AKISMET:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_akismet.la

