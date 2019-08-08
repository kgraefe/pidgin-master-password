plugindir = $(libdir)/pidgin
DEFS = -DLOCALEDIR=\"$(localedir)\"

plugin_LTLIBRARIES = master_password.la
master_password_la_SOURCES = \
	plugin.c \
	requesthook.c \
	masterkey.c

master_password_la_LDFLAGS = -module -avoid-version
