Steps to take when adding a new Kconfig symbol
==============================================

0) Make sure you really want a new Kconfig symbol and there's no
   way to do the right thing at runtime in platform configuration.

1) Add the new Kconfig symbol, deciding whether it should be in the
   Kconfig or Kconfig.noupstream file depending on whether it should
   be upstreamed or not.
   Many symbols should probably not be upstreamed.

2) Add the new symbol to the local-symbols file, otherwise it may
   get confused with a base kernel symbol once it goes upstream.

3) Decide what the state (remove, set to y, leave) of the symbol
   should be for the published "prune" trees. See prune.txt,
   specifically under the "CPTCFG_SYM state not known" error.
