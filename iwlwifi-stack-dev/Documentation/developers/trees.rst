Trees used for the driver
=========================

::

 iwlwifi-stack-dev
 (<branch> = master or release/*)
	|
	|
	|
	+-------> iwlwifi-chrome-kernel/chromeos-<cros-version>__<branch>	[defconfig: chromeos]
	|         Done using intc-scripts/chromeos.py, see VERSIONS variable
	|         there for <cros-version>s and corresponding WIFIVERSIONs.
	|         See the ChromeOS chapter for a more detailed description of
        |         the process and how to resolve problems when it fails per-CI.
	|
	|
	+-------> iwlwifi-public/<branch>		[defconfig: iwlwifi-public]
	+-------> iwlwifi-public-modrename/<branch>	[defconfig: iwlwifi-public, --modcompat renaming]
	+-------> iwlwifi-public-slave/<branch>		[defconfig: xmm6321]
	          This is done using intc-scripts/prune-mirror.py.
	          See the Pruning chapter for a more detailed description of
                  this process and how to resolve problems when it fails per-CI.
