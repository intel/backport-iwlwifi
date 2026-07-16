for fn in $(find $kernel_path/drivers/net/wireless/iwl7000/ -name 'Makefile*') ; do
	sed -i 's|\$(src)|\$(srctree)/\$(src)|' $fn
done
