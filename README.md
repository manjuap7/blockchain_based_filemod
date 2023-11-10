# blockchain_based_filemod
Blockchain based tracking of config file changes. Nice programs for learning and
understanding blockchain concepts. It would be used to implement file based
change monitoring with only authorized users allowed to modify. If any other
user modifies, the block chain would reveal the contamination in the config file.

This works on AIX/Linux ppc.

./blkchn_modify /etc/someconfig ram hostprod

Make the changes to the file, save and exit

It would display the diff and the block added with hash,signature and other details.

You can make multiple edit using the above command and each time a new block gets added.
The block contains the diff with integrity of the diff.

./blkchn_verify someconfig.meta someconfig

It will verify each block for current to prev hash, signature with user's private key.
