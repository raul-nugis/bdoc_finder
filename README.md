# bdoc_finder
Finds digitally signed document (DSD) BDOC or ASICE files and exports some of their data. 
Tested with Python 3.5.3 and 3.6.5 under Win10 64 Home; and with Python 3.5.3 under Ubuntu 16.
In Ubuntu, 'win_unicode_console' and 'win_unicode_console.enable()' were removed from the code 
and the script would produce CSV instead of XLSX.

This script will read raw images, mounted image and / or DSD candidate files from subfolder.
Workflow is somewhat different if it is candidate file read from folder, or candidate file
undeleted from raw/mounted image. Checks and recovery for potential files in images are 
based on hex regex signature. Checks for potential files read from folders are based on their internal structure.
Potentially DSD files with wrong structure are marked as malformed. Check on existent files enables quick-
separation of DSDs from other ZIP like containers.

The script works under in the following default setup:

1. Place script's .py and config.ini files in a folder. 
2. Create subfolder 'Files' in the same folder, put there suspected DSD files. 
3. Or/and create subfolder 'Image' for RAW images, place there DD images
4. Or/and mount .E01 image as volume. If image is mounted, do necessery modifications in config.ini
5. Run script. It will create folder 'Results' where, if this optionis enabled in .ini, checked
or malformed DSDs will be exported. It will also create,in script's root directory, an CSV or XLSX file
with the extracted data.

