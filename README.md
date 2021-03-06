# bdoc_finder
Finds digitally signed document (DSD) BDOC or ASICE files and exports some of their data. 
Tested with Python 3.5.3 and 3.6.5 under Win10 (64) Home; and with Python 3.5.3, 3.6.5 under 
Ubuntu v 16 (64) for analysis of files and from raw images.

This script will read raw images, mounted image and / or DSD candidate files from subfolder.
For files remote folder full path can be feed through commandline.
Workflow is somewhat different if it is candidate file read from folder, or candidate file
undeleted from raw/mounted image. Checks and recovery for potential files in images are 
based on hex regex signature. Checks for potential files read from folders are based on their internal structure.
Potentially DSD files with wrong structure are marked as malformed. Check on existent files enables quick-
separation of DSDs from other ZIP like containers. For images, NTFS and FAT32 have been tested.
To succeed in an image based on FAT32 changes are required in 'config.ini' 'geometry' settings, such as
changing the geometry to 1 sector per cluster and compensating in the 'maximum_filesize' variable.

The script works in the following default Python v3 setup:

pip install packages required such as 
"pip install pyasn1==0.2.3 python-dateutil==2.7.2 pytz==2018.4 six==1.11.0 win-unicode-console==0.5"

1. Place script's .py and config.ini files in a folder. 
2. Create subfolder 'Files' in the same folder, put there suspected DSD files.
Or feed the full path for the folder where files are in the commandline.
3. Or/and create subfolder 'Image' for RAW images, place there DD images
4. Or/and mount .E01 image as volume. If image is mounted, do necessery modifications in config.ini
5. Run script. It will create folder 'Results' where, if this optionis enabled in .ini, checked
or malformed DSDs will be exported. It will also create,in script's root directory, an CSV (.txt)
with the extracted data.