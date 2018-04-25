# coding: utf-8

''' 
This script will read raw images, mounted image
and / or DSD candidate files from subfolder.
Workflow is somewhat different if it is candidate 
file read from folder, or candidate file
undeleted from raw/mounted image. Checks
and recovery for potential files in images are 
based on hex regex signature.
Checks for potential files read from folders
 are based on their internal structure.
Potentially DSD files with wrong structure are marked 
as malformed. Check on existent files enables quick 
separation of DSDs from other ZIP like containers.
'''

# This addresses Dec 2017 bug on Win10
# https://bugs.python.org/issue32245

import win_unicode_console, os, logging
win_unicode_console.enable()

import re
import io
import sys
import glob
import ast
import configparser
import base64
from datetime import datetime
from zipfile import ZipFile
import xml.etree.ElementTree as ET
from pyasn1.codec.der import decoder as decoder

class Bdoc_Finder(object):

    ''' This is the class with functions for detecting DSD and extracting their data '''
    
    # Checks for config.ini depending on execution in local or remote dir
    if os.path.dirname(os.path.realpath(__file__)) == os.getcwd():
        config_ = 'config.ini'
    else:
        config_ = os.path.join(os.path.dirname(os.path.realpath(__file__)),'config.ini')

    # Reads variables from text file 'config.ini'
    # If fails reading config,ini it will use built-in variables and signatures
        
    config = configparser.ConfigParser()
    config.read(config_)
    try:
        image,mounted,mounted_size,file,result  = config["Pathes"].values()
        clusters_per_sectors,sector,\
        cluster_offset,maximum_filesize = config["Geometry"].values()
        header_hex_code,footer_hex_code,header_lenght = config["Signature"].values()
        format_ = config.get("Reporting","format_")
        scriptfolder = config.get("Reporting","scriptfolder")
        carve = config.get("Reporting","carve")
        tags_to_find_Base64 = config.get(
            "XML","tags_to_find_Base64").split('\n')[1:]
        tags_to_find_plaintext = config.get(
            "XML","tags_to_find_plaintext").split('\n')[1:]
        position = config.get("ASN.1","useful_attributes").split('\n')[1:]
    except:
        print('No config.ini file or wrong structure of config.ini file, \
        falling back to defaults.')
        image,file,result,mounted  = 'Image', 'Files', 'Results', ''
        format_ = 'Short'
        carve = 'False'
        scriptfolder = 'script'
        header_lenght = '105'
        clusters_per_sectors,sector,\
        cluster_offset,maximum_filesize = '8','512','0','10000'
        tags_to_find_Base64 = [
            '{http://www.w3.org/2000/09/xmldsig#}X509Certificate',
            '{http://uri.etsi.org/01903/v1.3.2#}EncapsulatedTimeStamp',
            '{http://uri.etsi.org/01903/v1.3.2#}EncapsulatedX509Certificate',
            '{http://uri.etsi.org/01903/v1.3.2#}EncapsulatedX509Certificate',
            '{http://uri.etsi.org/01903/v1.3.2#}EncapsulatedOCSPValue']
        tags_to_find_plaintext = [
            '{http://uri.etsi.org/01903/v1.3.2#}SigningTime',
            '{http://www.w3.org/2000/09/xmldsig#}X509IssuerName',
            '{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber',
            '{http://uri.etsi.org/01903/v1.3.2#}IssuerSerial',
            '{http://uri.etsi.org/01903/v1.3.2#}SignatureProductionPlace',
            '{http://uri.etsi.org/01903/v1.3.2#}City',
            '{http://uri.etsi.org/01903/v1.3.2#}StateOrProvince',
            '{http://uri.etsi.org/01903/v1.3.2#}PostalCode',
            '{http://uri.etsi.org/01903/v1.3.2#}CountryName',
            '{http://uri.etsi.org/01903/v1.3.2#}SignerRole',
            '{http://uri.etsi.org/01903/v1.3.2#}ClaimedRoles',
            '{http://uri.etsi.org/01903/v1.3.2#}ClaimedRole',
            '{http://uri.etsi.org/01903/v1.3.2#}ByName',
            '{http://uri.etsi.org/01903/v1.3.2#}ProducedAt']
        position = ['3','4','5']
        # These regexes exceed recommended 79 character wrapping lenghts style
        # Wrapping them, given that they have "" and '' and / and \ and 'binary' 
        # is exceedingly difficult.
        header_hex_code  = r"b'^PK\x03\x04(.|\s){26}mimetype(.|\s){0,36}(application\/vnd\.etsi\.asic\-e\+zip|K,\(\\\xc8\xc9LN,\xc9\xcc\xcf\xd3\/\xcbK\xd1K)'"
        footer_hex_code = r"b'PK\x05\x06\x00\x00(.|\s){14}.*?(\x00{2}|.*[ -~])'"
        mounted_size = 0
    
    # Can read folder where files are from commandline
    if len(sys.argv) > 1:
        file = str(sys.argv[1])

    def __init__(self):
       
        # Additional comments and explanations on variables are in 'config.ini'
        if self.scriptfolder == 'script':
            self.scriptfolder = os.path.dirname(os.path.realpath(__file__))
        elif self.scriptfolder == 'local':
            self.scriptfolder = os.getcwd()
        else:
            self.scriptfolder = os.path.dirname(os.path.realpath(__file__))

        if self.format_ == 'Short':
            self.format_ = 'Short'
        elif self.format_ == 'Long':
            self.format_ = 'Long'
        else:
            self.format_ = 'Long'

        if self.carve == 'True':
            self.carve is True
        elif self.carve == 'False':
            self.carve is False
        else:
            self.carve is False

        self.images = [] 
        self.image = os.path.join(self.scriptfolder, self.image, '*')
        for filename in sorted(glob.glob(self.image)):
            self.images.append(filename)
        if len(self.mounted) > 0:
            self.images.append(self.mounted)
            self.mounted_size = int(self.mounted_size)

        self.files = [] 
        self.file = os.path.join(self.scriptfolder, self.file, '*')
        for filename in sorted(glob.glob(self.file)):
            self.files.append(filename)

        result = os.path.join(self.scriptfolder, self.result)
        if not os.path.exists(result):
            os.makedirs(result)
        
        self.position =  list(map(int, self.position))

        self.clusters_per_sectors = int(self.clusters_per_sectors)
        self.sector = int(self.sector)
        self.maximum_filesize = int(self.maximum_filesize)
        self._cluster = self.clusters_per_sectors * self.sector
        self.header_lenght = int(self.header_lenght)
        self.header_hex_code = ast.literal_eval(self.header_hex_code)
        self.header_hex_code = re.compile(self.header_hex_code)
        self.footer_hex_code = ast.literal_eval(self.footer_hex_code)
        self.footer_hex_code = re.compile(self.footer_hex_code)
        
        if len(self.cluster_offset) != 0:
            self.cluster_offset = int(self.cluster_offset)
                      
    def discover_sectors(self,image):
        """
        This is the function for scanner, which will scan 
        DD image or mounted image and find all starts and ends
        or Headers and Footers of corresponding files
        provided contiguous clusters and HDD like geometry
        Mounted images reading rely on MS Windows syntax 
        """

        ### Variables ###

        start_carve_sector, end_carve_sector = [],[]
        current__cluster,_current__cluster = 0,0

        # Pointing to file and of file cluster total 
        # number calculation
        # Different methods for raw image file 
        # or for mounted drive
        
        try:
            file = open(image, 'rb')
        except Exception as e:
            print('Could not open',image,'because of',str(e))
            return
        if image.find('PHYSICALDRIVE') == -1:
            _clusters_total = int(os.path.getsize(image)/self._cluster)
        else:
            _clusters_total = int(self.mounted_size/self._cluster)
        file.seek(self.cluster_offset * self.sector)
        print('Clusters to analyse total:',str(_clusters_total),'...')

        ### Scanning for headers and footers ###

        while current__cluster <= _clusters_total:

            # This is reading one cluster and then moving 
            # the pointer one further cluster
            # This approach will not find 
            # NTFS resident files 
            # And this will not find ZIP files, 
            # which are smaller than a cluster 
            # Embedded signature and time-sresponses 
            # containing files are appr 13 Kb
            # So they can't really be residents
            # This approach will not find 
            # non-contiguously clustered files

            try:
                current_cluster = file.read(self._cluster)
            except:
                return start_carve_sector, end_carve_sector

            current__cluster += 1

            # This will apply the header #
            
            #header_lenght is the lenghts required for signature to work
            beginning_string_to_analyze = current_cluster[0:self.header_lenght]
            result = re.search(self.header_hex_code,beginning_string_to_analyze)

            # Action if header is present #

            if result:
                if result.group(0):

                    start_carve_sector.append(int(self.cluster_offset)  # Will
                    # remember where file starts
                     + self.clusters_per_sectors * (current__cluster - 1))
                    _current__cluster = 1

                    while _current__cluster <= self.maximum_filesize:  # Here is
                        #  administratively set max lenght

                        # This will read next cluster and move further one cluster #

                        current_cluster = file.read(self._cluster)

                        _current__cluster += 1
                        current__cluster += 1

                        # This will apply the footer, first to the whole cluster
                        # And second to the tail of the next cluster together with the
                        # current cluster

                        result2 = re.search(self.footer_hex_code,current_cluster)
                        if result2:
                            if result2.group(0):
                                if result2.span()[1] == len(current_cluster):
                                    end_carve_sector.append(int(self.cluster_offset)
                                     + 1 + (self.clusters_per_sectors)* (current__cluster))
                                else:
                                    end_carve_sector.append(int(self.cluster_offset)
                                     + (self.clusters_per_sectors)* (current__cluster))
                        
                        cluster_tail_2 = file.read(self._cluster)[0:self.sector]  #This
                        # is additional cluster-read, not the same read
                        joined_tail_2 = current_cluster + cluster_tail_2
                        result4 = re.search(self.footer_hex_code,joined_tail_2)
                        if result4:
                            if result4.group(0):
                                if result2 is None:
                                    if result4.span()[1] == len(joined_tail_2):
                                        end_carve_sector.append(int(self.cluster_offset)
                                         + 2 + (self.clusters_per_sectors) * (current__cluster))
                                    else:
                                        end_carve_sector.append(int(self.cluster_offset)
                                         + 1 + (self.clusters_per_sectors) * (current__cluster))

                        file.seek(self.cluster_offset*self.sector
                         + current__cluster*self._cluster)

                        if result2 or result4:
                            break
        destination = image.split('\\')[-1]
        print('Scan complete at cluster: ' +str(current__cluster - 1)
         + ' ' + str(len(start_carve_sector)) +','
         + str(len(end_carve_sector)) + ' start and end sectors found in '
          + destination)
        file.close()

        return start_carve_sector,end_carve_sector
    
    def recover_data_from_sectors(
        self,image,
        start_carve_sector,
        end_carve_sector):
        """
        This will recover file data based on starting
        and ending sectors in the image.
        """

        data = b''

        ### Copy sectors ###
        
        if end_carve_sector - start_carve_sector < 51200:  # limitation of size 
            # as for appr 25 MB max. Large-scale web scrapping of registry showed 
            # that 72% of documents come with email. It is anecdotically known that
            # in public sector frequent max size of email attachments is set to 25 MB
            file = open(image, 'rb')    
            file.seek(start_carve_sector*self.sector)
            data = file.read((end_carve_sector)*self.sector
             - start_carve_sector*self.sector)
            file.close()

            result = re.search(self.footer_hex_code,data)  # Apply improved 
            # footer to achieve MD5 match   
            if result:
                end = result.span()[1]
                data = data[0:end]

        return data
    
    def read_files(self,file):
        
        ''' Simply read the file '''
        
        with open(file,'rb') as f:
            data = f.read()
        return data

    def test_for_possible_bdoc(self,data):

        """
        This will test if data is ZIP and DSD and export signature
        """  

        # Variables and Checks #

        testing_for_DSD = False
        comment,list_of_ZIP,list_of_DSD,unziped_SIG = [],[],[],[]
        list_of_files = ''

        # Checks #

        if len(data) == 0:
            return comment,testing_for_DSD,list_of_DSD,unziped_SIG,list_of_files
        try:
            data_to_bytes = io.BytesIO(data)
        except TypeError as Te:
            print("Convert to bytes failed because",str(Te))
            return comment,testing_for_DSD,list_of_DSD,unziped_SIG,list_of_files

        # Try to Unzip #

        try:
            zipfile = ZipFile(data_to_bytes,'r')
            list_of_ZIP = zipfile.filelist
            if len(list_of_ZIP) > 0:
                pass
            else:
                return comment,testing_for_DSD,list_of_DSD,unziped_SIG,list_of_files
        except:
            return comment,testing_for_DSD,list_of_DSD,unziped_SIG,list_of_files

        # Check if signature file exists #

        comment_ZIP,comment_file,extra_file = '','',''
        
        if len(list_of_ZIP) > 0:
            comment_ZIP = zipfile.comment
            if len(comment_ZIP) > 0:
                comment_ZIP = 'ZIP_comment: ' + str(comment_ZIP)
            else:
                comment_ZIP = 'no_ZIP_Comment'
            
            for file in list_of_ZIP:
                comment_ = zipfile.getinfo(file.filename).comment
                if len(comment_) > 0:
                    comment_file = comment_ZIP + ', file_comment: ' + str(comment_)
                else:
                    comment_file = comment_ZIP + ', no_file_comment'

                extra = zipfile.getinfo(file.filename).extra
                if len(extra) > 0:
                    extra = str(extra)
                    extra = extra.replace(';','')
                    extra_file = comment_file + ', extra: ' + str(extra)
                    if sys.version_info < (3, 0):
                        extra_file = '\\x'.join(x.encode('hex') for x in extra_file)
                        extra_file = extra_file.decode('utf-8', errors = 'ignore')
                else:
                    extra_file = comment_file + ', no_extra'
                comment.append(extra_file)
                list_of_DSD.append(file.filename)    
                
                if (file.filename.find('META-INF') == -1 and 
                    file.filename.find('mimetype') == -1):
                    if len(list_of_files) == 0:
                        list_of_files = list_of_files + file.filename
                    else:
                        list_of_files = list_of_files +','+ file.filename

                if file.filename.find('META-INF/signature') > -1:

                    testing_for_DSD = True

                    # Check if unzips XML signature and extract #

                    try:
                        with zipfile.open(file.filename) as opened_file:
                            unzipped_file = opened_file.read()
                            if len(unzipped_file) > 0:
                                unziped_SIG.append(unzipped_file)
                            else:
                                unziped_SIG.append('')
                    except Exception as e:
                        print('Could not extract signature file from DSD because of',str(e))
                        unziped_SIG.append('')
                        
            return comment,testing_for_DSD,list_of_DSD,unziped_SIG,list_of_files
        
    def parce_sig_XML(self,unziped_SIG):

        """
        This will parce XML and export meaningful XML elements and ASN.1 encoded data.
        """ 

        # Variables to store results #

        found_values_text,found_values_Base64,found_values_ASN_1 = [],[],[]
        line_to_print = ''

        # Parcing XML #

        try:
            root_f = ET.fromstring(unziped_SIG)
        except:
            try:
                root_f = ET.fromstring(unziped_SIG[0])
            except TypeError as e:
                print('XML parcing failed:',str(e))
                return found_values_text,found_values_Base64,found_values_ASN_1

        last_step = root_f.findall(".//")
        for each_tag_attr in last_step:

            attr = each_tag_attr.attrib
            attr = 'None' if attr is None else attr
            attr = str(attr)

            tag = each_tag_attr.tag
            tag = 'None' if tag is None else tag

            text = each_tag_attr.text
            text = 'None' if text is None else text

            if tag in self.tags_to_find_plaintext:
                line_to_print = tag + ';' + text
                line_to_print = line_to_print.replace('\n','')
                found_values_text.append(line_to_print)

            if tag in self.tags_to_find_Base64:
                text = str(text)
                line_to_print = tag + ';' + str(text[0:10])
                line_to_print = line_to_print.replace('\n','')
                found_values_Base64.append(line_to_print)

                found_values_ASN_1.append(text)

        return found_values_text,found_values_Base64,found_values_ASN_1
    
    def parce_cert(self,found_values_ASN_1,found_values_Base64):

        """
        This will decode ASN.1 and export meaningful data.
        """

        # Variables to store results #

        found_values_ASN_decoded = []
        short_values = []
        date_to_add = ''

        # Decode X509Certificate and Responses #

        for encoded_ASN_1_datablock,ASN_tag in zip(
            found_values_ASN_1,found_values_Base64):
            ASN_tag = ASN_tag.split(";")[0]
            ASN_tag = ASN_tag.split("}")[1]

            if ASN_tag =='EncapsulatedTimeStamp' or ASN_tag =='EncapsulatedOCSPValue':
                try:
                    decoded_base64_OSCP = base64.b64decode(encoded_ASN_1_datablock)
                except:
                    error = 'Base64 decode failed in ' + ASN_tag
                    found_values_ASN_decoded.append(error)
                    short_values.append(error)
                    break
                date = re.compile(b'(\d{14}Z)')
                result_date = re.search(date,decoded_base64_OSCP)
                if result_date:
                    if result_date.group(0) is not None:
                        
                        # Rewrites date to more human readable format #
                        date_to_add = str(result_date.group(0))
                        date_to_add = date_to_add.replace("b'","'")
                        date_to_add = date_to_add.replace("'","")
                        date_to_add = date_to_add.replace("Z","")
                        date_to_add = str(date_to_add)
                        date_to_add = date_to_add[0:4] + '.' + date_to_add[4:6]\
                         + '.' + date_to_add[6:8] + ' ' + date_to_add[8:10]\
                          + ':' + date_to_add[10:12]  + ':' + date_to_add[12:]
                        found_values_ASN_decoded.append(date_to_add)

            if ASN_tag =='X509Certificate':
                try:
                    decoded_base64 = base64.b64decode(encoded_ASN_1_datablock)
                except:
                    error = 'Base64 decode failed in ' + ASN_tag
                    found_values_ASN_decoded.append(error)
                    short_values.append(error)
                    break
                try:
                    decoded_ASN_1_datablock = decoder.decode(decoded_base64)

                    # Makes short list, see 'config.ini' #

                    if self.format_ == 'Short':
                        ASN_objects = decoded_ASN_1_datablock[0].getComponentByPosition(0)[5]
                        lname = ASN_objects.getComponentByPosition(4)[0][1] + ';'
                        fname = ASN_objects.getComponentByPosition(5)[0][1]  + ';'
                        if lname == 'Corporate Signature':
                            pcode = ASN_objects.getComponentByPosition(0)[0][1]
                        else:
                            pcode = ASN_objects.getComponentByPosition(6)[0][1]
                        short_values.append(lname + fname + pcode)                        
                    else:
                        
                        # Makes long list, see 'config.ini' #
                        # place = 3, this is about Certification Authority
                        # place = 5, this is personal data
                        # place = 4, this is Cert validity dates

                        for place in self.position:
                            ASN_objects = decoded_ASN_1_datablock[0].getComponentByPosition(0)[place]
                            for name_objects in range(len(ASN_objects)):
                                name_object = ASN_objects.getComponentByPosition(name_objects)
                                if place == 4:
                                    ASN_value_to_add = name_object
                                    found_values_ASN_decoded.append(ASN_value_to_add)
                                
                                else:
                                    for ASN_object in range(len(name_object)):
                                        ASN_value_to_add = name_object.getComponentByPosition(ASN_object)[1]
                                        found_values_ASN_decoded.append(ASN_value_to_add)

                except Exception as e:
                    error = 'ASN.1 decode failed in ' + ASN_tag + ': ' + str(e)
                    found_values_ASN_decoded.append(error)
                    short_values.append(error)
                    break
                               
        return found_values_ASN_decoded,short_values,date_to_add
    
    def write_recovered_data_to_file(self,data,destination):

        """
        This will save recovered file data to a file in Results folder, 
        provided a name was given.
        """    
        destination = os.path.join(self.scriptfolder,self.result,destination)
        if len(data) > 0:
            file = open(destination, 'wb')
            file.write(data)
            file.close()
    
    def write_links_to_file(self,Resulting_CSV):

        ''' Write recovered attributive data to file '''
        
        if len(Resulting_CSV) == 0:
            print('No attributes were written.')
            return

        # Make unique filename
        current_time_to_filename = datetime.now().strftime('%d_%m_%Y_%H_%M_%S_%f')
        basename = current_time_to_filename + "_recovered_attributes_" + str(
            len(Resulting_CSV)) + ".csv"
        filename = os.path.join(self.scriptfolder, basename)

        if self.format_ == 'Long' and sys.version_info >= (3, 0):
            # Encoding issues have not been solved for Python 2
            line_by_line_file = open(filename, 'w', encoding = 'utf-8')
        else:
            line_by_line_file = open(filename, 'w')

        for line in Resulting_CSV:
            try:
                line_by_line_file.write("%s\n" % line)
            except Exception as e:
                print("Failed writing line-to-line to file:",str(e))

        line_by_line_file.close()

        print('File',basename,'of',str(len(Resulting_CSV)),'lines written in folder',self.scriptfolder)

if __name__ == "__main__":
    
    startTime = datetime.now()

    # Variables from setup #

    files = Bdoc_Finder().files
    images = Bdoc_Finder().images
    carve = Bdoc_Finder().carve
    scriptfolder = Bdoc_Finder().scriptfolder

    # Variables to collect results #

    line_to_save = 'File;Signed docs;Layer;Contents;Contents 2'
    short_line_to_save = 'File;No of Sign;Name;Surname;Personal Code;Date'

    Resulting_CSV,Short_csv = [line_to_save],[short_line_to_save]

    if len(files) == 0 and len(images) == 0:
        print('No files neither images were found to read files from.')

    else:
            
        # If files are found in subfolder #

        if len(files) > 0:
            print('Found',str(len(files)),'files to analyze...')
            for file in files:
                data = Bdoc_Finder().read_files(file)
                destination = file.split('\\')[-1]
                destination = destination.split('/')[-1]
                try:
                    
                    # Unzip signature and recover file #
                    
                    comments,testing_for_bdoc,list_of_DSD,unziped_SIG,list_of_files = Bdoc_Finder(

                    ).test_for_possible_bdoc(data)
                    
                    # Write recovered files #

                    if testing_for_bdoc is True:
                        if carve == 'True':
                            Bdoc_Finder().write_recovered_data_to_file(data,destination)
                        print(destination,'tested as BDOC, file size of',str(len(data)))
                    else:
                        if any("manifest.xml" in _file for _file in list_of_DSD):
                            # Known files having manifest.xml but there are files
                            # without signature. They include: unsigned BDOC, 
                            # unsigned ASICE; also: ODT, ODF files
                            print('Possible unsigned BDOC',destination,'detected, file size',str(len(data)))
                        else:
                            print(destination,'failed BDOC test, file size',str(len(data)))
                except Exception as e:
                    print('Failed trying to check if',destination,'ZIP because of',str(e))
                
                for comment in comments:
                    
                    # Add ZIP #
                    
                    line_to_save = destination +';'+ list_of_files +';ZIP;' + comment +';'
                    if testing_for_bdoc == True:
                        Resulting_CSV.append(line_to_save)

                iterator = 1    
                for unziped_SIG in unziped_SIG:

                    # Parce XML #
                
                    found_values_text,found_values_Base64,found_values_ASN_1 = Bdoc_Finder(

                    ).parce_sig_XML(unziped_SIG)
                    
                    # Decode ASN.1 #
                
                    found_values_ASN_decoded,short_values,date_to_add = Bdoc_Finder().parce_cert(
                        found_values_ASN_1,found_values_Base64)

                    # Collect results #

                    if len(short_values) > 0:
                        if testing_for_bdoc == True:    
                            for line_ in short_values:
                                short_line_to_save = destination +';'+ "Signature_" + str(iterator)+ ';'\
                                 + line_ + ';' + date_to_add
                                Short_csv.append(short_line_to_save)

                    for each_value in found_values_text:
                        line_to_save = destination +';'+ list_of_files +';XML;'+ each_value +';'
                        if testing_for_bdoc == True:
                            Resulting_CSV.append(line_to_save)
                    for each_value in found_values_ASN_decoded:
                        line_to_save = destination +';'+ list_of_files +';ASN.1;'+ each_value +';'
                        if testing_for_bdoc == True:
                            Resulting_CSV.append(line_to_save)
                    
                    iterator += 1

                line_to_save = ''

        if len(images) > 0:
            start_carve_sector,end_carve_sector = [],[]

            for image in images:
                print('Scanning image',image)
                
                # Scan image #
                        
                start_carve_sector,end_carve_sector = Bdoc_Finder().discover_sectors(image)

                # Carve data #

                for start_carve_sector,end_carve_sector in zip(
                    start_carve_sector,end_carve_sector):
                    data = Bdoc_Finder().recover_data_from_sectors(image,
                                        start_carve_sector,end_carve_sector)
                    if data:
                        destination = image.split('\\')[-1]
                        destination = destination.split('/')[-1]
                        destination = str(start_carve_sector) + '_' + str(end_carve_sector) \
                        + '_' + destination + '.bdoc'
                        try:
                            
                            # Unzip signature and recover file #

                            comments,testing_for_bdoc,list_of_DSD,unziped_SIG,list_of_files = Bdoc_Finder(

                            ).test_for_possible_bdoc(data)
                            
                            # Write recovered files #
                            
                            if testing_for_bdoc is True:
                                print(destination,'recovered a BDOC, file size of',str(len(data)))
                                if carve == 'True':
                                    Bdoc_Finder().write_recovered_data_to_file(data,destination)
                            else:
                                print(destination,'failed BDOC test',str(len(data)))
                                destination = 'Malformed_' + destination
                                if carve == 'True':
                                    Bdoc_Finder().write_recovered_data_to_file(data,destination)                
                            
                        except Exception as e:
                            print('Failed trying to check if',destination,'ZIP because of',str(e))   
                    
                        for comment in comments:
                            
                            # Add ZIP #
                            
                            line_to_save = destination +';'+ list_of_files +';ZIP;'+ comment +';'
                            Resulting_CSV.append(line_to_save)

                        iterator = 1    
                        for unziped_SIG in unziped_SIG:

                            # Parce XML #
                        
                            found_values_text,found_values_Base64,found_values_ASN_1 = Bdoc_Finder(

                            ).parce_sig_XML(unziped_SIG)
                            
                            # Decode ASN.1 #
                        
                            found_values_ASN_decoded,short_values,date_to_add = Bdoc_Finder().parce_cert(
                                found_values_ASN_1,found_values_Base64)
                            
                            # Collect results #

                            if len(short_values) > 0:
                                if testing_for_bdoc == True:    
                                    for line_ in short_values:
                                        short_line_to_save = destination +';'+ "Signature_" + str(iterator)+ ';'\
                                         + line_ + ';' + date_to_add
                                        Short_csv.append(short_line_to_save)

                            for each_value in found_values_text:
                                line_to_save = destination +';'+ list_of_files +';XML;'+ each_value +';'
                                Resulting_CSV.append(line_to_save)
                            for each_value in found_values_ASN_decoded:
                                line_to_save = destination +';'+ list_of_files +';ASN.1;'+ each_value +';'
                                Resulting_CSV.append(line_to_save)

                            iterator += 1

                        line_to_save = ''

    # Write collected data to XLSX file #
    # Can be replaced with 'write_links_to_file'
    # To export to CSV

    if len(Resulting_CSV) > 1 and Bdoc_Finder().format_ == 'Long':
        Bdoc_Finder().write_links_to_file(Resulting_CSV)
    if len(Short_csv) > 1 and Bdoc_Finder().format_ == 'Short':
        Bdoc_Finder().write_links_to_file(Short_csv)
    time = datetime.now() - startTime
    print('Script completed in',time,
    'the results were written in "',Bdoc_Finder().format_,'" format')