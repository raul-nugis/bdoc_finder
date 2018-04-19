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

class Bdoc_Finder(object):

    ''' This is the class with functions for detecting DSD and extracting their data '''

    import configparser
    
    # Reads variables from text file 'config.ini'
    # If fails reading config,ini it will use built-in variables and signatures

    config = configparser.ConfigParser()
    config.read('config.ini')
    try:
        image,mounted,mounted_size,file,result  = config["Pathes"].values()
        clusters_per_sectors,sector,\
        cluster_offset,maximum_filesize = config["Geometry"].values()
        header_hex_code,footer_hex_code,header_lenght = config["Signature"].values()
        format_ = config.get("Reporting","format_")
        carve = config.get("Reporting","carve")
        tags_to_find_Base64 = config.get(
            "XML","tags_to_find_Base64").split('\n')[1:]
        tags_to_find_plaintext = config.get(
            "XML","tags_to_find_plaintext").split('\n')[1:]
        useful_attributes = config.get("ASN.1","useful_attributes").split('\n')[1:]
    except:
        print('No config.ini file or wrong structure of config.ini file, \
        falling back to defauls.')
        image,file,result,mounted  = 'Image', 'Files', 'Results', ''
        format_ = 'Long'
        carve = 'False'
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
        useful_attributes = [
            'UTF8String',
            'PrintableString',
            'UTCTime',
            'BMPString']
        # These regexes exceed recommended 79 character wrapping lenghts style
        # Wrapping them, given that they have "" and '' and / and \ and 'binary' 
        # is exceedingly difficult.
        header_hex_code  = r"b'^PK\x03\x04(.|\s){26}mimetype(.|\s){0,36}(application\/vnd\.etsi\.asic\-e\+zip|K,\(\\\xc8\xc9LN,\xc9\xcc\xcf\xd3\/\xcbK\xd1K)'"
        footer_hex_code = r"b'PK\x05\x06\x00\x00(.|\s){14}.*?(\x00{2}|.*[ -~])'"
        mounted_size = 0

    def __init__(self):
       
        import os
        import re
        import glob
        import ast
        
        self.images = [] 
        self.image = os.path.join(os.getcwd(), self.image, '*')
        for filename in sorted(glob.glob(self.image)):
            self.images.append(filename)
        if len(self.mounted) > 0:
            self.images.append(self.mounted)
            self.mounted_size = int(self.mounted_size)

        self.files = [] 
        self.file = os.path.join(os.getcwd(), self.file, '*')
        for filename in sorted(glob.glob(self.file)):
            self.files.append(filename)
        
        result = os.path.join(os.getcwd(), self.result)
        if not os.path.exists(result):
            os.makedirs(result)
        
        if self.format_ == 'Short':
            self.format_ = 'Short'
        else:
            self.format_ = 'Long'

        if self.carve == 'True':
            self.carve is True
        else:
            self.carve is False
        
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
        except BaseException as e:
            print('Could not open',image,'because of',e)
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
            except BaseException as e:
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

        from zipfile import ZipFile
        import io

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
        except BaseException as e:
            pass

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
                    except BaseException as e:
                        print('Could not extract signature file from DSD because of',e)
                        unziped_SIG.append('')
                        
            return comment,testing_for_DSD,list_of_DSD,unziped_SIG,list_of_files
        
    def parce_sig_XML(self,unziped_SIG):

        """
        This will parce XML and export meaningful XML elements and ASN.1 encoded data.
        """ 

        import xml.etree.ElementTree as ET

        # Variables to store results #

        found_values_text,found_values_Base64,found_values_ASN_1 = [],[],[]
        line_to_print = ''

        # Parcing XML #

        try:
            root_f = ET.fromstring(unziped_SIG)
        except BaseException as e:
            try:
                root_f = ET.fromstring(unziped_SIG[0])
            except BaseException as e:
                print('XML parcing failed:',e)
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

        import re
        import base64
        from pyasn1.codec.der import decoder as decoder

        # Variables to store results #

        found_values_ASN_decoded = []
        additional_field = ''
        short_values = ''
        date_to_add = ''
        if self.format_ == 'Short':
            name_and_code = re.compile("(.|\s){1,26},(.|\s){1,26},\d{11}")

        # Decode X509Certificate and Responses #

        for encoded_ASN_1_datablock,ASN_tag in zip(
            found_values_ASN_1,found_values_Base64):
            ASN_tag = ASN_tag.split(";")[0]
            ASN_tag = ASN_tag.split("}")[1]

            if ASN_tag =='EncapsulatedTimeStamp' or ASN_tag =='EncapsulatedOCSPValue':
                try:
                    decoded_base64_OSCP = base64.b64decode(encoded_ASN_1_datablock)            
                except BaseException as e:
                    found_values_ASN_decoded.append('Time decode failed',e)
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
                except BaseException as e:
                    print('Base64 decode failed in',ASN_tag)
                    found_values_ASN_decoded.append('Base64_decode_failed',e)
                    break

                # This is to prepare for manual replacing of certain non-ASCII 
                # characters in names for difficult decode cases
                
                character = re.compile(b'(.){0,12}[^\x00-\x7F](.){0,12},(.){0,26},\d{11}')
                character2 = re.compile(b'(.){0,24},(.){0,12}[^\x00-\x7F](.){0,12},\d{11}')
                result = re.search(character,decoded_base64)
                result2 = re.search(character2,decoded_base64)

                if result:
                    if result.group(0) is not None:
                        additional_field = str(result.group(0))
                        additional_field = additional_field.replace("b'","'")
                        additional_field = additional_field.replace('"','')
                        additional_field = additional_field.replace("'","")
                if result2:
                    if result2.group(0) is not None:
                        additional_field = str(result2.group(0))
                        additional_field = additional_field.replace("b'","'")
                        additional_field = additional_field.replace('"','')
                        additional_field = additional_field.replace("'","")
                try:
                    decoded_ASN_1_datablock = decoder.decode(decoded_base64)
                except BaseException as e:
                    print('ASN.1 decode failed in',ASN_tag)
                    found_values_ASN_decoded.append('ASN.1_decode_failed',e)
                    break
                decoded_ASN_1_datablock = str(decoded_ASN_1_datablock[0])

                for useful_attribute in self.useful_attributes:
                    
                    # This is manual decoding of especially rare characters 
                    # for which 'BMPString' datatype seems to be used
                    # which stores them in HEX instead of text
                    # In large sample case of 3873 (3869 signed) files there was only one such 
                    # name encountered. The name will be retrieved, but this character
                    # will remain not decoded correctly

                    if useful_attribute == 'BMPString':
                        useful_attribute_prepared_string = re.escape(
                            useful_attribute) + ".{1,110}hexValue='.{1,110}'"
                        if re.findall(useful_attribute_prepared_string, decoded_ASN_1_datablock):
                            match = re.findall(useful_attribute_prepared_string, decoded_ASN_1_datablock)
                            for each_match in match:
                                split = each_match.split("'")
                                hex_decoded = bytearray.fromhex(split[1]).decode("ascii",errors="ignore")
                                hex_decoded = hex_decoded.replace('\x00','')
                                if hex_decoded.find(',') > -1:
                                    found_values_ASN_decoded.append(hex_decoded)
                                    if self.format_ == 'Short':
                                        short_values = hex_decoded
                                    
                    useful_attribute_prepared_string = re.escape(   #Administratively 
                    # set max distance of ASN.1 attr value
                        useful_attribute) + "\('.{0,50}'"
                    if re.findall(useful_attribute_prepared_string, decoded_ASN_1_datablock):
                        match = re.findall(useful_attribute_prepared_string, decoded_ASN_1_datablock)
                        match_iterator = 0
                        for each_match in match:
                            
                            split = each_match.split("'")
                            found_values_ASN_decoded.append(split[1])

                            # Makes short list, see 'config.ini' #

                            if self.format_ == 'Short':
                                if split[1] == 'Corporate Signature':
                                    corporate_match = match[match_iterator+1]
                                    split_ = corporate_match.split("'")
                                    short_values = split_[1]
                                if re.findall(name_and_code,split[1]):
                                    match_2 = re.search(name_and_code,split[1])
                                    if len(match_2.group(0)) > 0:
                                        short_values = match_2.group(0)

                            else:
                                pass

                            match_iterator += 1

                            # Replace some hard-to-decode characters #
                            if split[1] == 'digital signature' and additional_field is not '':
                                additional_field = additional_field.replace("'","")
                                additional_field = re.sub('^.{0,40}03U.{2}04.{2}03.{2}0c(.x..|.)?',
                                '',additional_field)
                                hex_ = [
                                    r'\xc3\x9c',r'\xc3\x96',
                                    r'\xc3\x95',r'\xc3\x84',
                                    r'\xc5\xa0',r'\xc5\xbd',
                                    '\xc4\xa0']
                                utf_ = ['Ü','Ö','Õ','Ä','Š','Ž','Ġ']
                                for orig,repl in zip(hex_,utf_):
                                    additional_field = str(additional_field.replace(orig,repl))
                                short_values = additional_field
                                found_values_ASN_decoded.append(additional_field)
                                

        return found_values_ASN_decoded,short_values,date_to_add
    
    def write_recovered_data_to_file(self,data,destination):

        """
        This will save recovered file data to a file in Results folder, 
        provided a name was given.
        """    
        destination = os.path.join(os.getcwd(),self.result,destination)
        if len(data) > 0:
            file = open(destination, 'wb')
            file.write(data)
            file.close()
    
    def write_links_to_file(self,Resulting_CSV):

        ''' Write recovered attributive data to file '''

        from datetime import datetime

        if len(Resulting_CSV) == 0:
            print('No attributes were written.')
            return

        current_time_to_filename = datetime.now().strftime('%d_%m_%Y_%H_%M_%S_%f')
        basename = current_time_to_filename + "_recovered_attributes_" + str(
            len(Resulting_CSV)) + ".txt"
        filename = os.path.join(os.getcwd(), basename)

        line_by_line_file = open(filename, 'w', encoding="utf-8")
        for line in Resulting_CSV:
            try:
                line_by_line_file.write("%s\n" % line)
            except BaseException as e:
                print("Failed writing line-to-line to file:",e)

        line_by_line_file.close()

        print('File',basename,'of',str(len(Resulting_CSV)),'lines written.')

    def write_links_to_xlsx(self,Resulting_CSV):
        
        ''' Create MS Excel '''
        
        import pandas

        from datetime import datetime

        if len(Resulting_CSV) == 0:
            print('No attributes were written.')
            return
        
        dataframe = pandas.DataFrame([sub.split(';') for sub in Resulting_CSV])
        dataframe.columns = dataframe.iloc[0]
        dataframe = dataframe[1:]

        current_time_to_filename = datetime.now().strftime('%d_%m_%Y_%H_%M_%S_%f')
        basename = current_time_to_filename + "_recovered_attributes_" + str(
            len(Resulting_CSV)) + ".xlsx"
        filename = os.path.join(os.getcwd(), basename)

        writer = pandas.ExcelWriter(filename, engine='xlsxwriter')
        dataframe.to_excel(writer, sheet_name='Data')
        writer.save()

        print('File',basename,'of',str(len(Resulting_CSV)),'lines written.')

if __name__ == "__main__":
    
    import os
    import re

    # Variables from setup #

    files = Bdoc_Finder().files
    images = Bdoc_Finder().images
    carve = Bdoc_Finder().carve

    # Variables to collect results #

    line_to_save = 'File;Signed docs;Layer;Contents;Contents 2'
    short_line_to_save = 'File;No of Sign;Name,Surname,Personal Code;Date'

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
                        print(destination,'tested as BDOC file size of',str(len(data)))
                    else:
                        if any("manifest.xml" in _file for _file in list_of_DSD):
                            # Known files having manifest.xml but there are files
                            # without signature. They include: unsigned BDOC, 
                            # unsigned ASICE; also: ODT, ODF files
                            print('Possible unsigned BDOC',destination,'detected, file size',str(len(data)))
                        else:
                            print(destination,'failed BDOC test, file size',str(len(data)))
                except BaseException as e:
                    print('Failed trying to check if',destination,'ZIP because of',e)
                
                for comment in comments:
                    
                    # Add ZIP #
                    
                    line_to_save = destination +';'+ list_of_files +';ZIP;'+ comment +';'
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

                    short_line_to_save = destination +';'+ "Signature_" + str(iterator)+ ';' + short_values + ';' + date_to_add

                    if testing_for_bdoc == True:
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
                                print(destination,'recovered a BDOC file size of',str(len(data)))
                                if carve == 'True':
                                    Bdoc_Finder().write_recovered_data_to_file(data,destination)
                            else:
                                print(destination,'failed BDOC test',str(len(data)))
                                destination = 'Malformed_' + destination
                                if carve == 'True':
                                    Bdoc_Finder().write_recovered_data_to_file(data,destination)                
                            
                        except BaseException as e:
                            print('Failed trying to check if',destination,'ZIP because of',e)   
                    
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

                            short_line_to_save = destination +';'+ "Signature_" + str(iterator)+ ';' + short_values + ';' + date_to_add
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
        try:
            Bdoc_Finder().write_links_to_xlsx(Resulting_CSV)
        except:
            print('Could not write to XLSX, writing to CSV instead.')
            Bdoc_Finder().write_links_to_file(Resulting_CSV)

    if len(Short_csv) > 1 and Bdoc_Finder().format_ == 'Short':
        try:
            Bdoc_Finder().write_links_to_xlsx(Short_csv)
        except:
            print('Could not write to XLSX, writing to CSV instead.')
            Bdoc_Finder().write_links_to_file(Short_csv)
