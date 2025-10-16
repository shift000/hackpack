import sys, base64

file = sys.argv[1]

conf = {
    'parts': 0,
    'file': file
}

class ContentPart:
    def __init__(self):
        self.properties = {
            'name':         'None',
            'encoding':     'None',
            'type':         'None',
            'charset':      'None',
            'disposition':  'None',
        }
        self.data = []
    
    def set_property(self, key, value):
        if key in self.properties.keys():
            self.properties[key] = value
            return 0
        return -1

    def get_property(self, key):
        if key in self.properties.keys():
            return self.properties[key]
        return -1

    def get_all_properties(self):
        rt = ''
        for k, v in self.properties.items():
            rt += f'{v}|'
        return rt[:-1]

    def add_data(self, data):
        if data:
            self.data.append(data)
            return 0
        return -1

    def get_data(self):
        return self.data

    def get_data_len(self):
        return len(self.data)
        

def write_part(cp):
    try:
        with open(f"{conf['file']}_{conf['parts']}", 'w+') as f:
            # Write Content Properties
            f.write(f'{cp.get_all_properties()}\n')

            max_parts = cp.get_data_len() - 1
            part_no = 0

            for fp in cp.get_data():
                if part_no == max_parts:
                    fp = fp.replace('\n', '')
                f.write(f'{fp}')
                part_no += 1
        conf['parts'] += 1
        return 0
    except Exception as e:
        print(f'Error while writing part: {e}!')
        return -1


def decode_base64(a, encoding):
    encoding = str(encoding, 'utf-8')
    missing_padding = len(a) % 4
    if missing_padding:
        a += b'=' * (4 - missing_padding)
    return base64.b64decode(str(a, 'utf-8').encode(encoding)).decode(encoding)


def line_has_content_indicator(line):
    ptr = 0
    sptr = ['-', '=', '_']
    if len(line) > 0:
        if line[0] not in sptr:
            return False

        for c in line:
            if c == sptr[ptr]:
                continue
            else:
                if ptr < len(sptr)-1 and c == sptr[ptr+1]:
                    ptr += 1
                    continue
                else:
                    if c in [str(e) for e in range(10)]:
                        return True
    return False

# STEP 1 : EXTRACT BASE64 ENCODED PARTS FROM EML FILE
with open(file, 'r') as f:
    l_found = False
    current_found_content = None

    for line in f.readlines():
        if line_has_content_indicator(line):
            if l_found:
                if not write_part(current_found_content) == 0:
                    print('Exiting on error..')
                    exit()
            
            current_found_content = None
            current_found_content = ContentPart()
            l_found = True
        elif l_found:
            if line not in ['\n', '\r', '\r\n'] and len(line) > 1:
                
                # Content-
                try:
                    if 'Content-' in line:
                        lx = line.replace('\n', '').strip().split(':')
                        lx_key = lx[0]
                        lx_val = lx[1].strip()

                        for key in current_found_content.properties.keys():
                            if key in lx_key.lower():
                                if lx_val[-1] == ';':
                                    lx_val = lx_val[:-1]
                                current_found_content.set_property(key, lx_val)
                                print(f'[+] Found key[{key}]> {lx_val.lower()}')

                    # Value
                    elif line[0] == '\t':
                        key = line.split('=')[0]
                        value = ''.join(line.split('=')[1:]).replace('\n', '')

                        if value[0] == '"':
                            value = value[1:]
                        if value.endswith('";'):
                            value = value[:-2]
                        elif value.endswith('"'):
                            value = value[:-1]

                        lx_key = key.replace("\t", " ")
                        lx_val = value.replace('\n', '')
                        for key in current_found_content.properties.keys():
                            if key in lx_key.lower():
                                current_found_content.set_property(key, lx_val)
                                print(f'  [+] Found subkey[{key}]> {lx_val.lower()}')
                    else:
                        current_found_content.add_data(line)
                except Exception as e:
                    print(f'Exception while extracting content: {e}')
    print('\n')

# STEP 2 : PARSE AND "REPAIR" PARTS AND OUTPUT THEM AS SINGLE FILES - FILETYPE AS DEFINED IN HEADER
types_to_parse = [e for e in ('application', 'image')]

for part_no in range(conf['parts']):
    part_data = {
        'name':     'None',
        'encoding': 'None',
        'type':     'None',
        'charset':  'None',
        'disposition': 'None',
        'data':     '',
        'skipped':  False
    }
    with open(f'{conf["file"]}_{part_no}', 'rb') as f:
        for i, line in enumerate(f.readlines()):
            line = line.replace(bytes('\n', 'utf-8'), b'')
            if i==0: # first line with block information
                header                  = line.split(b'|')
                part_data['name']       = header[0]
                part_data['encoding']   = header[1]
                part_data['type']       = header[2]
                part_data['charset']    = header[3]
                part_data['dispostion'] = header[4]

                if str(part_data["type"].split(b"/")[0], "utf-8") in types_to_parse:
                    if part_data['charset'] == b'utf-8':
                        part_data['name'] = decode_base64(part_data['name'].replace(b'?UTF-8?B?', b'')[:-1], part_data['charset'])

                else:
                    print('No attachment - skipping..')
                    part_data['skipped'] = True
                    break

                # skip first line, should not be in file
                continue
            for char in line:
                #'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!"§$%&/()=?#\'+-/*~\\}][{³²^°<>|_.:,;äÄöÖüÜ´`'
                if char in [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 33, 34, 167, 36, 37, 38, 47, 40, 41, 61, 63, 35, 39, 43, 45, 47, 42, 126, 92, 125, 93, 91, 123, 179, 178, 94, 176, 60, 62, 124, 95, 46, 58, 44, 59, 228, 196, 246, 214, 252, 220, 180, 96]:
                    part_data['data'] += chr(char)
    
        if not part_data['skipped']:
            cleaned_file_name = f'{conf["file"]}_{part_no}_{str(part_data["type"].split(b"/")[0], "utf-8")}'
            with open(f'{cleaned_file_name}', 'w+') as f:
                f.write(part_data['data'])
            print(f'cleaned attachment file {cleaned_file_name}')
