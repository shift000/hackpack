import sys

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

# STEP 1 : EXTRACT BASE64 ENCODED PARTS FROM EML FILE
with open(file, 'r') as f:
    l_found = False
    current_found_content = None

    for line in f.readlines():
        
        if line.find('--=_') > -1 and 'boundary' not in line:
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
                if 'Content-' in line:
                    lx = line.replace('\n', '').strip().split(':')
                    lx_key = lx[0]
                    lx_val = lx[1].strip()

                    for key in current_found_content.properties.keys():
                        if key in lx_key.lower():
                            if lx_val[-1] == ';':
                                lx_val = lx_val[:-1]
                            current_found_content.set_property(key, lx_val)
                            print(f'[+] Found {key} in {lx_key.lower()}')

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
                else:
                    current_found_content.add_data(line)

print(f"created {conf['parts']} parts for {conf['file']}".replace('\n', ''))
exit()

# STEP 2 : PARSE AND "REPAIR" PARTS AND OUTPUT THEM AS SINGLE FILES - FILETYPE AS DEFINED IN HEADER
file_out = ''

with open(file, 'rb') as f:
    for line in f.readlines():
        for char in line:
            #'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!"§$%&/()=?#\'+-/*~\\}][{³²^°<>|_.:,;äÄöÖüÜ´`'
            if char in [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 33, 34, 167, 36, 37, 38, 47, 40, 41, 61, 63, 35, 39, 43, 45, 47, 42, 126, 92, 125, 93, 91, 123, 179, 178, 94, 176, 60, 62, 124, 95, 46, 58, 44, 59, 228, 196, 246, 214, 252, 220, 180, 96]:
                file_out += ord(char)
with open(f'{file}_cleaned', 'w+') as f:
    f.write(file_out)

print('successfully repaired file...')
