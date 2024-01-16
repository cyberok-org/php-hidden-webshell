## Summary
This research presents proof-of-concept of fileless web-shell for PHP language. 
PHP memory corruption bug [#81992](https://bugs.php.net/bug.php?id=81992) is used for reading and writing into PHP process memory. Using ROP-chain in PHP, shellcode is copied into process memory. Then pointer in zend_module_entry structure is overwritten to point into shellcode. This gives a persistent backdoor in PHP process.
Proof-of-concept developed for PHP 7.4.33 / Apache web server.