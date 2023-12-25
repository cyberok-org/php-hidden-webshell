EXT_PATH=/home/user/php7_module/
PHP_SOURCE_PATH=/ssd/php_74/php-7.4.29
PHP_INSTALL_PATH=/ssd/php_74/php-7.4.29-binary
php "$PHP_SOURCE_PATH/ext/ext_skel.php" --ext example --dir "$EXT_PATH" --onlyunix
cp ./files/* "$EXT_PATH/example"
cd "$EXT_PATH/example"
$PHP_INSTALL_PATH/bin/phpize
./configure CFLAGS="-O0 -fno-stack-protector" --with-php-config="$PHP_INSTALL_PATH/bin/php-config"
make
python3 get_shellcode.py > out.txt