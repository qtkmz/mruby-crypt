#include <string.h>
#include "openssl/md5.h"
#include "mruby.h"
#include "mruby/class.h"
#include "mruby/string.h"

static char ascii64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static int crypt_md5_encrypt(char *output, char *password, char *key, char *salt)
{
    int i;
    char *p;
    unsigned char final[16];
    MD5_CTX  md1;
    MD5_CTX  md2;
    MD5_CTX  ctx1;

    MD5_Init(&md1);
    MD5_Update(&md1, password, strlen(password));
    MD5_Update(&md1, key, strlen(key));
    MD5_Update(&md1, salt, strlen(salt));

    MD5_Init(&md2);
    MD5_Update(&md2, password, strlen(password));
    MD5_Update(&md2, salt, strlen(salt));
    MD5_Update(&md2, password, strlen(password));
    MD5_Final(final, &md2);

    for (i = strlen(password); i > 0; i -= 16) {
        MD5_Update(&md1, final, i > 16 ? 16 : i);
    }

    for (i = strlen(password); i; i >>= 1) {
        if (i & 1) {
            MD5_Update(&md1, "\0", 1);
        } else {
            MD5_Update(&md1, password, 1);
        }
    }
    MD5_Final(final, &md1);

    for (i = 0; i < 1000; i++) {
        MD5_Init(&ctx1);
         if (i & 1) {
            MD5_Update(&ctx1, password, strlen(password));
        } else {
            MD5_Update(&ctx1, final, 16);
        }

        if (i % 3) {
            MD5_Update(&ctx1, salt, strlen(salt));
        }

        if (i % 7) {
            MD5_Update(&ctx1, password, strlen(password));
        }

        if (i & 1) {
            MD5_Update(&ctx1, final, 16);
        } else {
            MD5_Update(&ctx1, password, strlen(password));
        }

        MD5_Final(final, &ctx1);
    }

    p = output;
    for (i = 0; i < 5; i++) {
        if (i == 4) {
            *p++ = ascii64[final[5] & 0x3f];
            *p++ = ascii64[(final[i + 6] & 0xf) << 2 | final[5] >> 6];
        } else {
            *p++ = ascii64[final[i + 12] & 0x3f];
            *p++ = ascii64[(final[i + 6] & 0xf) << 2 | final[i + 12] >> 6];
        }
        *p++ = ascii64[(final[i] & 0x3) << 4 | final[i + 6] >> 4];
        *p++ = ascii64[final[i] >> 2];
    }
    *p++ = ascii64[final[11] & 0x3f];
    *p++ = ascii64[final[11] >> 6];
    *p = '\0';

    return 0;
}

static mrb_value mrb_crypt_aprmd5_encrypt(mrb_state *mrb, mrb_value self)
{
    mrb_value arg_key, arg_salt;
    char *key, *salt;
    char *head, *tail;
    char salt_str[8];
    int salt_len;
    char r[6 + 8 + 1 + 22 + 1] = "$apr1$";

    mrb_get_args(mrb, "SS", &arg_key, &arg_salt);
    key = RSTR_PTR(mrb_str_ptr(arg_key));
    salt = RSTR_PTR(mrb_str_ptr(arg_salt));

    if (strncmp(salt, "$apr1$", sizeof("$apr1") - 1) != 0) {
        return mrb_nil_value();
    }

    head = salt + sizeof("$apr1$") - 1;
    tail = strchr(head, '$');
    if (tail == NULL) {
        return mrb_nil_value();
    }

    salt_len = tail - head;
    if (8 < salt_len) {
        return mrb_nil_value();
    }
    strncpy(salt_str, head, salt_len);
    salt_str[salt_len] = '\0';

    strncat(r, salt_str, salt_len);
    strncat(r, "$", 1);

    crypt_md5_encrypt(r + 1 + sizeof("$apr1$") - 1 + salt_len, key, "$apr1$", salt_str);

    return mrb_str_new(mrb, r, strlen(r));
}

void mrb_mruby_crypt_gem_init(mrb_state* mrb)
{
    struct RClass *module_crypt, *class_aprmd5;

    module_crypt = mrb_define_module(mrb, "Crypt");

    class_aprmd5 = mrb_define_class_under(mrb, module_crypt, "APRMD5", mrb->object_class);
    mrb_define_class_method(mrb, class_aprmd5, "encrypt", mrb_crypt_aprmd5_encrypt, MRB_ARGS_REQ(2));
}

void mrb_mruby_crypt_gem_final(mrb_state* mrb)
{
}
