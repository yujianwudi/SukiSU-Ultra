#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>
#include "ksu.h"

bool is_manager_apk(char *path);

struct dynamic_sign_config {
    unsigned int size;
    char hash[65];
    int is_set;
};

int ksu_handle_dynamic_sign(struct dynamic_sign_user_config *config);
void ksu_dynamic_sign_init(void);
void ksu_dynamic_sign_exit(void);
bool ksu_load_dynamic_sign(void);

#endif