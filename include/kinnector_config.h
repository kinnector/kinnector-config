#ifndef KINNECTOR_CONFIG_H
#define KINNECTOR_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque struct representing the config manager
typedef struct kinnector_config_t kinnector_config_t;

// Signer info struct matching Rust's FFI representation
typedef struct {
    const char* signer_name;
    const char* team_id;
    bool is_signed;
} signer_info_t;

// FFI methods
int kinnector_config_load(const char* path, const uint8_t* public_key, kinnector_config_t** out_config);
int kinnector_config_reload(kinnector_config_t* config);
bool kinnector_config_is_path_excluded(kinnector_config_t* config, const char* file_path);
bool kinnector_config_is_trusted_vendor(kinnector_config_t* config, const signer_info_t* signer);
bool kinnector_config_is_trusted_cli(kinnector_config_t* config, const char* binary_path, uint32_t category_flag);
bool kinnector_config_is_domain_allowed(kinnector_config_t* config, const char* domain);
void kinnector_config_free(kinnector_config_t* config);

#ifdef __cplusplus
}
#endif

#endif // KINNECTOR_CONFIG_H
