/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/* Test Pointer Auttributes */

#include <sys/types.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_key.h"
#include "sgx_tseal.h"
#include "../Enclave.h"
#include "Enclave_t.h"

#define MAX_FILE_LEN 4096

#define MIN_USERNAME_LEN 3
#define MAX_USERNAME_LEN 8
#define MIN_PASSWORD_LEN 3
#define MAX_PASSWORD_LEN 32
#define MAX_ATTEMPTS 3
char *USERNAME = NULL;
char *PASSWORD = NULL;
sgx_sealed_data_t *SEALED_DATA = NULL;

/* checksum_internal:
 *   get simple checksum of input buffer and length
 */
int32_t checksum_internal(char *buf, size_t count)
{
    register int32_t sum = 0;
    int16_t *ptr = (int16_t *)buf;

    /* Main summing loop */
    while(count > 1) {
        sum = sum + *ptr++;
        count = count - 2;
    }

    /* Add left-over byte, if any */
    if (count > 0)
        sum = sum + *((char *)ptr);

	return ~sum;
}

/* ecall_pointer_user_check, ecall_pointer_in, ecall_pointer_out, ecall_pointer_in_out:
 *   The root ECALLs to test [in], [out], [user_check] attributes.
 */
size_t ecall_pointer_user_check(void *val, size_t sz)
{
    /* check if the buffer is allocated outside */
    if (sgx_is_outside_enclave(val, sz) != 1)
        abort();

    char tmp[100] = {0};
    size_t len = sz>100?100:sz;
    
    /* copy the memory into the enclave to make sure 'val' 
     * is not being changed in checksum_internal() */
    memcpy(tmp, val, len);
    
    int32_t sum = checksum_internal((char *)tmp, len);
    printf("Checksum(0x%p, %zu) = 0x%x\n", 
            val, len, sum);
    
    /* modify outside memory directly */
    memcpy(val, "SGX_SUCCESS", len>12?12:len);

	return len;
}

/* ecall_pointer_in:
 *   the buffer of val is copied to the enclave.
 */

void ecall_pointer_in(int *val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    *val = 1234;
}

/* ecall_pointer_out:
 *   the buffer of val is copied to the untrusted side.
 */
void ecall_pointer_out(int *val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    assert(*val == 0);
    *val = 1234;
}

/* ecall_pointer_in_out:
 * the buffer of val is double-copied.
 */
void ecall_pointer_in_out(int *val)
{
    if (sgx_is_within_enclave(val, sizeof(int)) != 1)
        abort();
    *val = 1234;
}

/* ocall_pointer_attr:
 *   The root ECALL that test OCALL [in], [out], [user_check].
 */
void ocall_pointer_attr(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    int val = 0;
    ret = ocall_pointer_user_check(&val);
    if (ret != SGX_SUCCESS)
        abort();

    val = 0;
    ret = ocall_pointer_in(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 0);

    val = 0;
    ret = ocall_pointer_out(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);

    val = 0;
    ret = ocall_pointer_in_out(&val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);

    return;
}

/* ecall_pointer_string:
 *   [string] defines a string.
 */
void ecall_pointer_string(char *str)
{
    strncpy(str, "0987654321", strlen(str));
}

/* ecall_pointer_string_const:
 *   const [string] defines a string that cannot be modified.
 */
void ecall_pointer_string_const(const char *str)
{
    char* temp = new char[strlen(str)];
    strncpy(temp, str, strlen(str));
    delete []temp;
}

/* ecall_pointer_size:
 *   'len' needs to be specified to tell Edger8r the length of 'str'.
 */
void ecall_pointer_size(void *ptr, size_t len)
{
    strncpy((char*)ptr, "0987654321", len);
}

/* ecall_pointer_count:
 *   'cnt' needs to be specified to tell Edger8r the number of elements in 'arr'.
 */
void ecall_pointer_count(int *arr, int cnt)
{
    for (int i = (cnt - 1); i >= 0; i--)
        arr[i] = (cnt - 1 - i);
}

/* ecall_pointer_isptr_readonly:
 *   'buf' is user defined type, shall be tagged with [isptr].
 *   if it's not writable, [readonly] shall be specified. 
 */
void ecall_pointer_isptr_readonly(buffer_t buf, size_t len)
{
    strncpy((char*)buf, "0987654321", len);
}

/* get_buffer_len:
 *   get the length of input buffer 'buf'.
 */
size_t get_buffer_len(const char* buf)
{
    (void)buf;
    return 10*sizeof(int);
}

/* ecall_pointer_sizefunc:
 *   call get_buffer_len to determine the length of 'buf'.
 */
void ecall_pointer_sizefunc(char *buf)
{
    int *tmp = (int*)buf;
    for (int i = 0; i < 10; i++) {
        assert(tmp[i] == 0);
        tmp[i] = i;
    }
}

int is_valid_username(char *username)
{
  if (username == NULL)
    return 0;

  size_t username_len = 0;

  while (username[username_len] != '\0' && username_len < MAX_USERNAME_LEN)
    username_len++;
  if (username_len < MIN_USERNAME_LEN || username[username_len] != '\0') {
    ocall_printf_string_2_ints("Username must be between %u and %u characters long.\n",
			       MIN_USERNAME_LEN, MAX_USERNAME_LEN);
    return 0;
  }
  return 1;
}

int is_valid_password(char *password)
{
  if (password == NULL)
    return 0;

  size_t password_len = 0;
  
  while (password[password_len] != '\0' && password_len < MAX_PASSWORD_LEN)
    password_len++;
  if (password_len < MIN_PASSWORD_LEN || password[password_len] != '\0') {
    ocall_printf_string_2_ints("Password must be between %u and %u characters long.\n",
			       MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
    return 0;
  }
  return 1;
} 

int is_valid_user(char *username, char *password)
{
  // username and password must have MAX_XXX_LEN + 1 bytes allocated
  
  if (username == NULL || password == NULL)
    abort();
  
  return is_valid_username(username) & is_valid_password(password);
}

int auth_user(char *username, char *password)
{
  if (USERNAME == NULL || PASSWORD == NULL)
    abort();
  
  if (strcmp(username, USERNAME) != 0 || strcmp(password, PASSWORD) != 0) {
    ocall_print_string("Invalid username or password.\n");
    return 0;
  }
  return 1;
}

void ecall_encrypt_file(char *fn)
{  
  assert(USERNAME == NULL && PASSWORD == NULL && SEALED_DATA == NULL);

  sgx_status_t ret;

  // Read file given by fn.
  char in_buf[MAX_FILE_LEN + 1];
  ret = ocall_fopen_and_read((void *) in_buf, MAX_FILE_LEN, fn);
  if (ret != SGX_SUCCESS)
    abort();
  in_buf[MAX_FILE_LEN] = '\0';
  size_t in_buf_len = strlen(in_buf);

  char suffix[] = "_encrypted";
  size_t fn_len = strlen(fn);
  size_t suffix_len = strlen(suffix);

  // Allocate name of file to store encrypted data.
  char *fn_enc = (char *) calloc(1, fn_len + suffix_len);
  if (fn_enc == NULL)
    abort();
  strncat(fn_enc, fn, fn_len);
  strncat(fn_enc, suffix, suffix_len);

  // Get username and password from user.
  USERNAME = (char *) calloc(1, MAX_USERNAME_LEN + 1);
  PASSWORD = (char *) calloc(1, MAX_PASSWORD_LEN + 1);
  int ocall_success;
  do {
    ret = ocall_set_user(USERNAME, MAX_USERNAME_LEN, PASSWORD, MAX_PASSWORD_LEN, &ocall_success);
    if (ret != SGX_SUCCESS)
      abort();
  } while (ocall_success == 0 || is_valid_user(USERNAME, PASSWORD) == 0);
    
  // Seal data.
  uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, in_buf_len);
  if (sealed_data_size == 0xFFFFFFFF)
    abort();
  SEALED_DATA = (sgx_sealed_data_t *) malloc(sealed_data_size);
  ret = sgx_seal_data(0, NULL, in_buf_len, (uint8_t *) in_buf, sealed_data_size, SEALED_DATA);
  if (ret != SGX_SUCCESS)
    abort();

  // Write sealed data payload to file for inspection.
  sgx_aes_gcm_data_t aes_data = SEALED_DATA->aes_data;
  char *out_buf = (char *) malloc(aes_data.payload_size + 1);
  memcpy(out_buf, aes_data.payload, aes_data.payload_size);
  out_buf[aes_data.payload_size] = '\0';
  ocall_fopen_and_write(out_buf, fn_enc);
}

void ecall_decrypt_file(char *fn)
{
  assert(USERNAME != NULL && PASSWORD != NULL && SEALED_DATA != NULL);
  
  sgx_status_t ret;

  char suffix[] = "_decrypted";
  size_t fn_len = strlen(fn);
  size_t suffix_len = strlen(suffix);

  char *fn_dec = (char *) calloc(1, fn_len + suffix_len);
  if (fn_dec == NULL)
    abort();
  strncat(fn_dec, fn, fn_len);
  strncat(fn_dec, suffix, suffix_len);

  char *username = (char *) malloc(MAX_USERNAME_LEN + 1);
  char *password = (char *) malloc(MAX_PASSWORD_LEN + 1);
  int ocall_success, attempt = 0;
  ocall_print_string("Need to authenticate.\n");
  do {
    if (attempt >= MAX_ATTEMPTS) {
      ocall_print_string("Max attempts reached. Abort.\n");
      abort();
    }
    ret = ocall_get_user(username, MAX_USERNAME_LEN, password, MAX_PASSWORD_LEN, &ocall_success);
    if (ret != SGX_SUCCESS)
      abort();
    attempt++;
  } while (ocall_success == 0 || auth_user(username, password) == 0);

  uint32_t decrypted_len = sgx_get_encrypt_txt_len(SEALED_DATA);
  if (decrypted_len == 0xFFFFFFFF)
    abort();
  char *out_buf = (char *) malloc(decrypted_len + 1);
  uint32_t MAC_len = 0;
  ret = sgx_unseal_data(SEALED_DATA, NULL, &MAC_len, (uint8_t *) out_buf, &decrypted_len);
  if (ret != SGX_SUCCESS)
    abort();
  out_buf[decrypted_len] = '\0';
  ret = ocall_print_string(out_buf);
  if (ret != SGX_SUCCESS)
    abort();
  ret = ocall_fopen_and_write(out_buf, fn_dec);
  if (ret != SGX_SUCCESS)
    abort();
}
