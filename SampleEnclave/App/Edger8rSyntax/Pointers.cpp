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


#include <stdio.h>

#include "../App.h"
#include "Enclave_u.h"

/* edger8r_pointer_attributes:
 *   Invokes the ECALLs declared with pointer attributes.
 */
void edger8r_pointer_attributes(void)
{
    int val = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    char c[128] = {0};
    size_t len = 0;
    memset(c, 0xe, 128);
    ret = ecall_pointer_user_check(global_eid, &len, &c, 128);
    if (ret != SGX_SUCCESS)
        abort();
    assert(strcmp(c, "SGX_SUCCESS") == 0);


    val = 0;
    ret = ecall_pointer_in(global_eid, &val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 0);
    
    val = 0;
    ret = ecall_pointer_out(global_eid, &val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);
    
    val = 0;
    ret = ecall_pointer_in_out(global_eid, &val);
    if (ret != SGX_SUCCESS)
        abort();
    assert(val == 1234);
    
    ret = ocall_pointer_attr(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    char str1[] = "1234567890";
    ret = ecall_pointer_string(global_eid, str1);
    if (ret != SGX_SUCCESS)
        abort();
    assert(memcmp(str1, "0987654321", strlen(str1)) == 0);

    const char str2[] = "1234567890";
    ret = ecall_pointer_string_const(global_eid, str2);
    if (ret != SGX_SUCCESS)
        abort();
    assert(memcmp(str2, "1234567890", strlen(str2)) == 0);

    char str3[] = "1234567890";
    ret = ecall_pointer_size(global_eid, (void*)str3, strlen(str3));
    if (ret != SGX_SUCCESS)
        abort();
    assert(memcmp(str3, "0987654321", strlen(str3)) == 0);

    char str4[] = "1234567890";
    ret = ecall_pointer_isptr_readonly(global_eid, (buffer_t)str4, strlen(str4));
    if (ret != SGX_SUCCESS)
        abort();
    assert(memcmp(str4, "1234567890", strlen(str4)) == 0);

    int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    ret = ecall_pointer_count(global_eid, arr, 10);
    if (ret != SGX_SUCCESS)
        abort();

    for (int i = 0; i < 10; i++)
        assert(arr[i] == (9 - i));
    
    memset(arr, 0x0, sizeof(arr));
    ret = ecall_pointer_sizefunc(global_eid, (char *)arr);
    if (ret != SGX_SUCCESS)
        abort();

    for (int i = 0; i < 10; i++)
        assert(arr[i] == i);

    char fn[] = "test";
    ret = ecall_encrypt_file(global_eid, fn);
    if (ret != SGX_SUCCESS)
      abort();

    char fn_enc[] = "test_encrypted";
    ret = ecall_decrypt_file(global_eid, fn_enc);
    if (ret != SGX_SUCCESS)
      abort();
    
    return;
}

/* ocall_pointer_user_check:
 *   The OCALL declared with [user_check].
 */
void ocall_pointer_user_check(int* val)
{
    (void)val;
    assert(val != NULL);
}

/* ocall_pointer_in:
 *   The OCALL declared with [in].
 */
void ocall_pointer_in(int* val)
{
    *val = 1234;
}

/* ocall_pointer_out:
 *   The OCALL declared with [out].
 */
void ocall_pointer_out(int* val)
{
    *val = 1234;
}

/* ocall_pointer_in_out:
 *   The OCALL declared with [in, out].
 */
void ocall_pointer_in_out(int* val)
{
    *val = 1234;
}

void ocall_fopen_and_read(void *buf_, size_t len, char *fn)
{
  printf("In ocall_fopen_and_read\n");
  printf("Reading up to %lu bytes from %s\n", len, fn);
  
  char *buf = (char *) buf_;
  memset(buf, 0x0, len);
  FILE *fp = fopen(fn, "r");
  if (fp == NULL)
    return;

  fread(buf, sizeof(char), len, fp);
  fclose(fp);
}

void ocall_fopen_and_write(char *buf, char *fn)
{
  printf("In ocall_fopen_and_write\n");
  printf("Writing %s to %s\n", buf, fn);
  
  FILE *fp = fopen(fn, "w");
  if (fp == NULL)
    return;
  printf("Here\n");

  fwrite(buf, sizeof(char), strlen(buf), fp);
  fclose(fp);
}

void ocall_set_user(char *username, size_t username_len, char *password, size_t password_len, int *success)
{
  *success = 0;
  memset(username, '\0', username_len);
  memset(password, '\0', password_len);
  
  char c;
  int i, extra;
  
  printf("Creating new user\n");
  printf("Enter username: ");
  fflush(stdout);

  if (fgets(username, username_len, stdin) == NULL)
    return;
  // Flush to end of line if necessary
  i = 0;
  while (i < username_len) {
    if (username[i] == '\n') {
      username[i] = '\0';
      break;
    }
    i++;
  }
  if (i == username_len) {
    extra = 0;
    while ((c = getchar()) != '\n' && c != EOF)
      extra = 1;
    if (extra == 1)
      return;
  }

  printf("Enter password: ");
  fflush(stdout);

  if (fgets(password, password_len, stdin) == NULL)
    return;
  // Flush to end of line if necessary
  i = 0;
  while (i < password_len) {
    if (password[i] == '\n') {
      password[i] = '\0';
      break;
    }
    i++;
  }
  if (i == password_len) {
    extra = 0;
    while ((c = getchar()) != '\n' && c != EOF)
      extra = 1;
    if (extra == 1)
      return;
  }

  *success = 1;
}

void ocall_get_user(char *username, size_t username_len, char *password, size_t password_len, int *success)
{
  *success = 0;
  memset(username, '\0', username_len);
  memset(password, '\0', password_len);
  
  char c;
  int i, extra;
  
  printf("Need to authenticate\n");
  printf("Enter username: ");
  fflush(stdout);

  if (fgets(username, username_len, stdin) == NULL)
    return;
  // Flush to end of line if necessary
  i = 0;
  while (i < username_len) {
    if (username[i] == '\n') {
      username[i] = '\0';
      break;
    }
    i++;
  }
  if (i == username_len) {
    extra = 0;
    while ((c = getchar()) != '\n' && c != EOF)
      extra = 1;
    if (extra == 1)
      return;
  }

  printf("Enter password: ");
  fflush(stdout);

  if (fgets(password, password_len, stdin) == NULL)
    return;
  // Flush to end of line if necessary
  i = 0;
  while (i < password_len) {
    if (password[i] == '\n') {
      password[i] = '\0';
      break;
    }
    i++;
  }
  if (i == password_len) {
    extra = 0;
    while ((c = getchar()) != '\n' && c != EOF)
      extra = 1;
    if (extra == 1)
      return;
  }

  *success = 1;
}
