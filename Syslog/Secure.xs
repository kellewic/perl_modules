#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <stdlib.h>

#define RET_SZ	4096

static char hex[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
static char const *bin[16]= {
  "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
  "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"
};


const void
_encrypt (const char *BF_KEY, const char *data, char *ret, int ret_sz)
{
  unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
  BIO *benc, *bmem, *b64;

  if (data != NULL && strlen(data)){
    benc = BIO_new(BIO_f_cipher());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    benc = BIO_push(benc, b64);

    memset(key, 0, EVP_MAX_KEY_LENGTH);
    memmove(iv, BF_KEY, sizeof(iv));
    BIO_set_cipher(benc, EVP_bf_cfb(), key, iv, 1);

    BIO_write(benc, data, strlen(data));
    BIO_flush(benc);

    BIO_read(bmem, ret, ret_sz);

    BIO_set_close(bmem, BIO_CLOSE);
    BIO_vfree(benc);
    BIO_vfree(bmem);
    BIO_vfree(b64);
  }
}

const void
_decrypt (const char *BF_KEY, const char *data, char *ret, int ret_sz)
{
  unsigned char iv[EVP_MAX_IV_LENGTH], key[EVP_MAX_KEY_LENGTH];
  BIO *benc, *bmem, *b64;

  if (data != NULL && strlen(data)){
    benc = BIO_new(BIO_f_cipher());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    benc = BIO_push(benc, b64);

    memset(key, 0, EVP_MAX_KEY_LENGTH);
    memmove(iv, BF_KEY, sizeof(iv));
    BIO_set_cipher(benc, EVP_bf_cfb(), key, iv, 0);

    BIO_write(bmem, data, strlen(data));
    BIO_flush(bmem);

    BIO_read(benc, ret, ret_sz);

    BIO_set_close(bmem, BIO_CLOSE);
    BIO_vfree(benc);
    BIO_vfree(bmem);
    BIO_vfree(b64);
  }
}

MODULE = Syslog::Secure     PACKAGE = Syslog::Secure
PROTOTYPES: DISABLE

void
sslEncrypt(key, data)
	const char *key;
	const char *data;
PPCODE:
{
	char *ret;

	New(0, ret, RET_SZ, char);
	memset(ret, 0, RET_SZ);
	_encrypt(key, data, ret, RET_SZ-1);
	PUSHs(sv_2mortal(newSVpv(ret, 0)));
	Safefree(ret);
}

void
sslDecrypt(key, data)
	const char *key;
   const char *data;
PPCODE:
{
   char *ret;

   New(0, ret, RET_SZ, char);
	memset(ret, 0, RET_SZ);
   _decrypt(key, data, ret, RET_SZ-1);
   PUSHs(sv_2mortal(newSVpv(ret, 0)));
   Safefree(ret);
}

void
encodebytes(obj, data)
	SV *obj;
	unsigned char *data;
PPCODE:
{
  int a, c, x, y, z, maxbin;
  unsigned char *res;
  unsigned char lrc=0;
  char r[2], binary[8];
  SV *final;

  if (!sv_isa(obj, "Syslog::Secure")){
    croak("method encodebytes not called in an object context");
  }

  New(0, res, strlen(data)+2, unsigned char);
  memset(res, 0, strlen(data)+2);

  for (a=0; a<strlen(data); a++){
    c = (int)data[a];
    for (x=1, maxbin=64, z=0; x<8; x++, maxbin/=2){
      if (c - maxbin >= 0){
        binary[x] = '1';
        c -= maxbin;
        z++;
      }
      else{
         binary[x] = '0';
      }
    }

    binary[0] = (z%2?'1':'0');

    for (x=0;x<16;x++){
      if (!strncmp(binary, bin[x], 4))
        r[0] = hex[x];

      if (!strncmp(binary+4, bin[x], 4))
        r[1] = hex[x];
    }

    sprintf(binary, "0x%c%c", r[0], r[1]);
    res[a] = (unsigned char)strtol(binary, NULL, 16);

    if (res[a] != 0x82)
      lrc ^= res[a];
  }

  PUSHs(sv_2mortal(newSVpv(res, 0)));
  Safefree(res);
}

SV *
decodebytes(obj, data)
	SV *obj;
	unsigned char *data;
PPCODE:
{
   int x, y, o;
   unsigned char h[3];
   char binary[8];
   unsigned char *res;
   SV *final;

  	if (!sv_isa(obj, "Syslog::Secure")){
    	croak("method encodebytes not called in an object context");
  	}

	New(0, res, strlen(data)+2, unsigned char);
	memset(res, 0, strlen(data)+2);

   for (x=0, o=0; x<strlen(data); x++){
      int maxbin, ch=0;

      sprintf(h, "%02X", data[x]);

      for (y=0;y<16;y++){
         if (h[0] == hex[y])
            memcpy(binary, bin[y], 4);

         if (h[1] == hex[y])
            memcpy(binary+4, bin[y], 4);
      }

      for (y=1, maxbin=64; y<8; y++, maxbin/=2){
         if (binary[y] == '1')
            ch += maxbin;
      }

      res[x] = (char)ch;
   }

   PUSHs(sv_2mortal(newSVpv(res, 0)));
   Safefree(res);
}

