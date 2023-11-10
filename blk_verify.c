#include <memory.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/stat.h>


#define PRI_KEY_PATH "/tmp/trc/hackathon/private.pem"
#define PUB_KEY_PATH "/tmp/trc/hackathon/public.pem"

typedef struct trusted_changes_chain_t {
  unsigned char username[16];
  unsigned char hostname[256];
  unsigned char prev_hash[EVP_MAX_MD_SIZE+1];
  time_t        timestamp;
  unsigned char current_hash[EVP_MAX_MD_SIZE+1];
  unsigned char signed_hash[256+1];
  unsigned int  difflen;
  unsigned char diff[1];
} trusted_changes_chain_t;

int read_keys(EVP_PKEY **pvtkey, EVP_PKEY **pubkey) {
  FILE *pvt_fileptr = NULL, *pub_fileptr = NULL;

  *pvtkey = NULL; *pubkey = NULL;

  *pvtkey = EVP_PKEY_new();
  *pubkey = EVP_PKEY_new();

  pvt_fileptr = fopen(PRI_KEY_PATH, "r");
  if (!pvt_fileptr) {
    printf("failed to open pvt key file.\n");
    return -1;
  }

  *pvtkey = PEM_read_PrivateKey(pvt_fileptr, NULL, NULL, NULL);
  if (!(*pvtkey)) {
    printf("failed to read pvt key.\n");
    return -1;
  }

  pub_fileptr = fopen(PUB_KEY_PATH, "r");
  if (!pub_fileptr) {
    printf("failed to read pub key file.\n");
    return -1;
  }

  *pubkey = PEM_read_PUBKEY(pub_fileptr, NULL, NULL, NULL);
  if (!(*pubkey)) {
    printf("failed to read pub key.\n");
    return -1;
  }

  return 0;
}

int create_hash(unsigned char *buf, int len, unsigned char **hash) {
  unsigned int  md_len;
  EVP_MD_CTX  * mdctx;
  unsigned char md_buf[EVP_MAX_MD_SIZE];

  mdctx = EVP_MD_CTX_new();

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    return -1;

  if (EVP_DigestUpdate(mdctx, (void *)buf, len) != 1)
    return -1;

  /* Need to update with multiple factors like timestamp ... */
  if (EVP_DigestFinal_ex(mdctx, md_buf, &md_len) != 1)
    return -1;

  (void) memcpy(*hash, md_buf, md_len);

  EVP_MD_CTX_free(mdctx);

  return 0;
}

int verify_signedhash(unsigned char *buf, int len, EVP_PKEY *pubkey, unsigned char *hash_sign) {
  EVP_MD_CTX  * mdctx;
  unsigned long sign_len = 0;
  unsigned char md_buf[EVP_MAX_MD_SIZE];
  unsigned char * sign = NULL;
  int rc = 0;
  unsigned char *signed_hash = NULL;
  unsigned char tbuf[256];

  mdctx = EVP_MD_CTX_new();

  if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
    printf("DigestVerifyInit failed\n");
    return -1;
  }

  if (EVP_DigestVerifyUpdate(mdctx, buf, len) <= 0) {
    printf("EVP_DigestVerifyUpdate failed\n");
    return -1;
  }

  if ((rc = EVP_DigestVerifyFinal(mdctx, hash_sign, 256)) <= 0) {
    printf("EVP_DigestVerifyFinal failed\n");
    return -1;
  }

  return rc;

  /*
  if (mdctx != NULL)
    EVP_MD_CTX_free(mdctx);*/
}

int generate_diff_files(unsigned char *meta_filename, unsigned char *filename) {
  trusted_changes_chain_t blk, *blk_ptr = NULL;
  struct stat statbuf;
  FILE *fin = NULL, *fout = NULL;
  int rc = 0;
  unsigned int count = 0, i;
  unsigned char *dbuf = NULL;
  unsigned char diff_filename[256];

  fin = fopen(meta_filename,"rb");
  if (fin == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  rc = fread(&count, sizeof(unsigned int), 1, fin);
  if (rc != 1) {
    printf("fread failed\n");
    return -1;
  }

  for (i = 0; i < count; i++) {
    memset(&blk, 0, sizeof(trusted_changes_chain_t));
    rc = fread((char *)&blk, sizeof(struct trusted_changes_chain_t), 1, fin);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    if (i == 0)
      continue;

    dbuf = (unsigned char *) calloc(blk.difflen, 1);
    if (dbuf == NULL) {
      printf("calloc failed\n");
      return -1;
    }
    rc = fread(dbuf, blk.difflen-1, 1, fin);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    memset(&diff_filename[0], 0, 256);
    sprintf(diff_filename, "/tmp/trc/hackathon/%s.diff.%d", filename, i);
    fout = fopen(diff_filename,"w");
    if (fout == NULL) {
      printf("fopen failed\n");
      return -1;
    }

    if (dbuf != NULL) {
      unsigned int difflen = 0;
      difflen = strlen(dbuf) ;
      rc = fwrite(dbuf, difflen, 1, fout);
      if (rc != 1) {
        printf("fwrite failed\n");
        return -1;
      }
    }

    fclose(fout);
  }

  fclose(fin);

  return 0;
}

int verify_block_chain(unsigned char * meta_filename,
                       unsigned char *latest_filename,
                       unsigned int vcount,
                       EVP_PKEY *pubkey) {
  trusted_changes_chain_t blk, *blk_ptr = NULL;
  struct stat statbuf;
  FILE *fin = NULL, *flat = NULL;
  int rc = 0, skip = 0;
  unsigned int i, count=0;
  unsigned char hash[EVP_MAX_MD_SIZE+1];
  unsigned char *current_hash;
  unsigned char *buffer;
  unsigned char tbuf[256];

  fin = fopen(meta_filename,"rb");
  if (fin == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  rc = fread(&count, sizeof(unsigned int), 1, fin);
  if (rc != 1) {
    printf("fread failed\n");
    return -1;
  }

  /* Verification steps
   * 1. Verify the hash and prev_hash from next block
   * 2. Verify the hash of latest file with the current hash
   * 3. Verify the signature of the current hash
   */
  skip = vcount;
  for (i = 0; i < count; i++) {
    /* Save the current hash to be compared with prev_hash */
    if (i > 0)
      memcpy(&hash, &blk.current_hash, EVP_MAX_MD_SIZE+1);

    memset(&blk, 0, sizeof(trusted_changes_chain_t));
    rc = fread((char *)&blk, sizeof(struct trusted_changes_chain_t), 1, fin);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    if (i > 0) {
      /* Seek to next block */
      fseek(fin, (blk.difflen -1), SEEK_CUR);
    }

    /* Only the next 2 blocks to verify */
    if (--skip >= 0)
      continue;

    /* Perform the 1st verify */
    if (!memcmp(&hash, &blk.prev_hash, 64)) {
      printf("Previous hash verification for Block #%d and #%d PASSED\n", (i+1), i);
    }
    else
    {
      printf("Verify Failed !!!!  - Current hash and Prev Hash Verification failed\n");
      return -1;
    }

    flat = fopen(latest_filename,"r");
    if (flat == NULL) {
      printf("fopen failed\n");
      return -1;
    }

    if (stat(latest_filename, &statbuf) < 0) {
      printf("statfs failed\n");
      return -1;
    }

    buffer = (unsigned char *) calloc(statbuf.st_size, 1);
    if (buffer == NULL) {
      printf("calloc failed\n");
      return -1;
    }

    rc = fread(buffer, statbuf.st_size, 1, flat);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    current_hash = (unsigned char *) calloc (256, 1);
    if (current_hash == NULL) {
      printf("calloc failed\n");
      return -1;
    }
    rc = create_hash(buffer, statbuf.st_size, &current_hash);
    if (rc < 0) {
      printf("create hash failed\n");
      return -1;
    }

    if (!memcmp(current_hash, &blk.current_hash, 64)) {
      printf("Block Verification for the Latest file and the hash stored in the Block #%d PASSED\n", i+1);
    }
    else
    {
      printf("Verify Failed !!!!  - Latest file hash and Block Hash Verification FAILED\n");
      return -1;
    }

    rc = verify_signedhash(buffer, statbuf.st_size, pubkey, blk.signed_hash);
    if (rc == 1) {
      printf("Block Signature Verification Stored in the Block #%d PASSED\n", i+1);
    }
    else if (rc == 0) {
      printf("Verify Failed !!!!  - Signature verification failed\n");
      return -1;
    }

    free(current_hash);
    free(buffer);

    /* We have already verified the last 2 based on vcount, so break */
    break;

  }

  fclose(flat);
  fclose(fin);

  return 0;
}

int main(int argc,char *argv[]) {
  EVP_PKEY *pvtkey = NULL, *pubkey = NULL;
  int rc = 0;
  unsigned count = 0;

  if (!strcmp(argv[3], "gendiff")) {
    rc = generate_diff_files(argv[1], argv[2]);
    if (rc != 0) {
      printf("generate_diff_files failed\n");
      return -1;
    }
    return 0;
  }

  /* Read the keys */
  rc = read_keys(&pvtkey, &pubkey);
  if (rc < 0){
    printf("read keys failed\n");
    return -1;
  }

  if (!strcmp(argv[1], "verify")) {
    count = strtol(argv[4], NULL, 10);
    rc = verify_block_chain(argv[2], argv[3], count, pubkey);
    if (rc != 0) {
      printf("Block Chain Verification Failed !!\n");
      return -1;
    }
    return 0;
  }

  return 0;
}
