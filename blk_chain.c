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

int create_signedhash(unsigned char *buf, int len, EVP_PKEY *pkey, unsigned char **hash_sign) {
  EVP_MD_CTX  * mdctx;
  unsigned long sign_len = 0;
  unsigned char md_buf[EVP_MAX_MD_SIZE];
  unsigned char * sign = NULL;

  mdctx = EVP_MD_CTX_new();

  if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
    printf("DigestSignInit failed\n");
    return -1;
  }

  if (EVP_DigestSignUpdate(mdctx, buf, len) <= 0) {
    printf("EVP_DigestSignUpdate failed\n");
    return -1;
  }

  if (EVP_DigestSignFinal(mdctx, NULL, &sign_len) <= 0) {
    printf("EVP_DigestSignFinal failed\n");
  }

  sign=(unsigned char *) calloc(sign_len, 1);
  if (sign == NULL) {
    printf("calloc failed\n");
    return -1;
  }

  if (EVP_DigestSignFinal(mdctx, sign, &sign_len) <= 0) {
    printf("EVP_DigestSignFinal failed\n");
    return -1;
  }

  (void) memcpy(*hash_sign, sign, sign_len);

  /*
  if (mdctx != NULL)
    EVP_MD_CTX_free(mdctx);*/

  return 0;
}

int commit_blk_chain(char *filename, trusted_changes_chain_t *block, unsigned char *diff) {

  FILE *fout = NULL;
  unsigned int count = 0;
  int rc = 0;
  unsigned int difflen = 0;
  struct stat statbuf;

  fout = fopen(filename,"ab+");
  if (fout == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  if (stat(filename, &statbuf) < 0) {
    printf("stat failed\n");
    return -1;
  }

  if (statbuf.st_size != 0) {
    (void)fseek(fout, 0, SEEK_SET);

    rc = fread(&count, sizeof(unsigned int), 1, fout);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }
    fclose(fout);

    count = count + 1;

    fout = fopen(filename,"rb+");
    if (fout == NULL) {
      printf("fopen failed\n");
      return -1;
    }

    rc = fwrite(&count, sizeof(int), 1, fout);
    if (rc != 1) {
      printf("fwrite failed\n");
      return -1;
    }

    fclose(fout);
  }
  else
  {
    count = 1;
    (void)fseek(fout, 0, SEEK_SET);
    rc = fwrite(&count, sizeof(int), 1, fout);
    if (rc != 1) {
      printf("fwrite failed\n");
      return -1;
    }
    fclose(fout);
  }

  fout = fopen(filename,"rb+");
  if (fout == NULL) {
    printf("fopen failed\n");
    return -1;
  }
  (void)fseek(fout, 0, SEEK_END);

  rc = fwrite((char *)block, sizeof(struct trusted_changes_chain_t), 1, fout);
  if (rc != 1) {
    printf("fwrite failed\n");
    return -1;
  }

  if (diff != NULL) {
    difflen = strlen(diff) ;
    rc = fwrite(diff, difflen, 1, fout);
    if (rc != 1) {
      printf("fwrite failed\n");
      return -1;
    }
  }

  fclose(fout);

  return 0;
}

int add_new_block(unsigned char *orig_filename, unsigned char *filename,
                  unsigned char *diff_filename, EVP_PKEY *pkey,
                  unsigned char * username, unsigned char * hostname) {
  trusted_changes_chain_t block;
  FILE *fin = NULL;
  struct stat statbuf;
  unsigned char *buffer = NULL;
  unsigned char *hash;
  unsigned char *hash_sign;
  unsigned char meta_filename[256];
  int rc = 0;

  memset((void *)&block, 0, sizeof(trusted_changes_chain_t));

  /* First check if Genesis block needs to be inserted */
  sprintf(meta_filename, "/tmp/trc/hackathon/%s.meta", filename);
  if (access(meta_filename, 0) < 0) {
    fin = fopen(orig_filename, "r");
    if (fin == NULL) {
      printf("fopen failed\n");
      return -1;
    }

    if (stat(orig_filename, &statbuf) < 0) {
      printf("statfs failed\n");
      return -1;
    }
    buffer = (unsigned char *) calloc(statbuf.st_size, 1);
    if (buffer == NULL) {
      printf("calloc failed\n");
      return -1;
    }

    rc = fread(buffer, statbuf.st_size, 1, fin);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    memset(&block.prev_hash, 0, EVP_MAX_MD_SIZE +1);

    hash = (unsigned char *) calloc (256, 1);
    rc = create_hash(buffer, statbuf.st_size, &hash);
    if (rc < 0) {
      printf("create hash failed\n");
      return -1;
    }
    memcpy(&block.current_hash, hash, EVP_MAX_MD_SIZE);

    memset((void *)hash, 0, 256);
    rc = create_signedhash(buffer, statbuf.st_size, pkey, &hash);
    if (rc < 0) {
      printf("create signed hash failed\n");
      return -1;
    }
    memcpy(&block.signed_hash, hash, 256);
    free(buffer);
    buffer = NULL;

    time(&block.timestamp);
    strcpy(block.username, "Genesis Block");
    strcpy(block.hostname, "Genesis Block"); 
    block.difflen = 0;
    fclose(fin);

    rc = commit_blk_chain(meta_filename, &block, NULL);
    if (rc < 0) {
      printf("commit block in the block chain failed\n");
      return -1;
    }
  }

  fin = fopen(filename,"r");
  if (fin == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  if (stat(filename, &statbuf) < 0) {
    printf("statfs failed\n");
    return -1;
  }

  buffer = (unsigned char *) calloc(statbuf.st_size, 1);
  if (buffer == NULL) {
    printf("calloc failed\n");
    return -1;
  }

  rc = fread(buffer, statbuf.st_size, 1, fin);
  if (rc != 1) {
    printf("fread failed\n");
    return -1;
  }
  fclose(fin);

  rc = get_prev_hash(meta_filename, &block.prev_hash);
  if (rc < 0) {
    printf("Previous hash fetch failed\n");
    return -1;
  }

  hash = (unsigned char *) calloc (256, 1);
  rc = create_hash(buffer, statbuf.st_size, &hash);
  if (rc < 0) {
    printf("create hash failed\n");
    return -1;
  }
  memcpy(&block.current_hash, hash, EVP_MAX_MD_SIZE);
  
  memset((void *)hash, 0, 256);
  rc = create_signedhash(buffer, statbuf.st_size, pkey, &hash);
  if (rc < 0) {
    printf("create signed hash failed\n");
    return -1;
  }
  memcpy(&block.signed_hash, hash, 256);
  free(buffer);

  time(&block.timestamp);
  strcpy(block.username, username);
  strcpy(block.hostname, hostname);

  fin = fopen(diff_filename,"r");
  if (fin == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  if (stat(diff_filename, &statbuf) < 0) {
    printf("stat failed\n");
    return -1;
  }

  buffer = (unsigned char *) calloc((statbuf.st_size + 1), 1);
  if (buffer == NULL) {
    printf("Calloc failed\n");
    return -1;
  }

  rc = fread(buffer, statbuf.st_size, 1, fin);
  if (rc != 1) {
    printf("fread failed\n");
    return -1;
  }
  fclose(fin);

  block.difflen = statbuf.st_size + 1;

  rc = commit_blk_chain(meta_filename, &block, buffer);
  if (rc < 0) {
    printf("commit block in the block chain failed\n");
    return -1;
  }

  return 0;
}

get_prev_hash(unsigned char *meta_filename, unsigned char ** prev_hash) {
  trusted_changes_chain_t blk, *blk_ptr = NULL;
  struct stat statbuf;
  FILE *fout = NULL;
  int rc = 0;
  unsigned int count = 0, i;
  struct tm * lcl_tm;
  unsigned char tbuf[256];
  unsigned char *dbuf = NULL;

  fout = fopen(meta_filename,"r");
  if (fout == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  if (stat(meta_filename, &statbuf) < 0) {
    printf("statfs failed\n");
    return -1;
  }

  if (statbuf.st_size == 0) {
    memset(prev_hash, 0, EVP_MAX_MD_SIZE +1);
    return 0;
  }

  rc = fread(&count, sizeof(unsigned int), 1, fout);
  if (rc != 1) {
    printf("fread failed\n");
    return -1;
  }

  for (i = 0; i < count; i++) {
    memset(&blk, 0, sizeof(trusted_changes_chain_t));
    rc = fread((char *)&blk, sizeof(struct trusted_changes_chain_t), 1, fout);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    if (i > 0) {
      dbuf = (unsigned char *) calloc(blk.difflen, 1);
      if (dbuf == NULL) {
        printf("calloc failed\n");
        return -1;
      }
      rc = fread(dbuf, blk.difflen-1, 1, fout);
      if (rc != 1) {
        printf("fread failed\n");
        return -1;
      }
      free(dbuf);
    }

    memcpy(prev_hash, &blk.current_hash, 64);
  }

  return 0;
}

int read_block_chain(unsigned char *meta_filename) {
  trusted_changes_chain_t blk, *blk_ptr = NULL;
  struct stat statbuf;
  FILE *fout = NULL;
  int rc = 0;
  unsigned int count = 0, i;
  struct tm * lcl_tm;
  unsigned char tbuf[256];
  unsigned char tmbuf[256];
  unsigned char *dbuf = NULL;

  fout = fopen(meta_filename,"rb+");
  if (fout == NULL) {
    printf("fopen failed\n");
    return -1;
  }

  printf("0=0=0=0=0=0=0=0=0=0=0 -BLOCKCHAIN- 0=0=0=0=0=0=0=0=0=0=0=0=0=0\n\n");

  rc = fread(&count, sizeof(unsigned int), 1, fout);
  if (rc != 1) {
    printf("fread failed\n");
    return -1;
  }
  printf("No of Trusted Blocks in the blockchain\t: %d\n\n", count);

  for (i = 0; i < count; i++) {
    memset(&blk, 0, sizeof(trusted_changes_chain_t));
    rc = fread((char *)&blk, sizeof(struct trusted_changes_chain_t), 1, fout);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    printf("Block #    \t: %d\n", i+1);
    printf("Username\t: %s\n", blk.username);
    printf("Hostname\t: %s\n", blk.hostname);

    memset(&tbuf, 0, 256);
    EVP_EncodeBlock((unsigned char *)&tbuf, (unsigned char*)&blk.prev_hash, 64);
    printf("Previous Hash\t: %s\n", tbuf);

    lcl_tm = (struct tm *) localtime((time_t *)&blk.timestamp);
    strftime(tmbuf, 20, "%c", lcl_tm);
    printf("Timestamp\t: %s\n", tmbuf);

    memset(&tbuf, 0, 256);
    EVP_EncodeBlock((unsigned char *)&tbuf, (unsigned char*)&blk.current_hash, 64);
    printf("Current Hash\t: %s\n", tbuf);

    memset(&tbuf, 0, 256);
    EVP_EncodeBlock((unsigned char *)&tbuf, (unsigned char*)&blk.signed_hash, 256);
    printf("Signed Hash\t: %s\n", tbuf);

    if (i == 0) {
      printf("File Diff\t: %s\n\n", "Genesis Block - No Diff");
      printf("     ^^^     \n");
      printf("     ^^^     \n");
      printf("     |||     \n\n");
    }
    else
    {
      dbuf = (unsigned char *) calloc(blk.difflen, 1);
      if (dbuf == NULL) {
        printf("calloc failed\n");
        return -1;
      }
      rc = fread(dbuf, blk.difflen-1, 1, fout);
      if (rc != 1) {
        printf("fread failed\n");
        return -1;
      }
      printf("File Diff\t: %s\n", dbuf);
      printf("     ^^^     \n");
      printf("     ^^^     \n");
      printf("     |||     \n\n");
      free(dbuf);
    }
  }
  printf("0=0=0=0=0=0=0=0=0=0=0=0 -END- 0=0=0=0=0=0=0=0=0=0=0=0=0\n");
  
  return 0;
}

int getcount(unsigned char *filename) {
  char meta_filename[256];
  FILE *fout = NULL;
  unsigned int count = 0;
  int rc = 0;

  /* First check if Genesis block needs to be inserted */
  if (access(filename, 0) < 0) {
    printf("%d\n", 0);
  }
  else
  {
    fout = fopen(filename,"rb");
    if (fout == NULL) {
      printf("fopen failed\n");
      return -1;
    }

    rc = fread(&count, sizeof(unsigned int), 1, fout);
    if (rc != 1) {
      printf("fread failed\n");
      return -1;
    }

    fclose(fout);
    printf("%d\n", count);

  }
  return 0;
} 

int main(int argc,char *argv[]) {

  char *orig_filename;
  char *filename;
  char *diff_file;
  char meta_filename[256];
  EVP_PKEY *pvtkey = NULL, *pubkey = NULL;
  int rc = 0;

  if (!strcmp(argv[2], "getcount")) {
    rc = getcount(argv[1]);
    if (rc != 0) {
      printf("getcount failed\n");
      return -1;
    }
    return 0;
  }

  if (!strcmp(argv[1], "print")) {
    rc = read_block_chain(argv[2]);
    if (rc != 0) {
      printf("print failed\n");
      return -1;
    }
    return 0;
  }

  orig_filename=argv[1];
  filename=argv[2];
  diff_file=argv[3];

  /* Read the keys */
  rc = read_keys(&pvtkey, &pubkey);
  if (rc < 0){
    printf("read keys failed\n");
    return -1;
  }

  /* Create the new block from current file and diff */
  /* This routine will further insert the block in the block chain */
  rc = add_new_block(orig_filename, filename, diff_file, pvtkey, argv[4], argv[5]);
  if (rc < 0) {
    printf("add_new_block failed\n");
    return -1;
  }

  /* Read the current block chain and print */
  sprintf(meta_filename, "/tmp/trc/hackathon/%s.meta", filename);
  rc = read_block_chain(meta_filename);
  if (rc < 0) {
    printf("read_block_chain failed\n");
    return -1;
  }

  return 0;
}
