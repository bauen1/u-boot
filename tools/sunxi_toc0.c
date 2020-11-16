// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2018 Arm Ltd.
 * (C) Copyright 2020 Samuel Holland
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <image.h>

#include "imagetool.h"
#include "mkimage.h"

/* checksum initialiser value */
#define STAMP_VALUE			0x5F0A6C39

/*
 * NAND requires 8K padding. For other devices, BROM requires only
 * 512B padding, but let's use the larger padding to cover everything.
 */
#define PAD_SIZE			8192

struct toc0_key_item {
	uint32_t vendor_id;
	uint32_t key0_n_len;
	uint32_t key0_e_len;
	uint32_t key1_n_len;
	uint32_t key1_e_len;
	uint32_t sig_len;
	uint8_t  key0[512];
	uint8_t  key1[512];
	uint8_t  reserved[32];
	uint8_t  sig[256];
};

/*
 * Create a key item in @buf, containing the public keys @root_key and @fw_key,
 * and signed by the RSA key @root_key.
 */
static int toc0_create_key_item(uint8_t *buf, uint32_t *len,
				RSA *root_key, RSA *fw_key)
{
	struct toc0_key_item *key_item = (void *)buf;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	int ret = EXIT_FAILURE;
	unsigned int dummy;
	int n_len, e_len;

	/* Store key 0. */
	n_len = BN_bn2bin(RSA_get0_n(root_key), key_item->key0);
	e_len = BN_bn2bin(RSA_get0_e(root_key), key_item->key0 + n_len);
	if (n_len + e_len > sizeof(key_item->key0))
		goto err;
	key_item->key0_n_len = cpu_to_le32(n_len);
	key_item->key0_e_len = cpu_to_le32(e_len);

	/* Store key 1. */
	n_len = BN_bn2bin(RSA_get0_n(fw_key), key_item->key1);
	e_len = BN_bn2bin(RSA_get0_e(fw_key), key_item->key1 + n_len);
	if (n_len + e_len > sizeof(key_item->key1))
		goto err;
	key_item->key1_n_len = cpu_to_le32(n_len);
	key_item->key1_e_len = cpu_to_le32(e_len);

	/* Sign the key item. */
	key_item->sig_len = cpu_to_le32(RSA_size(root_key));
	SHA256(buf, key_item->sig - buf, digest);
	if (!RSA_sign(NID_sha256, digest, sizeof(digest),
		      key_item->sig, &dummy, root_key))
		goto err;

	*len = sizeof(*key_item);
	ret = EXIT_SUCCESS;

err:
	return ret;
}

/*
 * Verify the key item in @buf, containing two public keys @key0 and @key1,
 * and signed by the RSA key @key0. If @root_key is provided, only signatures
 * by that key will be accepted. @key1 is returned in @key.
 */
static int toc0_verify_key_item(const uint8_t *buf, uint32_t len,
				RSA *root_key, RSA **fw_key)
{
	struct toc0_key_item *key_item = (void *)buf;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	int ret = EXIT_FAILURE;
	int n_len, e_len;
	RSA *key0 = NULL;
	RSA *key1 = NULL;
	BIGNUM *n, *e;

	if (len < sizeof(*key_item))
		goto err;

	/* Load key 0. */
	n_len = le32_to_cpu(key_item->key0_n_len);
	e_len = le32_to_cpu(key_item->key0_e_len);
	if (n_len + e_len > sizeof(key_item->key0))
		goto err;
	n = BN_bin2bn(key_item->key0, n_len, NULL);
	e = BN_bin2bn(key_item->key0 + n_len, e_len, NULL);
	key0 = RSA_new();
	if (!key0)
		goto err;
	if (!RSA_set0_key(key0, n, e, NULL))
		goto err;

	/* If a root key was provided, compare it to key 0. */
	if (root_key && (BN_cmp(n, RSA_get0_n(root_key)) ||
			 BN_cmp(e, RSA_get0_e(root_key))))
		goto err;

	/* Verify the key item signature. */
	SHA256(buf, key_item->sig - buf, digest);
	if (!RSA_verify(NID_sha256, digest, sizeof(digest),
			key_item->sig, le32_to_cpu(key_item->sig_len), key0))
		goto err;

	if (fw_key) {
		/* Load key 1. */
		n_len = le32_to_cpu(key_item->key1_n_len);
		e_len = le32_to_cpu(key_item->key1_e_len);
		if (n_len + e_len > sizeof(key_item->key1))
			goto err;
		n = BN_bin2bn(key_item->key1, n_len, NULL);
		e = BN_bin2bn(key_item->key1 + n_len, e_len, NULL);
		key1 = RSA_new();
		if (!key1)
			goto err;
		if (!RSA_set0_key(key1, n, e, NULL))
			goto err;

		if (*fw_key) {
			/* If a FW key was provided, compare it to key 1. */
			if (BN_cmp(n, RSA_get0_n(*fw_key)) ||
			    BN_cmp(e, RSA_get0_e(*fw_key)))
				goto err;
		} else {
			/* Otherwise, send key1 back to the caller. */
			*fw_key = key1;
			key1 = NULL;
		}
	}

	ret = EXIT_SUCCESS;

err:
	RSA_free(key0);
	RSA_free(key1);

	return ret;
}

#ifndef ASN1_BROKEN_SEQUENCE
#define ASN1_BROKEN_SEQUENCE(tname) \
	static const ASN1_AUX tname##_aux = {NULL, ASN1_AFLG_BROKEN}; \
	ASN1_SEQUENCE(tname)
#define static_ASN1_BROKEN_SEQUENCE_END(stname) \
	static_ASN1_SEQUENCE_END_ref(stname, stname)
#endif

typedef struct toc0_empty_seq_st {
} TOC0_OPAQUE_SEQ;

ASN1_BROKEN_SEQUENCE(TOC0_OPAQUE_SEQ) = {
} static_ASN1_BROKEN_SEQUENCE_END(TOC0_OPAQUE_SEQ)

typedef struct toc0_pkey_info_st {
	TOC0_OPAQUE_SEQ	algorithm;
	RSA		*key;
} TOC0_PKEY_INFO;

ASN1_SEQUENCE(TOC0_PKEY_INFO) = {
	ASN1_EMBED(TOC0_PKEY_INFO, algorithm, TOC0_OPAQUE_SEQ),
	ASN1_SIMPLE(TOC0_PKEY_INFO, key, RSAPublicKey),
} static_ASN1_SEQUENCE_END(TOC0_PKEY_INFO)

typedef struct toc0_extension_st {
	ASN1_OCTET_STRING digest;
} TOC0_EXTENSION;

ASN1_SEQUENCE(TOC0_EXTENSION) = {
	ASN1_EMBED(TOC0_EXTENSION, digest, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(TOC0_EXTENSION)

typedef struct toc0_cert_info_st {
	ASN1_INTEGER	version;
	ASN1_INTEGER	serialNumber;
	TOC0_OPAQUE_SEQ	signature;
	TOC0_OPAQUE_SEQ	issuer;
	TOC0_OPAQUE_SEQ	validity;
	TOC0_OPAQUE_SEQ	subject;
	TOC0_PKEY_INFO	subjectPublicKeyInfo;
	TOC0_EXTENSION	extension;
} TOC0_CERT_INFO;

ASN1_SEQUENCE(TOC0_CERT_INFO) = {
	ASN1_EXP_EMBED(TOC0_CERT_INFO, version, ASN1_INTEGER, 0),
	ASN1_EMBED(TOC0_CERT_INFO, serialNumber, ASN1_INTEGER),
	ASN1_EMBED(TOC0_CERT_INFO, signature, TOC0_OPAQUE_SEQ),
	ASN1_EMBED(TOC0_CERT_INFO, issuer, TOC0_OPAQUE_SEQ),
	ASN1_EMBED(TOC0_CERT_INFO, validity, TOC0_OPAQUE_SEQ),
	ASN1_EMBED(TOC0_CERT_INFO, subject, TOC0_OPAQUE_SEQ),
	ASN1_EMBED(TOC0_CERT_INFO, subjectPublicKeyInfo, TOC0_PKEY_INFO),
	ASN1_EXP_EMBED(TOC0_CERT_INFO, extension, TOC0_EXTENSION, 3),
} static_ASN1_SEQUENCE_END(TOC0_CERT_INFO)

IMPLEMENT_ASN1_FUNCTIONS(TOC0_CERT_INFO)

typedef struct toc0_cert_sig_st {
	TOC0_OPAQUE_SEQ	algorithm;
	ASN1_BIT_STRING	value;
} TOC0_CERT_SIG;

ASN1_SEQUENCE(TOC0_CERT_SIG) = {
	ASN1_EMBED(TOC0_CERT_SIG, algorithm, TOC0_OPAQUE_SEQ),
	ASN1_EMBED(TOC0_CERT_SIG, value, ASN1_BIT_STRING),
} static_ASN1_SEQUENCE_END(TOC0_CERT_SIG)

IMPLEMENT_ASN1_FUNCTIONS(TOC0_CERT_SIG)

typedef struct toc0_cert_st {
	TOC0_CERT_INFO	info;
	TOC0_CERT_SIG	sig;
} TOC0_CERT;

ASN1_SEQUENCE(TOC0_CERT) = {
	ASN1_EMBED(TOC0_CERT, info, TOC0_CERT_INFO),
	ASN1_EMBED(TOC0_CERT, sig, TOC0_CERT_SIG),
} static_ASN1_SEQUENCE_END(TOC0_CERT)

IMPLEMENT_ASN1_FUNCTIONS(TOC0_CERT)

#define TOC0_CERT_ITEM_SIZE		605

/*
 * Create a certificate in @buf, describing the firmware with SHA256 digest
 * @digest, and signed by the RSA key @fw_key.
 */
static int toc0_create_cert_item(uint8_t *buf, uint32_t *len, RSA *fw_key,
				 uint8_t digest[static SHA256_DIGEST_LENGTH])
{
	size_t digest_len = SHA256_DIGEST_LENGTH;
	uint8_t *info_der = NULL;
	uint8_t *cert_der = buf;
	int ret = EXIT_FAILURE;
	uint8_t *sig = NULL;
	TOC0_CERT cert = {};
	int info_der_len;
	uint32_t sig_len;

	/* Construct and DER-encode the certificate. */
	cert.info.subjectPublicKeyInfo.key = fw_key;
	ASN1_STRING_set0(&cert.info.extension.digest, digest, digest_len);
	info_der_len = i2d_TOC0_CERT_INFO(&cert.info, &info_der);
	if (info_der_len < 0)
		goto err;

	/* Sign the certificate. */
	sig = OPENSSL_malloc(RSA_size(fw_key));
	if (!sig)
		goto err;
	/* SBROM signs all but the last 4 bytes of the certificate. */
	SHA256(info_der, info_der_len - 4, sig);
	if (!RSA_sign(NID_sha256, sig, digest_len, sig, &sig_len, fw_key))
		goto err;
	cert.sig.value.flags = ASN1_STRING_FLAG_BITS_LEFT;
	ASN1_STRING_set0(&cert.sig.value, sig, sig_len);

	/* Write the complete certificate to the buffer. */
	*len = i2d_TOC0_CERT(&cert, &buf);
	if (*len < 0)
		goto err;

	/* SBROM requires TOC0_CERT_SIG to be tagged as a BIT STRING. */
	assert(cert_der[4 + info_der_len] == 0x30);
	cert_der[4 + info_der_len] = 0x03;

	/* Verify the hardcoded header size is still correct. */
	assert(*len == TOC0_CERT_ITEM_SIZE);

	ret = EXIT_SUCCESS;

err:
	OPENSSL_free(info_der);
	OPENSSL_free(sig);

	return ret;
}

/*
 * Verify the certificate in @buf, describing the firmware with SHA256 digest
 * @digest, and signed by the RSA key contained within. If @fw_key is provided,
 * only that key will be accepted.
 */
static int toc0_verify_cert_item(const uint8_t *buf, uint32_t len, RSA *fw_key,
				 uint8_t digest[static SHA256_DIGEST_LENGTH])
{
	size_t digest_len = SHA256_DIGEST_LENGTH;
	const uint8_t *cert_tmp = NULL;
	uint8_t *cert_der = NULL;
	TOC0_CERT *cert = NULL;
	int ret = EXIT_FAILURE;
	int sig_tag_offset;
	RSA *cert_key;
	int info_len;

	/* Copy the DER to a writable buffer for fixing the signature tag. */
	cert_tmp = cert_der = OPENSSL_malloc(len);
	if (!cert_der)
		goto err;
	memcpy(cert_der, buf, len);

	/*
	 * Undo the tag hack done when creating the certificate. While hard-
	 * coding offsets here is ugly, the SBROM does the same thing; so if
	 * these checks fail, the image would not boot anyway.
	 */
	info_len = cert_der[6] << 8 | cert_der[7];
	sig_tag_offset = 8 + info_len;
	if (sig_tag_offset > len)
		goto err;
	if (cert_der[sig_tag_offset] != 0x03)
		goto err;
	cert_der[sig_tag_offset] = 0x30;

	/* Parse the DER. */
	cert = d2i_TOC0_CERT(NULL, &cert_tmp, len);
	if (!cert)
		goto err;

	/* If a key was provided, compare it to the embedded key. */
	cert_key = cert->info.subjectPublicKeyInfo.key;
	if (fw_key && (BN_cmp(RSA_get0_n(cert_key), RSA_get0_n(fw_key)) ||
		       BN_cmp(RSA_get0_e(cert_key), RSA_get0_e(fw_key))))
		goto err;

	/*
	 * Verify the certificate signature. Note that the digest starts at
	 * the TOC0_CERT_INFO header, but is only as long as the TOC0_CERT_INFO
	 * contents, meaning that the last 4 content bytes (the size of the
	 * header) are not signed. This replicates the behavior of the SBROM.
	 */
	SHA256(cert_der + 4, info_len, digest);
	if (!RSA_verify(NID_sha256, digest, digest_len,
			ASN1_STRING_get0_data(&cert->sig.value),
			ASN1_STRING_length(&cert->sig.value), cert_key))
		goto err;

	ret = EXIT_SUCCESS;

err:
	OPENSSL_free(cert_der);
	TOC0_CERT_free(cert);

	return ret;
}

#define TOC0_MAIN_NAME			"TOC0.GLH"
#define TOC0_MAIN_MAGIC			0x89119800
#define TOC0_MAIN_END			"MIE;"

struct toc0_main {
	uint8_t  name[8];
	uint32_t magic;
	uint32_t checksum;
	uint32_t serial;
	uint32_t status;
	uint32_t num_items;
	uint32_t length;
	uint8_t  platform[4];
	uint8_t  reserved[8];
	uint8_t  end[4];
};

#define TOC0_ITEM_NAME_CERT		0x00010101
#define TOC0_ITEM_NAME_FIRMWARE		0x00010202
#define TOC0_ITEM_NAME_KEY		0x00010303
#define TOC0_ITEM_END			"IIE;"

struct toc0_item {
	uint32_t name;
	uint32_t offset;
	uint32_t length;
	uint32_t status;
	uint32_t type;
	uint32_t load_addr;
	uint8_t  reserved[4];
	uint8_t  end[4];
};

#define TOC0_MINIMUM_NUM_ITEMS		2
#define TOC0_MINIMUM_HEADER_LENGTH	ALIGN(sizeof(struct toc0_main)     + \
					      sizeof(struct toc0_item) *     \
						TOC0_MINIMUM_NUM_ITEMS     + \
					      TOC0_CERT_ITEM_SIZE, 32)
#define TOC0_DEFAULT_NUM_ITEMS		3
#define TOC0_DEFAULT_HEADER_LENGTH	ALIGN(sizeof(struct toc0_main)     + \
					      sizeof(struct toc0_item) *     \
						TOC0_DEFAULT_NUM_ITEMS     + \
					      sizeof(struct toc0_key_item) + \
					      TOC0_CERT_ITEM_SIZE, 32)

/*
 * Always create a TOC0 containing 3 items. The extra item will be ignored on
 * older SoCs.
 */
static int toc0_create(uint8_t *buf, uint32_t len, RSA *root_key, RSA *fw_key,
		       uint8_t *key_item, uint32_t key_item_len,
		       uint8_t *fw_item, uint32_t fw_item_len, uint32_t fw_addr)
{
	struct toc0_main *main = (void *)buf;
	struct toc0_item *item = (void *)(main + 1);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint32_t *buf32 = (void *)buf;
	RSA *orig_fw_key = fw_key;
	int ret = EXIT_FAILURE;
	uint32_t checksum = 0;
	uint32_t item_offset;
	uint32_t item_length;
	int i;

	/* Hash the firmware for inclusion in the certificate. */
	SHA256(fw_item, fw_item_len, digest);

	/* Create the main TOC0 header, containing three items. */
	memcpy(main->name, TOC0_MAIN_NAME, sizeof(main->name));
	main->magic	= cpu_to_le32(TOC0_MAIN_MAGIC);
	main->checksum	= cpu_to_le32(STAMP_VALUE);
	main->num_items	= cpu_to_le32(TOC0_DEFAULT_NUM_ITEMS);
	memcpy(main->end, TOC0_MAIN_END, sizeof(main->end));

	/* The first item links the ROTPK to the signing key. */
	item_offset = sizeof(*main) + TOC0_DEFAULT_NUM_ITEMS * sizeof(*item);
	/* Using an existing key item avoids needing the root private key. */
	if (key_item) {
		item_length = sizeof(*key_item);
		if (toc0_verify_key_item(key_item, item_length,
					 root_key, &fw_key))
			goto err;
		memcpy(buf + item_offset, key_item, item_length);
	} else if (toc0_create_key_item(buf + item_offset, &item_length,
					root_key, fw_key)) {
		goto err;
	}

	item->name	= cpu_to_le32(TOC0_ITEM_NAME_KEY);
	item->offset	= cpu_to_le32(item_offset);
	item->length	= cpu_to_le32(item_length);
	memcpy(item->end, TOC0_ITEM_END, sizeof(item->end));

	/* The second item contains a certificate signed by the firmware key. */
	item_offset = item_offset + item_length;
	if (toc0_create_cert_item(buf + item_offset, &item_length,
				  fw_key, digest))
		goto err;

	item++;
	item->name	= cpu_to_le32(TOC0_ITEM_NAME_CERT);
	item->offset	= cpu_to_le32(item_offset);
	item->length	= cpu_to_le32(item_length);
	memcpy(item->end, TOC0_ITEM_END, sizeof(item->end));

	/* The third item contains the actual boot code. */
	item_offset = ALIGN(item_offset + item_length, 32);
	item_length = fw_item_len;
	if (buf + item_offset != fw_item)
		memmove(buf + item_offset, fw_item, item_length);

	item++;
	item->name	= cpu_to_le32(TOC0_ITEM_NAME_FIRMWARE);
	item->offset	= cpu_to_le32(item_offset);
	item->length	= cpu_to_le32(item_length);
	item->load_addr	= cpu_to_le32(fw_addr);
	memcpy(item->end, TOC0_ITEM_END, sizeof(item->end));

	/* Pad to the required block size with 0xff to be flash-friendly. */
	item_offset = item_offset + item_length;
	item_length = ALIGN(item_offset, PAD_SIZE) - item_offset;
	memset(buf + item_offset, 0xff, item_length);

	/* Fill in the total padded file length. */
	item_offset = item_offset + item_length;
	main->length = cpu_to_le32(item_offset);

	/* Verify enough space was provided when creating the image. */
	assert(len >= item_offset);

	/* Calculate the checksum. Yes, it's that simple. */
	for (i = 0; i < item_offset / 4; ++i)
		checksum += le32_to_cpu(buf32[i]);
	main->checksum = cpu_to_le32(checksum);

	ret = EXIT_SUCCESS;

err:
	if (fw_key != orig_fw_key)
		RSA_free(fw_key);

	return ret;
}

static const struct toc0_item *toc0_find_item(const struct toc0_main *main,
					      uint32_t name, uint32_t *offset,
					      uint32_t *length)
{
	const struct toc0_item *item = (void *)(main + 1);
	uint32_t item_offset, item_length;
	uint32_t num_items, main_length;
	int i;

	num_items   = le32_to_cpu(main->num_items);
	main_length = le32_to_cpu(main->length);

	for (i = 0; i < num_items; ++i, ++item) {
		if (le32_to_cpu(item->name) != name)
			continue;

		item_offset = le32_to_cpu(item->offset);
		item_length = le32_to_cpu(item->length);

		if (item_offset > main_length ||
		    item_length > main_length - item_offset)
			continue;

		*offset = item_offset;
		*length = item_length;

		return item;
	}

	return NULL;
}

static int toc0_verify(const uint8_t *buf, uint32_t len, RSA *root_key)
{
	const struct toc0_main *main = (void *)buf;
	const struct toc0_item *item;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint32_t main_length = le32_to_cpu(main->length);
	uint32_t checksum = STAMP_VALUE;
	uint32_t *buf32 = (void *)buf;
	uint32_t length, offset;
	int ret = EXIT_FAILURE;
	RSA *fw_key = NULL;
	int i;

	if (len < main_length)
		goto err;

	/* Verify the main header. */
	if (memcmp(main->name, TOC0_MAIN_NAME, sizeof(main->name)))
		goto err;
	if (le32_to_cpu(main->magic) != TOC0_MAIN_MAGIC)
		goto err;
	/* Verify the checksum without modifying the buffer. */
	for (i = 0; i < main_length / 4; ++i)
		checksum += le32_to_cpu(buf32[i]);
	if (checksum != 2 * le32_to_cpu(main->checksum))
		goto err;
	/* The length must be at least 512 byte aligned. */
	if (main_length % 512)
		goto err;
	if (memcmp(main->end, TOC0_MAIN_END, sizeof(main->end)))
		goto err;

	/* Verify the key item if present. */
	item = toc0_find_item(main, TOC0_ITEM_NAME_KEY, &offset, &length);
	if (!item)
		fw_key = root_key;
	else if (toc0_verify_key_item(buf + offset, length, root_key, &fw_key))
		goto err;

	/* Hash the firmware to compare with the certificate. */
	item = toc0_find_item(main, TOC0_ITEM_NAME_FIRMWARE, &offset, &length);
	if (!item)
		goto err;
	SHA256(buf + offset, length, digest);

	/* Verify the certificate item. */
	item = toc0_find_item(main, TOC0_ITEM_NAME_CERT, &offset, &length);
	if (!item)
		goto err;
	if (toc0_verify_cert_item(buf + offset, length, fw_key, digest))
		goto err;

	ret = EXIT_SUCCESS;

err:
	if (fw_key != root_key)
		RSA_free(fw_key);

	return ret;
}

static int toc0_check_params(struct image_tool_params *params)
{
	return !params->dflag;
}

static int toc0_verify_header(unsigned char *buf, int image_size,
			      struct image_tool_params *params)
{
	RSA *root_key = NULL;
	FILE *fp;
	int ret;

	/* A root public key is optional. */
	fp = fopen("root_key.pem", "rb");
	if (fp) {
		root_key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
		fclose(fp);
	}

	ret = toc0_verify(buf, image_size, root_key);

	RSA_free(root_key);

	return ret;
}

static const char *toc0_item_name(uint32_t name)
{
	if (name == TOC0_ITEM_NAME_CERT)
		return "Certificate";
	if (name == TOC0_ITEM_NAME_FIRMWARE)
		return "Firmware";
	if (name == TOC0_ITEM_NAME_KEY)
		return "Key Ladder";
	return "(unknown)";
}

static void toc0_print_header(const void *buf)
{
	const struct toc0_main *main = buf;
	const struct toc0_item *item = (void *)(main + 1);
	uint32_t head_length, main_length, num_items;
	uint32_t item_offset, item_length, item_name;
	int load_addr = -1;
	int i;

	num_items   = le32_to_cpu(main->num_items);
	head_length = sizeof(*main) + num_items * sizeof(*item);
	main_length = le32_to_cpu(main->length);

	printf("Allwinner TOC0 Image, %d items, %d bytes\n"
	       " 00000000:%08x   Headers\n",
	       num_items, main_length, head_length);

	for (i = 0; i < num_items; ++i, ++item) {
		item_offset = le32_to_cpu(item->offset);
		item_length = le32_to_cpu(item->length);
		item_name   = le32_to_cpu(item->name);

		if (item_name == TOC0_ITEM_NAME_FIRMWARE)
			load_addr = le32_to_cpu(item->load_addr);

		printf(" %08x:%08x %x %s\n",
		       item_offset, item_length,
		       item_name & 0xf, toc0_item_name(item_name));
	}

	if (num_items && item_offset + item_length < main_length) {
		item_offset = item_offset + item_length;
		item_length = main_length - item_offset;

		printf(" %08x:%08x   Padding\n",
		       item_offset, item_length);
	}

	if (load_addr >= 0)
		printf("Load address: 0x%08x\n", load_addr);
}

static void toc0_set_header(void *buf, struct stat *sbuf, int ifd,
			    struct image_tool_params *params)
{
	uint32_t key_item_len = 0;
	uint8_t *key_item = NULL;
	int ret = EXIT_FAILURE;
	RSA *root_key = NULL;
	RSA *fw_key = NULL;
	FILE *fp;

	/* Either a key item or the root private key is required. */
	fp = fopen("key_item.bin", "rb");
	if (fp) {
		key_item_len = sizeof(struct toc0_key_item);
		key_item = OPENSSL_malloc(key_item_len);
		if (!key_item)
			goto err;
		if (fread(key_item, key_item_len, 1, fp) != 1)
			goto err;
		fclose(fp);
		fp = NULL;
	}
	fp = fopen("rotpk.pem", "rb");
	if (fp) {
		root_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
		fp = NULL;
	}
	if (!root_key) {
		if (!key_item)
			goto err;

		/* With a key item, the root public key is okay too. */
		fp = fopen("rotpk.pem", "rb");
		if (fp) {
			root_key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
			fclose(fp);
			fp = NULL;
		}
	}

	/* The certificate/firmware private key is always required. */
	fp = fopen("key.pem", "rb");
	if (fp) {
		fw_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
		fp = NULL;
	}
	if (!fw_key) {
		/* If the root key is a private key, it can be used instead. */
		if (root_key && RSA_get0_d(root_key))
			fw_key = root_key;
		else
			goto err;
	}

	ret = toc0_create(buf, params->file_size, root_key, fw_key,
			  key_item, key_item_len,
			  buf + TOC0_DEFAULT_HEADER_LENGTH,
			  params->orig_file_size, params->addr);

err:
	if (key_item)
		OPENSSL_free(key_item);
	OPENSSL_free(root_key);
	if (fw_key != root_key)
		OPENSSL_free(fw_key);
	if (fp)
		fclose(fp);

	if (ret != EXIT_SUCCESS)
		exit(ret);
}

static int toc0_extract_subimage(void *buf, struct image_tool_params *params)
{
	return -1;
}

static int toc0_check_image_type(uint8_t type)
{
	return type == IH_TYPE_SUNXI_TOC0 ? 0 : 1;
}

static int toc0_vrec_header(struct image_tool_params *params,
			    struct image_type_params *tparams)
{
	tparams->hdr = calloc(tparams->header_size, 1);

	/* Save off the unpadded data size for SHA256 calculation. */
	params->orig_file_size = params->file_size - TOC0_DEFAULT_HEADER_LENGTH;

	/* Return padding to 8K blocks. */
	return ALIGN(params->file_size, PAD_SIZE) - params->file_size;
}

U_BOOT_IMAGE_TYPE(
	sunxi_toc0,
	"Allwinner TOC0 Boot Image support",
	TOC0_DEFAULT_HEADER_LENGTH,
	NULL,
	toc0_check_params,
	toc0_verify_header,
	toc0_print_header,
	toc0_set_header,
	toc0_extract_subimage,
	toc0_check_image_type,
	NULL,
	toc0_vrec_header
);
