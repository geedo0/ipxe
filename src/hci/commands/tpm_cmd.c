/*
 * Copyright (C) 2013 Matthew Garrett <matthew.garrett at nebula.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <errno.h>
#include <getopt.h>
#include <ipxe/command.h>
#include <ipxe/crypto.h>
#include <ipxe/efi/efi.h>
#include <ipxe/efi/efi_utils.h>
#include <ipxe/efi/Protocol/TcgService.h>
#include <ipxe/image.h>
#include <ipxe/parseopt.h>
#include <ipxe/sha1.h>
#include <realmode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <usr/imgmgmt.h>

#undef ERRFILE
#define ERRFILE ERRFILE_tpm

#define TCG_ALG_SHA ( (TCG_ALGORITHM_ID) 0x00000004 ) // The SHA1 algorithm
#define EV_IPL ((TCG_EVENTTYPE) 0x0000000d)

/** @file
 *
 * TPM commands
 *
 */

/** "tpm" options */
struct tpm_options {};

/** "tpm" option list */
static struct option_descriptor tpm_opts[] = {};

/** "tpm" command descriptor */
static struct command_descriptor tpm_cmd =
	COMMAND_DESC ( struct tpm_options, tpm_opts, 2, 2,
					 "<image> <pcr>" );

int tpm_present ( void ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;

	union {
		void *interface;
		EFI_TCG_PROTOCOL *prot;
	} tcg;

	TCG_EFI_BOOT_SERVICE_CAPABILITY protocolCapability;
	uint32_t tcgFeatureFlags;
	EFI_PHYSICAL_ADDRESS eventLogLocation;
	EFI_PHYSICAL_ADDRESS eventLogLastEntry;

	if ( ( efirc = bs->LocateProtocol ( &efi_tcg_protocol_guid, NULL,
					&tcg.interface ) ) != 0 ) {
		DBG ( "Failed to locate TCG protocol: 0x%08x\n", (uint32_t) efirc );
		return 0;
	}

	if ( ( efirc = tcg.prot->StatusCheck(tcg.prot, &protocolCapability,
					&tcgFeatureFlags, &eventLogLocation, &eventLogLastEntry ) ) ) {
		DBG ( "Could not obtain status: 0x%08x\n", (uint32_t) efirc );
		return 0;
	}

	DBG ( "Size: %d\n", protocolCapability.Size);
	DBG ( "TPM Version: %02d.%02d.%02d.%02d\n",
		protocolCapability.ProtocolSpecVersion.Major,
		protocolCapability.ProtocolSpecVersion.Minor,
		protocolCapability.ProtocolSpecVersion.RevMajor,
		protocolCapability.ProtocolSpecVersion.RevMinor
	);

	return protocolCapability.TPMPresentFlag != 0;
}

int update_pcr ( unsigned int pcr, uint8_t *digest ) {
	EFI_BOOT_SERVICES *bs = efi_systab->BootServices;
	EFI_STATUS efirc;
	uint32_t i;

	EFI_PHYSICAL_ADDRESS EventLogLastEntry;
	TCG_PCR_EVENT tcgLogData;
	uint32_t EventNumber = 0;

	union {
		void *interface;
		EFI_TCG_PROTOCOL *prot;
	} tcg;

	if ( ( efirc = bs->LocateProtocol ( &efi_tcg_protocol_guid, NULL,
					&tcg.interface ) ) != 0 ) {
		DBG ( "Failed to locate TCG protocol: 0x%08x\n", (uint32_t) efirc );
		return -ENOTSUP;
	}

	tcgLogData.PCRIndex = (TCG_PCRINDEX) pcr;
	tcgLogData.EventType = EV_IPL;
	for( i = 0; i < sha1_algorithm.digestsize; i++) {
		tcgLogData.Digest.digest[i] = digest[i];
	}
	// Should be "IPL" but the headers define Event to be an array of length 1
	tcgLogData.EventSize = 1;
	tcgLogData.Event[0] = (uint8_t) 'I';

	if ( ( efirc = tcg.prot->HashLogExtendEvent(tcg.prot, 0, 0, TCG_ALG_SHA,
					&tcgLogData, &EventNumber, &EventLogLastEntry) ) ) {
		DBG ( "EFI_TCG_PROTOCOL.HashLogExtendEvent Failed: 0x%08x\n",
			(uint32_t) efirc );
		return -EIO;
	}

	return 0;
}

/**
 * Generate a sha1 hash an image
 *
 * @v image		Image to hash
 * @v digest_out	Output buffer. Must be at least 20 bytes long.
 */
void hash_image ( struct image *image, uint8_t *digest_out ) {
	struct digest_algorithm *digest = &sha1_algorithm;
	uint8_t digest_ctx[digest->ctxsize];
	uint8_t buf[128];
	size_t offset;
	size_t len;
	size_t frag_len;

	offset = 0;
	len = image->len;

	/* calculate digest */
	digest_init ( digest, digest_ctx );
	while ( len ) {
		frag_len = len;
		if ( frag_len > sizeof ( buf ) )
			frag_len = sizeof ( buf );
		copy_from_user ( buf, image->data, offset, frag_len );
		digest_update ( digest, digest_ctx, buf, frag_len );
		len -= frag_len;
		offset += frag_len;
	}
	digest_final ( digest, digest_ctx, digest_out );
}

/**
 * The "tpm" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int tpm_exec ( int argc, char **argv) {
	struct tpm_options opts;
	struct image *image;
	int rc;
	int pcr;
	char *end;
	uint8_t digest[sha1_algorithm.digestsize];

	if ( ! tpm_present () )
	{
		printf ( "TPM not present\n");
		return -ENODEV;
	}

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &tpm_cmd, &opts ) ) != 0 ) {
		printf ( "Unable to parse options: %d\n", rc );
		return rc;
	}

	/* Acquire image */
	unsigned long timeout = 60;
	if ( ( rc = imgacquire ( argv[1], timeout, &image ) ) != 0 ) {
		printf ( "Unable to acquire image: %d\n", rc );
		return rc;
	}

	hash_image ( image, digest );

	pcr = strtoul( argv[2], &end, 10 );

	if ( *end || pcr < 8 || pcr > 15) {
		printf ( "Invalid PCR \"%s\"\n", argv[2] );
		return -EINVAL;
	}

	return update_pcr ( pcr, digest );
}

struct command tpm_command __command = {
	.name = "tpm",
	.exec = tpm_exec,
};
