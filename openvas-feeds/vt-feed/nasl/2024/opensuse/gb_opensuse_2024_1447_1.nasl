# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856113");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-0914");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:01:38 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-05-07 01:00:25 +0000 (Tue, 07 May 2024)");
  script_name("openSUSE: Security Advisory for openCryptoki (SUSE-SU-2024:1447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1447-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D6VERPVK3GYPK53DHQMFYB2I5SMISXMS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openCryptoki'
  package(s) announced via the SUSE-SU-2024:1447-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openCryptoki fixes the following issues:

  Upgrade openCryptoki to version 3.23 (jsc#PED-3360, jsc#PED-3361)

  * EP11: Add support for FIPS-session mode

  * CVE-2024-0914: Updates to harden against RSA timing attacks (bsc#1219217)

  * Bug fixes

  * provide user(pkcs11) and group(pkcs11)

  Upgrade to version 3.22 (jsc#PED-3361)

  * CCA: Add support for the AES-XTS key type using CPACF protected keys

  * p11sak: Add support for managing certificate objects

  * p11sak: Add support for public sessions (no-login option)

  * p11sak: Add support for logging in as SO (security Officer)

  * p11sak: Add support for importing/exporting Edwards and Montgomery keys

  * p11sak: Add support for importing of RSA-PSS keys and certificates

  * CCA/EP11/Soft/ICA: Ensure that the 2 key parts of an AES-XTS key are
      different

  Update to version 3.21 (jsc#PED-3360, jsc#PED-3361)

  * EP11 and CCA: Support concurrent HSM master key changes

  * CCA: protected-key option

  * pkcsslotd: no longer run as root user and further hardening

  * p11sak: Add support for additional key types (DH, DSA, generic secret)

  * p11sak: Allow wildcards in label filter

  * p11sak: Allow to specify hex value for CKA_ID attribute

  * p11sak: Support sorting when listing keys

  * p11sak: New commands: set-key-attr, copy-key to modify and copy keys

  * p11sak: New commands: import-key, export-key to import and export keys

  * Remove support for --disable-locks (transactional memory)

  * Updates to harden against RSA timing attacks

  * Bug fixes

  ##");

  script_tag(name:"affected", value:"'openCryptoki' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
