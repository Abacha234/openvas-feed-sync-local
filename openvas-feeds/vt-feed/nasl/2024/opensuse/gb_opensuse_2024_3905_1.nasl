# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856689");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-50782");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:52:10 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-11-05 05:00:47 +0000 (Tue, 05 Nov 2024)");
  script_name("openSUSE: Security Advisory for openssl (SUSE-SU-2024:3905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3905-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YHCXW7HVIA2EO5KSMYO7CIOZIE2RF2LP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the SUSE-SU-2024:3905-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_1 fixes the following issues:

  Security fixes:

  * CVE-2023-50782: Implicit rejection in PKCS#1 v1.5 (bsc#1220262)

  Other fixes:

  * FIPS: AES GCM external IV implementation (bsc#1228618)

  * FIPS: Mark PBKDF2 and HKDF HMAC input keys with size >= 112 bits as approved
      in the SLI. (bsc#1228623)

  * FIPS: Enforce KDF in FIPS style (bsc#1224270)

  * FIPS: Mark HKDF and TLSv1.3 KDF as approved in the SLI (bsc#1228619)

  * FIPS: The X9.31 scheme is not approved for RSA signature operations in FIPS
      186-5. (bsc#1224269)

  * FIPS: Differentiate the PSS length requirements (bsc#1224275)

  * FIPS: Mark sigGen and sigVer primitives as non-approved (bsc#1224272)

  * FIPS: Disable PKCSv1.5 and shake in FIPS mode (bsc#1224271)

  * FIPS: Mark SHA1 as non-approved in the SLI (bsc#1224266)

  * FIPS: DH FIPS selftest and safe prime group (bsc#1224264)

  * FIPS: Remove not needed FIPS DRBG files (bsc#1224268)

  * FIPS: Add Pair-wise Consistency Test when generating DH key (bsc#1224265)

  * FIPS: Disallow non-approved KDF types (bsc#1224267)

  * FIPS: Disallow RSA sigVer with 1024 and ECDSA sigVer/keyVer P-192
      (bsc#1224273)

  * FIPS: DRBG component chaining (bsc#1224258)

  * FIPS: Align CRNGT_BUFSIZ with Jitter RNG output size (bsc#1224260)");

  script_tag(name:"affected", value:"'openssl' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
