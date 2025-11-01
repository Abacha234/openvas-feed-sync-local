# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856893");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-36405", "CVE-2024-37305", "CVE-2024-54137");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-01-07 08:15:13 +0000 (Tue, 07 Jan 2025)");
  script_name("openSUSE: Security Advisory for liboqs, oqs (SUSE-SU-2025:0005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0005-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O4ZJGNG4TWYMDZ2DQWHAAHD6QTIXIUTA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liboqs, oqs'
  package(s) announced via the SUSE-SU-2025:0005-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for liboqs, oqs-provider fixes the following issues:

  This update supplies the new FIPS standardized ML-KEM, ML-DSA, SHL-DSA
  algorithms.

  This update liboqs to 0.12.0:

  * This release updates the ML-DSA implementation to the final FIPS 204
      version. This release still includes the NIST Round 3 version of Dilithium
      for interoperability purposes, but we plan to remove Dilithium Round 3 in a
      future release.

  * This will be the last release of liboqs to include Kyber (that is, the NIST
      Round 3 version of Kyber, prior to its standardization by NIST as ML-KEM in
      FIPS 203). Applications should switch to ML-KEM (FIPS 203).

  * The addition of ML-DSA FIPS 204 final version to liboqs has introduced a new
      signature API which includes a context string parameter. We are planning to
      remove the old version of the API without a context string in the next
      release to streamline the API and bring it in line with NIST specifications.
      Users who have an opinion on this removal are invited to provide input at

  Security issues:

  * CVE-2024-54137: Fixed bug in HQC decapsulation that leads to incorrect
      shared secret value during decapsulation when called with an invalid
      ciphertext. (bsc#1234292)

  * new library major version 7

  Updated to 0.11.0:

  * This release still includes the NIST Round 3 version of Kyber for
      interoperability purposes, but we plan to remove Kyber Round 3 in a future
      release.

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'liboqs, oqs' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
