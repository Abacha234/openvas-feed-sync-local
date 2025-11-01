# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833804");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-5679", "CVE-2023-6516");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:46 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:38 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for bind (SUSE-SU-2024:0590-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0590-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LLNKOQRCD72E3BLQA5UKDCZLJEVSGGAW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the SUSE-SU-2024:0590-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  Update to release 9.16.48:

  Feature Changes: * The IP addresses for B.ROOT-SERVERS.NET have been updated to
  170.247.170.2 and 2801:1b8:10::b.

  Security Fixes: * Validating DNS messages containing a lot of DNSSEC signatures
  could cause excessive CPU load, leading to a denial-of-service condition. This
  has been fixed. (CVE-2023-50387) [bsc#1219823] * Preparing an NSEC3 closest
  encloser proof could cause excessive CPU load, leading to a denial-of-service
  condition. This has been fixed. (CVE-2023-50868) [bsc#1219826] * Parsing DNS
  messages with many different names could cause excessive CPU load. This has been
  fixed. (CVE-2023-4408) [bsc#1219851] * Specific queries could cause named to
  crash with an assertion failure when nxdomain-redirect was enabled. This has
  been fixed. (CVE-2023-5517) [bsc#1219852] * A bad interaction between DNS64 and
  serve-stale could cause named to crash with an assertion failure, when both of
  these features were enabled. This has been fixed. (CVE-2023-5679) [bsc#1219853]

  * Query patterns that continuously triggered cache database maintenance could
  cause an excessive amount of memory to be allocated, exceeding max-cache-size
  and potentially leading to all available memory on the host running named being
  exhausted. This has been fixed. (CVE-2023-6516) [bsc#1219854]

  Removed Features: * Support for using AES as the DNS COOKIE algorithm (cookie-
  algorithm aes ) has been deprecated and will be removed in a future release.
  Please use the current default, SipHash-2-4, instead.

  ##");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
