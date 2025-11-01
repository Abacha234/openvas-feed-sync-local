# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856533");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-6917", "CVE-2024-3019", "CVE-2024-45769", "CVE-2024-45770");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-28 19:15:49 +0000 (Thu, 28 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-10-05 04:00:29 +0000 (Sat, 05 Oct 2024)");
  script_name("openSUSE: Security Advisory for pcp (SUSE-SU-2024:3533-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3533-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EJ6XABU6MHTMW7YBC6VNICEWPLUE5ELO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcp'
  package(s) announced via the SUSE-SU-2024:3533-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcp fixes the following issues:

  pcp was updated from version 5.3.7 to version 6.2.0 (jsc#PED-8192,
  jsc#PED-8389):

  * Security issues fixed:

  * CVE-2024-45770: Fixed a symlink attack that allows escalating from the pcp
      to the root user (bsc#1230552)

  * CVE-2024-45769: Fixed a heap corruption through metric pmstore operations
      (bsc#1230551)

  * CVE-2023-6917: Fixed local privilege escalation from pcp user to root in
      /usr/libexec/pcp/lib/pmproxy (bsc#1217826)

  * CVE-2024-3019: Disabled redis proxy by default (bsc#1222121)

  * Major changes:

  * Add version 3 PCP archive support: instance domain change-deltas, Y2038-safe
      timestamps, nanosecond-precision timestamps, arbitrary timezones support,
      64-bit file offsets used throughout for larger (beyond 2GB) individual
      volumes.

  * Opt-in using the /etc/pcp.conf PCP_ARCHIVE_VERSION setting

  * Version 2 archives remain the default (for next few years).

  * Switch to using OpenSSL only throughout PCP (dropped NSS/NSPR)  this impacts
      on libpcp, PMAPI clients and PMCD use of encryption  these are now
      configured and used consistently with pmproxy HTTPS support and redis-
      server, which were both already using OpenSSL.

  * New nanosecond precision timestamp PMAPI calls for PCP library interfaces
      that make use of timestamps.
  These are all optional, and full backward compatibility is preserved for
  existing tools.

  * For the full list of changes please consult the packaged CHANGELOG file

  * Other packaging changes:

  * Moved pmlogger_daily into main package (bsc#1222815)

  * Change dependency from openssl-devel >= 1.1.1 to openssl-devel >= 1.0.2p.
      Required for SLE-12.

  * Introduce 'pmda-resctrl' package, disabled for architectures other than
      x86_64.

  * Change the architecture for various subpackages to 'noarch' as they contain
      no binaries.

  * Disable 'pmda-mssql', as it fails to build.");

  script_tag(name:"affected", value:"'pcp' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
