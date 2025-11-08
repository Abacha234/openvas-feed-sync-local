# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.3954.1");
  script_cve_id("CVE-2020-35881", "CVE-2025-55159");
  script_tag(name:"creation_date", value:"2025-11-06 14:12:56 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 16:44:07 +0000 (Thu, 07 Jan 2021)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:3954-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3954-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253954-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249851");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023164.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aws-efs-utils' package(s) announced via the SUSE-SU-2025:3954-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aws-efs-utils fixes the following issues:

Update to version 2.3.3 (bsc#1240044).

Security issues fixed:

- CVE-2025-55159: slab: incorrect bounds check in `get_disjoint_mut` function can lead to potential crash due to out-of-bounds access (bsc#1248055).
- CVE-2020-35881: traitobject: log4rs: out-of-bounds write due to fat pointer layout assumptions (bsc#1249851).

Other issues fixed:

- Build and install efs-proxy binary (bsc#1240044).

- Fixed in version 2.3.3:
 * Add environment variable support for AWS profiles and regions
 * Regenerate Cargo.lock with rust 1.70.0
 * Update circle-ci config
 * Fix AWS Env Variable Test and Code Style Issue
 * Remove CentOS 8 and Ubuntu 16.04 from verified Linux distribution list

- Fixed in version 2.3.2:
 * Update version in amazon-efs-utils.spec to 2.3.1
 * Fix incorrect package version

- Fixed in version 2.3.1:
 * Fix backtrace version to resolve ubuntu and rhel build issues
 * Pin Cargo.lock to avoid unexpected error across images

- Fixed in version 2.3.0:
 * Add support for pod-identity credentials in the credentials chain
 * Enable mounting with IPv6 when using with the 'stunnel' mount option

- Fixed in version 2.2.1:
 * Update log4rs

- Fixed in version 2.2.0
 * Use region-specific domain suffixes for dns endpoints where missing
 * Merge PR #211 - Amend Debian control to use binary architecture

- Fixed in version 2.1.0
 * Add mount option for specifying region
 * Add new ISO regions to config file

- Fixed in version 2.0.4
 * Add retry logic to and increase timeout for EC2 metadata token
 retrieval requests

- Fixed in version 2.0.3:
 * Upgrade py version
 * Replace deprecated usage of datetime

- Fixed in version 2.0.2
 * Check for efs-proxy PIDs when cleaning tunnel state files
 * Add PID to log entries

- Fxied in version 2.0.1
 * Disable Nagle's algorithm for efs-proxy TLS mounts to improve latencies

- Fixed in version 2.0.0:
 * Replace stunnel, which provides TLS encryptions for mounts, with efs-proxy, a component built in-house at AWS.
 Efs-proxy lays the foundation for upcoming feature launches at EFS.

- Fixed in version 1.36.0:
 * Support new mount option: crossaccount, conduct cross account mounts via ip address. Use client AZ-ID to choose
 mount target.

- Fixed in version 1.35.2:
 * Revert 'Add warning if using older Version'
 * Support MacOS Sonoma

- Fixed in version 1.35.1:
 * Revert openssl requirement change
 * Revert 'Update EFS Documentation: Clarify Current FIPS Compliance Status'
 * Update EFS Documentation: Clarify Current FIPS Compliance Status
 * test: Change repo urls in eol debian9 build
 * Check private key file size to skip generation
 * test: Fix pytest that failed since commit 3dd89ca
 * Fix should_check_efs_utils_version scope
 * Add warning if using old version
 * Add 'fsap' option as EFS-only option

- Fixed in version 1.35.0:
 * Add parameters to allow mount fo pod ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'aws-efs-utils' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"aws-efs-utils", rpm:"aws-efs-utils~2.3.3~150600.17.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
