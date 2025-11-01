# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841617");
  script_cve_id("CVE-2012-5374", "CVE-2012-5375", "CVE-2013-2147");
  script_tag(name:"creation_date", value:"2013-11-18 10:12:09 +0000 (Mon, 18 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2017-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2017-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was discovered in the Btrfs file system in the
Linux kernel. A local user could cause a denial of service by creating a
large number of files with names that have the same CRC32 hash value.
(CVE-2012-5374)

A denial of service flaw was discovered in the Btrfs file system in the
Linux kernel. A local user could cause a denial of service (prevent file
creation) for a victim, by creating a file with a specific CRC32C hash
value in a directory important to the victim. (CVE-2012-5375)

Dan Carpenter discovered an information leak in the HP Smart Array and
Compaq SMART2 disk-array driver in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-2147)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
