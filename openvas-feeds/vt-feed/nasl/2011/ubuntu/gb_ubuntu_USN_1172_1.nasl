# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840705");
  script_cve_id("CVE-2011-1098", "CVE-2011-1154", "CVE-2011-1155", "CVE-2011-1548");
  script_tag(name:"creation_date", value:"2011-07-22 12:44:51 +0000 (Fri, 22 Jul 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1172-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1172-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'logrotate' package(s) announced via the USN-1172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that logrotate incorrectly handled the creation of new
log files. Local users could possibly read log files if they were opened
before permissions were in place. This issue only affected Ubuntu 8.04 LTS.
(CVE-2011-1098)

It was discovered that logrotate incorrectly handled certain log file
names when used with the shred option. Local attackers able to create log
files with specially crafted filenames could use this issue to execute
arbitrary code. This issue only affected Ubuntu 10.04 LTS, 10.10, and
11.04. (CVE-2011-1154)

It was discovered that logrotate incorrectly handled certain malformed log
filenames. Local attackers able to create log files with specially crafted
filenames could use this issue to cause logrotate to stop processing log
files, resulting in a denial of service. (CVE-2011-1155)

It was discovered that logrotate incorrectly handled symlinks and hard
links when processing log files. A local attacker having write access to
a log file directory could use this issue to overwrite or read arbitrary
files. This issue only affected Ubuntu 8.04 LTS. (CVE-2011-1548)");

  script_tag(name:"affected", value:"'logrotate' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
