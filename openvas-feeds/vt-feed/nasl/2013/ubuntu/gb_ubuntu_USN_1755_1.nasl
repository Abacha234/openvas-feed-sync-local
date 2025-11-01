# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841350");
  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_tag(name:"creation_date", value:"2013-03-08 04:52:20 +0000 (Fri, 08 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1755-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1755-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1755-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-1755-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJDK did not properly validate certain types
of images. A remote attacker could exploit this to cause OpenJDK to crash.
(CVE-2013-0809)

It was discovered that OpenJDK did not properly check return values when
performing color conversion for images. If a user were tricked into
opening a crafted image with OpenJDK, such as with the Java plugin, a
remote attacker could cause OpenJDK to crash or execute arbitrary code
outside of the Java sandbox with the privileges of the user invoking the
program. (CVE-2013-1493)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
