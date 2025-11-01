# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67386");
  script_cve_id("CVE-2010-0743");
  script_tag(name:"creation_date", value:"2010-05-14 18:09:58 +0000 (Fri, 14 May 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2042");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2042");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iscsitarget' package(s) announced via the DSA-2042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florent Daigniere discovered multiple format string vulnerabilities in Linux SCSI target framework (which is known as iscsitarget under Debian) allow remote attackers to cause a denial of service in the ietd daemon. The flaw could be trigger by sending a carefully-crafted Internet Storage Name Service (iSNS) request.

For the stable distribution (lenny), this problem has been fixed in version 0.4.16+svn162-3.1+lenny1.

For the testing distribution (squeeze), this problem has been fixed in version 0.4.17+svn229-1.4.

For the unstable distribution (sid), this problem has been fixed in version 0.4.17+svn229-1.4.");

  script_tag(name:"affected", value:"'iscsitarget' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);