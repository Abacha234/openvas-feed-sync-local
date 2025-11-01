# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703550");
  script_cve_id("CVE-2015-8325");
  script_tag(name:"creation_date", value:"2016-04-14 22:00:00 +0000 (Thu, 14 Apr 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-30 01:29:00 +0000 (Sat, 30 Jun 2018)");

  script_name("Debian: Security Advisory (DSA-3550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3550");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3550");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-3550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Shayan Sadigh discovered a vulnerability in OpenSSH: If PAM support is enabled and the sshd PAM configuration is configured to read userspecified environment variables and the UseLogin option is enabled, a local user may escalate her privileges to root.

In Debian UseLogin is not enabled by default.

For the oldstable distribution (wheezy), this problem has been fixed in version 6.0p1-4+deb7u4.

For the stable distribution (jessie), this problem has been fixed in version 6.7p1-5+deb8u2.

For the unstable distribution (sid), this problem has been fixed in version 1:7.2p2-3.

We recommend that you upgrade your openssh packages.");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);