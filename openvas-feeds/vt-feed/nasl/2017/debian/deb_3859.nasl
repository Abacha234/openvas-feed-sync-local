# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703859");
  script_cve_id("CVE-2017-9078", "CVE-2017-9079");
  script_tag(name:"creation_date", value:"2017-05-18 22:00:00 +0000 (Thu, 18 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-11 17:11:00 +0000 (Mon, 11 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-3859)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3859");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3859");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dropbear' package(s) announced via the DSA-3859 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in Dropbear, a lightweight SSH2 server and client:

CVE-2017-9078

Mark Shepard discovered a double free in the TCP listener cleanup which could result in denial of service by an authenticated user if Dropbear is running with the '-a' option.

CVE-2017-9079

Jann Horn discovered a local information leak in parsing the .authorized_keys file.

For the stable distribution (jessie), these problems have been fixed in version 2014.65-1+deb8u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your dropbear packages.");

  script_tag(name:"affected", value:"'dropbear' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);