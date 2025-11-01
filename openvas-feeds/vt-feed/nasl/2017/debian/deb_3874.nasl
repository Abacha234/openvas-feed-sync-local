# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703874");
  script_cve_id("CVE-2017-6430", "CVE-2017-8366");
  script_tag(name:"creation_date", value:"2017-06-08 22:00:00 +0000 (Thu, 08 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3874)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3874");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3874");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ettercap' package(s) announced via the DSA-3874 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Agostino Sarubbo and AromalUllas discovered that ettercap, a network security tool for traffic interception, contains vulnerabilities that allowed an attacker able to provide maliciously crafted filters to cause a denial-of-service via application crash.

For the stable distribution (jessie), these problems have been fixed in version 1:0.8.1-3+deb8u1.

For the upcoming stable (stretch) and unstable (sid) distributions, these problems have been fixed in version 1:0.8.2-4.

We recommend that you upgrade your ettercap packages.");

  script_tag(name:"affected", value:"'ettercap' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);