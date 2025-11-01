# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704380");
  script_cve_id("CVE-2018-6574", "CVE-2018-7187", "CVE-2019-6486");
  script_tag(name:"creation_date", value:"2019-01-31 23:00:00 +0000 (Thu, 31 Jan 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:01:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-4380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4380");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4380");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/golang-1.8");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'golang-1.8' package(s) announced via the DSA-4380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the implementation of the P-521 and P-384 elliptic curves, which could result in denial of service and in some cases key recovery.

In addition this update fixes two vulnerabilities in go get, which could result in the execution of arbitrary shell commands.

For the stable distribution (stretch), these problems have been fixed in version 1.8.1-1+deb9u1.

We recommend that you upgrade your golang-1.8 packages.

For the detailed security status of golang-1.8 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'golang-1.8' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);