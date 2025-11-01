# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704178");
  script_cve_id("CVE-2018-10119", "CVE-2018-10120");
  script_tag(name:"creation_date", value:"2018-04-19 22:00:00 +0000 (Thu, 19 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4178)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4178");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4178");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libreoffice");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libreoffice' package(s) announced via the DSA-4178 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in LibreOffice's code to parse MS Word and Structured Storage files, which could result in denial of service and potentially the execution of arbitrary code if a malformed file is opened.

For the oldstable distribution (jessie), these problems have been fixed in version 1:4.3.3-2+deb8u11.

For the stable distribution (stretch), these problems have been fixed in version 1:5.2.7-1+deb9u4.

We recommend that you upgrade your libreoffice packages.

For the detailed security status of libreoffice please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);