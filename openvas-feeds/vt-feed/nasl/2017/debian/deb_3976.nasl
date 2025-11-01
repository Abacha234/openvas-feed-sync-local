# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703976");
  script_cve_id("CVE-2017-2923", "CVE-2017-2924");
  script_tag(name:"creation_date", value:"2017-09-16 22:00:00 +0000 (Sat, 16 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-13 19:05:00 +0000 (Mon, 13 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-3976)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3976");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3976");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freexl' package(s) announced via the DSA-3976 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcin Icewall Noga of Cisco Talos discovered two vulnerabilities in freexl, a library to read Microsoft Excel spreadsheets, which might result in denial of service or the execution of arbitrary code if a malformed Excel file is opened.

For the oldstable distribution (jessie), these problems have been fixed in version 1.0.0g-1+deb8u4.

For the stable distribution (stretch), these problems have been fixed in version 1.0.2-2+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 1.0.4-1.

We recommend that you upgrade your freexl packages.");

  script_tag(name:"affected", value:"'freexl' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);