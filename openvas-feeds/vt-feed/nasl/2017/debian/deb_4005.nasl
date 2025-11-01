# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704005");
  script_cve_id("CVE-2017-10086", "CVE-2017-10114");
  script_tag(name:"creation_date", value:"2017-10-19 22:00:00 +0000 (Thu, 19 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 18:05:00 +0000 (Fri, 12 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-4005)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4005");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4005");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjfx' package(s) announced via the DSA-4005 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two unspecified vulnerabilities were discovered in OpenJFX, a rich client application platform for Java.

For the stable distribution (stretch), these problems have been fixed in version 8u141-b14-3~deb9u1.

We recommend that you upgrade your openjfx packages.");

  script_tag(name:"affected", value:"'openjfx' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);