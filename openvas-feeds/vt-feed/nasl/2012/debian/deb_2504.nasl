# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71483");
  script_cve_id("CVE-2011-2730");
  script_tag(name:"creation_date", value:"2012-08-10 07:07:37 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2504");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2504");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libspring-2.5-java' package(s) announced via the DSA-2504 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Spring Framework contains an information disclosure vulnerability in the processing of certain Expression Language (EL) patterns, allowing attackers to access sensitive information using HTTP requests.

NOTE: This update adds a springJspExpressionSupport context parameter which must be manually set to false when the Spring Framework runs under a container which provides EL support itself.

For the stable distribution (squeeze), this problem has been fixed in version 2.5.6.SEC02-2+squeeze1.

We recommend that you upgrade your libspring-2.5-java packages.");

  script_tag(name:"affected", value:"'libspring-2.5-java' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);