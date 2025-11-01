# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703682");
  script_cve_id("CVE-2016-5180");
  script_tag(name:"creation_date", value:"2016-10-05 10:13:05 +0000 (Wed, 05 Oct 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:17:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-3682)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3682");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3682");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'c-ares' package(s) announced via the DSA-3682 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gzob Qq discovered that the query-building functions in c-ares, an asynchronous DNS request library would not correctly process crafted query names, resulting in a heap buffer overflow and potentially leading to arbitrary code execution.

For the stable distribution (jessie), this problem has been fixed in version 1.10.0-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1.12.0-1.

We recommend that you upgrade your c-ares packages.");

  script_tag(name:"affected", value:"'c-ares' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);