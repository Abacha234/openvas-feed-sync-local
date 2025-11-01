# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705142");
  script_cve_id("CVE-2022-29824");
  script_tag(name:"creation_date", value:"2022-05-24 01:00:55 +0000 (Tue, 24 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 14:53:00 +0000 (Tue, 10 May 2022)");

  script_name("Debian: Security Advisory (DSA-5142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5142");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5142");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxml2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-5142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm reported that several buffer handling functions in libxml2, a library providing support to read, modify and write XML and HTML files, don't check for integer overflows, resulting in out-of-bounds memory writes if specially crafted, multi-gigabyte XML files are processed. An attacker can take advantage of this flaw for denial of service or execution of arbitrary code.

For the oldstable distribution (buster), this problem has been fixed in version 2.9.4+dfsg1-7+deb10u4.

For the stable distribution (bullseye), this problem has been fixed in version 2.9.10+dfsg-6.7+deb11u2.

We recommend that you upgrade your libxml2 packages.

For the detailed security status of libxml2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);