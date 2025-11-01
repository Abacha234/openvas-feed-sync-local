# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704063");
  script_cve_id("CVE-2017-15120");
  script_tag(name:"creation_date", value:"2017-12-10 23:00:00 +0000 (Sun, 10 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4063");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4063");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pdns-recursor");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns-recursor' package(s) announced via the DSA-4063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Toshifumi Sakaguchi discovered that PowerDNS Recursor, a high-performance resolving name server was susceptible to denial of service via a crafted CNAME answer.

The oldstable distribution (jessie) is not affected.

For the stable distribution (stretch), this problem has been fixed in version 4.0.4-1+deb9u3.

We recommend that you upgrade your pdns-recursor packages.

For the detailed security status of pdns-recursor please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);