# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53662");
  script_cve_id("CVE-2003-0743");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-376)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-376");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-376");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim, exim-tls' package(s) announced via the DSA-376 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow exists in exim, which is the standard mail transport agent in Debian. By supplying a specially crafted HELO or EHLO command, an attacker could cause a constant string to be written past the end of a buffer allocated on the heap. This vulnerability is not believed at this time to be exploitable to execute arbitrary code.

For the stable distribution (woody) this problem has been fixed in exim version 3.35-1woody2 and exim-tls version 3.35-3woody1.

For the unstable distribution (sid) this problem has been fixed in exim version 3.36-8. The unstable distribution does not contain an exim-tls package.

We recommend that you update your exim or exim-tls package.");

  script_tag(name:"affected", value:"'exim, exim-tls' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);