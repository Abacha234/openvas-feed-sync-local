# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702935");
  script_cve_id("CVE-2014-3775");
  script_tag(name:"creation_date", value:"2014-05-20 22:00:00 +0000 (Tue, 20 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2935)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2935");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2935");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgadu' package(s) announced via the DSA-2935 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that malformed responses from a Gadu-Gadu file relay server could lead to denial of service or the execution of arbitrary code in applications linked to the libgadu library.

The oldstable distribution (squeeze) is not affected.

For the stable distribution (wheezy), this problem has been fixed in version 1.11.2-1+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 1:1.12.0~rc3-1.

We recommend that you upgrade your libgadu packages.");

  script_tag(name:"affected", value:"'libgadu' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);