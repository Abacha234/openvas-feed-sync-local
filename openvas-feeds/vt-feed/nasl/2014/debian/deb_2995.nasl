# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702995");
  script_cve_id("CVE-2014-4607");
  script_tag(name:"creation_date", value:"2014-08-02 22:00:00 +0000 (Sat, 02 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-14 15:26:00 +0000 (Fri, 14 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-2995)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2995");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2995");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lzo2' package(s) announced via the DSA-2995 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Don A. Bailey from Lab Mouse Security discovered an integer overflow flaw in the way the lzo library decompressed certain archives compressed with the LZO algorithm. An attacker could create a specially crafted LZO-compressed input that, when decompressed by an application using the lzo library, would cause that application to crash or, potentially, execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 2.06-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in version 2.08-1.

For the unstable distribution (sid), this problem has been fixed in version 2.08-1.

We recommend that you upgrade your lzo2 packages.");

  script_tag(name:"affected", value:"'lzo2' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);