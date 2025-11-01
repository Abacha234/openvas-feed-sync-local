# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703189");
  script_cve_id("CVE-2014-7933", "CVE-2014-8543", "CVE-2014-8544", "CVE-2014-8547", "CVE-2014-8548", "CVE-2014-9604");
  script_tag(name:"creation_date", value:"2015-03-14 23:00:00 +0000 (Sat, 14 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3189");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3189");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DSA-3189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and decoders of the libav multimedia library. A full list of the changes is available at

For the stable distribution (wheezy), these problems have been fixed in version 6:0.8.17-1.

For the unstable distribution (sid), these problems have been fixed in version 6:11.3-1.

We recommend that you upgrade your libav packages.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);