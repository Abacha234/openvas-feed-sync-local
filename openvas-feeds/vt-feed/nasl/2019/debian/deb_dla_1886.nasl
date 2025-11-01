# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891886");
  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2816");
  script_tag(name:"creation_date", value:"2019-08-16 02:00:12 +0000 (Fri, 16 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 18:47:00 +0000 (Thu, 06 Oct 2022)");

  script_name("Debian: Security Advisory (DLA-1886)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1886");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1886-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-7' package(s) announced via the DLA-1886 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The latest security update of openjdk-7 caused a regression when applications relied on elliptic curve algorithms to establish SSL connections. Several duplicate classes were removed from rt.jar by the upstream developers of OpenJDK because they were also present in sunec.jar. However Debian never shipped the SunEC security provider in OpenJDK 7.

The issue was resolved by building sunec.jar and its corresponding native library libsunec.so from source. In order to build these libraries from source, an update of nss to version 2:3.26-1+debu8u6 is required.

Updates for the amd64 architecture are already available, new packages for i386, armel and armhf will be available within the next 24 hours.

For Debian 8 Jessie, this problem has been fixed in version 7u231-2.6.19-1~deb8u2.

We recommend that you upgrade your openjdk-7 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);