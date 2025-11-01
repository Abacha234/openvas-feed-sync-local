# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892057");
  script_cve_id("CVE-2019-19911", "CVE-2020-5312", "CVE-2020-5313");
  script_tag(name:"creation_date", value:"2020-01-07 03:00:10 +0000 (Tue, 07 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-2057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2057");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2057");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pillow' package(s) announced via the DLA-2057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were three vulnerabilities in Pillow, an imaging library for the Python programming language

CVE-2019-19911

There is a DoS vulnerability in Pillow before 6.2.2 caused by FpxImagePlugin.py calling the range function on an unvalidated 32-bit integer if the number of bands is large. On Windows running 32-bit Python, this results in an OverflowError or MemoryError due to the 2 GB limit. However, on Linux running 64-bit Python this results in the process being terminated by the OOM killer.

CVE-2020-5312

libImaging/PcxDecode.c in Pillow before 6.2.2 has a PCX P mode buffer overflow.

CVE-2020-5313

libImaging/FliDecode.c in Pillow before 6.2.2 has an FLI buffer overflow.

For Debian 8 Jessie, these problems have been fixed in version 2.6.1-2+deb8u4.

We recommend that you upgrade your pillow packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pillow' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);