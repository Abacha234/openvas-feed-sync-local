# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61032");
  script_cve_id("CVE-2008-0554");
  script_tag(name:"creation_date", value:"2008-05-27 13:41:50 +0000 (Tue, 27 May 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1579)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1579");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1579");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'netpbm-free' package(s) announced via the DSA-1579 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the GIF reader implementation in netpbm-free, a suite of image manipulation utilities. Insufficient input data validation could allow a maliciously-crafted GIF file to overrun a stack buffer, potentially permitting the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 2:10.0-11.1+etch1.

For the unstable distribution (sid), these problems were fixed in version 2:10.0-11.1.

We recommend that you upgrade your netpbm packages.");

  script_tag(name:"affected", value:"'netpbm-free' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);