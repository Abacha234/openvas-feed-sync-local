# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840487");
  script_cve_id("CVE-2010-2575");
  script_tag(name:"creation_date", value:"2010-08-30 14:59:25 +0000 (Mon, 30 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-979-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-979-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-979-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdegraphics' package(s) announced via the USN-979-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Cornelius of Secunia Research discovered a boundary error during
RLE decompression in the 'TranscribePalmImageToJPEG()' function in
generators/plucker/inplug/image.cpp of okular when processing images
embedded in PDB files, which can be exploited to cause a heap-based
buffer overflow. (CVE-2010-2575)");

  script_tag(name:"affected", value:"'kdegraphics' package(s) on Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
