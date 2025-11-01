# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891666");
  script_cve_id("CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");
  script_tag(name:"creation_date", value:"2019-02-10 23:00:00 +0000 (Sun, 10 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 16:29:00 +0000 (Mon, 03 Jun 2019)");

  script_name("Debian: Security Advisory (DLA-1666)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1666");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1666");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freerdp' package(s) announced via the DLA-1666 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"For the FreeRDP version in Debian jessie LTS a security and functionality update has recently been provided. FreeRDP is a free re-implementation of the Microsoft RDP protocol (server and client side) with freerdp-x11 being the most common RDP client these days.

Functional improvements:

With help from FreeRDP upstream (cudos to Bernhard Miklautz and Martin Fleisz) we are happy to announce that RDP proto v6 and CredSSP v3 support have been backported to the old FreeRDP 1.1 branch.

Since Q2/2018, Microsoft Windows servers and clients received an update that defaulted their RDP server to proto version 6. Since this change, people have not been able anymore to connect to recently updated MS Windows machines using old the FreeRDP 1.1 branch as found in Debian jessie LTS and Debian stretch.

With the recent FreeRDP upload to Debian jessie LTS, connecting to up-to-date MS Windows machines is now again possible.

Security issues:

CVE-2018-8786

FreeRDP contained an integer truncation that lead to a heap-based buffer overflow in function update_read_bitmap_update() and resulted in a memory corruption and probably even a remote code execution.

CVE-2018-8787

FreeRDP contained an integer overflow that leads to a heap-based buffer overflow in function gdi_Bitmap_Decompress() and resulted in a memory corruption and probably even a remote code execution.

CVE-2018-8788

FreeRDP contained an out-of-bounds write of up to 4 bytes in function nsc_rle_decode() that resulted in a memory corruption and possibly even a remote code execution.

CVE-2018-8789

FreeRDP contained several out-of-bounds reads in the NTLM authentication module that resulted in a denial of service (segfault).

For Debian 8 Jessie, these security problems have been fixed in version 1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3.

We recommend that you upgrade your freerdp packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'freerdp' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);