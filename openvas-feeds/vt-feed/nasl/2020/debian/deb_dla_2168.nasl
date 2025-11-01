# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892168");
  script_cve_id("CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-6435", "CVE-2017-6436", "CVE-2017-6439", "CVE-2017-7982");
  script_tag(name:"creation_date", value:"2020-04-03 03:00:20 +0000 (Fri, 03 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-02 10:15:00 +0000 (Thu, 02 Apr 2020)");

  script_name("Debian: Security Advisory (DLA-2168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2168");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2168");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libplist' package(s) announced via the DLA-2168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libplist is a library for reading and writing the Apple binary and XML property lists format. It's part of the libimobiledevice stack, providing access to iDevices (iPod, iPhone, iPad ...).

CVE-2017-5209

The base64decode function in base64.c allows attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read) via split encoded Apple Property List data.

CVE-2017-5545

The main function in plistutil.c allows attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read) via Apple Property List data that is too short.

CVE-2017-5834

The parse_dict_node function in bplist.c allows attackers to cause a denial of service (out-of-bounds heap read and crash) via a crafted file.

CVE-2017-5835

libplist allows attackers to cause a denial of service (large memory allocation and crash) via vectors involving an offset size of zero.

CVE-2017-6435

The parse_string_node function in bplist.c allows local users to cause a denial of service (memory corruption) via a crafted plist file.

CVE-2017-6436

The parse_string_node function in bplist.c allows local users to cause a denial of service (memory allocation error) via a crafted plist file.

CVE-2017-6439

Heap-based buffer overflow in the parse_string_node function in bplist.c allows local users to cause a denial of service (out-of-bounds write) via a crafted plist file.

CVE-2017-7982

Integer overflow in the plist_from_bin function in bplist.c allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted plist file.

For Debian 8 Jessie, these problems have been fixed in version 1.11-3+deb8u1.

We recommend that you upgrade your libplist packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libplist' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);