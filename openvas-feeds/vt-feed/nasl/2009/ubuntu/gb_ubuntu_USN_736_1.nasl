# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63620");
  script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
  script_tag(name:"creation_date", value:"2009-03-19 23:52:38 +0000 (Thu, 19 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-736-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-736-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gst-plugins-good0.10' package(s) announced via the USN-736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GStreamer Good Plugins did not correctly handle
malformed Composition Time To Sample (ctts) atom data in Quicktime (mov)
movie files. If a user were tricked into opening a crafted mov file, an
attacker could execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-0386)

It was discovered that GStreamer Good Plugins did not correctly handle
malformed Sync Sample (aka stss) atom data in Quicktime (mov) movie files.
If a user were tricked into opening a crafted mov file, an attacker could
cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2009-0387)

It was discovered that GStreamer Good Plugins did not correctly handle
malformed Time-to-sample (aka stts) atom data in Quicktime (mov) movie
files. If a user were tricked into opening a crafted mov file, an attacker
could execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-0397)");

  script_tag(name:"affected", value:"'gst-plugins-good0.10' package(s) on Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
