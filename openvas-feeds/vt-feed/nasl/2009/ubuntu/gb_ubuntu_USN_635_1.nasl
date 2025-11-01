# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840193");
  script_cve_id("CVE-2008-0073", "CVE-2008-0225", "CVE-2008-0238", "CVE-2008-0486", "CVE-2008-1110", "CVE-2008-1161", "CVE-2008-1482", "CVE-2008-1686", "CVE-2008-1878");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-635-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-635-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xine-lib' package(s) announced via the USN-635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop discovered an array index vulnerability in the SDP
parser. If a user or automated system were tricked into opening a
malicious RTSP stream, a remote attacker may be able to execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-0073)

Luigi Auriemma discovered that xine-lib did not properly check
buffer sizes in the RTSP header-handling code. If xine-lib opened an
RTSP stream with crafted SDP attributes, a remote attacker may be
able to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-0225, CVE-2008-0238)

Damian Frizza and Alfredo Ortega discovered that xine-lib did not
properly validate FLAC tags. If a user or automated system were
tricked into opening a crafted FLAC file, a remote attacker may be
able to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-0486)

It was discovered that the ASF demuxer in xine-lib did not properly
check the length if the ASF header. If a user or automated system
were tricked into opening a crafted ASF file, a remote attacker
could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2008-1110)

It was discovered that the Matroska demuxer in xine-lib did not
properly verify frame sizes. If xine-lib opened a crafted ASF file,
a remote attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking
the program. (CVE-2008-1161)

Luigi Auriemma discovered multiple integer overflows in xine-lib. If
a user or automated system were tricked into opening a crafted FLV,
MOV, RM, MVE, MKV or CAK file, a remote attacker may be able to
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-1482)

It was discovered that xine-lib did not properly validate its input
when processing Speex file headers. If a user or automated system
were tricked into opening a specially crafted Speex file, an
attacker could create a denial of service or possibly execute
arbitrary code as the user invoking the program. (CVE-2008-1686)

Guido Landi discovered a stack-based buffer overflow in xine-lib
when processing NSF files. If xine-lib opened a specially crafted
NSF file with a long NSF title, an attacker could create a denial of
service or possibly execute arbitrary code as the user invoking the
program. (CVE-2008-1878)");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
