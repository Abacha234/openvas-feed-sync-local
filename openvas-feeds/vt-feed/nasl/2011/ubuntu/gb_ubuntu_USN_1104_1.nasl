# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840629");
  script_cve_id("CVE-2010-3429", "CVE-2010-3908", "CVE-2010-4704", "CVE-2011-0480", "CVE-2011-0722", "CVE-2011-0723");
  script_tag(name:"creation_date", value:"2011-04-06 14:20:31 +0000 (Wed, 06 Apr 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1104-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1104-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1104-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-1104-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cesar Bernardini and Felipe Andres Manzano discovered that FFmpeg
incorrectly handled certain malformed flic files. If a user were tricked
into opening a crafted flic file, an attacker could cause a denial of
service via application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. This issue only affected
Ubuntu 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3429)

Dan Rosenberg discovered that FFmpeg incorrectly handled certain malformed
wmv files. If a user were tricked into opening a crafted wmv file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. This issue only affected Ubuntu 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2010-3908)

It was discovered that FFmpeg incorrectly handled certain malformed ogg
files. If a user were tricked into opening a crafted ogg file, an attacker
could cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2010-4704)

It was discovered that FFmpeg incorrectly handled certain malformed WebM
files. If a user were tricked into opening a crafted WebM file, an attacker
could cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2011-0480)

Dan Rosenberg discovered that FFmpeg incorrectly handled certain malformed
RealMedia files. If a user were tricked into opening a crafted RealMedia
file, an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. This issue only affected Ubuntu 8.04 LTS, 9.10 and 10.04 LTS.
(CVE-2011-0722)

Dan Rosenberg discovered that FFmpeg incorrectly handled certain malformed
VC1 files. If a user were tricked into opening a crafted VC1 file, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2011-0723)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
