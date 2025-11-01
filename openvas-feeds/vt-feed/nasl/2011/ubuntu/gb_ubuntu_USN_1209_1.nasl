# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840750");
  script_cve_id("CVE-2011-1196", "CVE-2011-1931", "CVE-2011-2161", "CVE-2011-3362");
  script_tag(name:"creation_date", value:"2011-09-23 14:39:49 +0000 (Fri, 23 Sep 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1209-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1209-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1209-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-1209-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg incorrectly handled certain malformed ogg
files. If a user were tricked into opening a crafted ogg file, an attacker
could cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program. This
issue only affected Ubuntu 10.10. (CVE-2011-1196)

It was discovered that FFmpeg incorrectly handled certain malformed AMV
files. If a user were tricked into opening a crafted AMV file, an attacker
could cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program. This
issue only affected Ubuntu 10.10. (CVE-2011-1931)

It was discovered that FFmpeg incorrectly handled certain malformed APE
files. If a user were tricked into opening a crafted APE file, an attacker
could cause a denial of service via application crash. (CVE-2011-2161)

Emmanouel Kellinis discovered that FFmpeg incorrectly handled certain
malformed CAVS files. If a user were tricked into opening a crafted CAVS
file, an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2011-3362)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
