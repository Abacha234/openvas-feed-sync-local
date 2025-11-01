# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842008");
  script_cve_id("CVE-2014-1574", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581", "CVE-2014-1585", "CVE-2014-1586");
  script_tag(name:"creation_date", value:"2014-10-16 04:00:32 +0000 (Thu, 16 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2373-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2373-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2373-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2373-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bobby Holley, Christian Holler, David Bolter, Byron Campen and Jon
Coppeard discovered multiple memory safety issues in Thunderbird. If a
user were tricked in to opening a specially crafted message with scripting
enabled, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1574)

Atte Kettunen discovered a buffer overflow during CSS manipulation. If a
user were tricked in to opening a specially crafted message, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2014-1576)

Holger Fuhrmannek discovered an out-of-bounds read with Web Audio. If a
user were tricked in to opening a specially crafted message with scripting
enabled, an attacker could potentially exploit this to steal sensitive
information. (CVE-2014-1577)

Abhishek Arya discovered an out-of-bounds write when buffering WebM video
in some circumstances. If a user were tricked in to opening a specially
crafted message with scripting enabled, an attacker could potentially
exploit this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1578)

A use-after-free was discovered during text layout in some circumstances.
If a user were tricked in to opening a specially crafted message with
scripting enabled, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1581)

Eric Shepherd and Jan-Ivar Bruaroey discovered issues with video sharing
via WebRTC in iframes, where video continues to be shared after being
stopped and navigating to a new site doesn't turn off the camera. An
attacker could potentially exploit this to access the camera without the
user being aware. (CVE-2014-1585, CVE-2014-1586)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
