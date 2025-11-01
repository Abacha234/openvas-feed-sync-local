# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842938");
  script_cve_id("CVE-2015-0245");
  script_tag(name:"creation_date", value:"2016-11-08 10:22:54 +0000 (Tue, 08 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-3116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3116-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3116-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the USN-3116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that DBus incorrectly validated the source of
ActivationFailure signals. A local attacker could use this issue to cause a
denial of service. This issue only applied to Ubuntu 12.04 LTS and Ubuntu
14.04 LTS. (CVE-2015-0245)

It was discovered that DBus incorrectly handled certain format strings. A
local attacker could use this issue to cause a denial of service, or
possibly execute arbitrary code. This issue is only exposed to unprivileged
users when the fix for CVE-2015-0245 is not applied, hence this issue is
only likely to affect Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. Ubuntu 16.04
LTS and Ubuntu 16.10 have been updated as a preventative measure in the
event that a new attack vector for this issue is discovered.
(No CVE number)");

  script_tag(name:"affected", value:"'dbus' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
