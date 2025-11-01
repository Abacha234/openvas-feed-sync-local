# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841972");
  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638", "CVE-2014-3639");
  script_tag(name:"creation_date", value:"2014-09-23 03:53:39 +0000 (Tue, 23 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2352-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2352-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2352-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the USN-2352-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon McVittie discovered that DBus incorrectly handled the file
descriptors message limit. A local attacker could use this issue to cause
DBus to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only applied to Ubuntu 12.04 LTS and Ubuntu
14.04 LTS. (CVE-2014-3635)

Alban Crequy discovered that DBus incorrectly handled a large number of
file descriptor messages. A local attacker could use this issue to cause
DBus to stop responding, resulting in a denial of service. This issue only
applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-3636)

Alban Crequy discovered that DBus incorrectly handled certain file
descriptor messages. A local attacker could use this issue to cause DBus
to maintain persistent connections, possibly resulting in a denial of
service. This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-3637)

Alban Crequy discovered that DBus incorrectly handled a large number of
parallel connections and parallel message calls. A local attacker could use
this issue to cause DBus to consume resources, possibly resulting in a
denial of service. (CVE-2014-3638)

Alban Crequy discovered that DBus incorrectly handled incomplete
connections. A local attacker could use this issue to cause DBus to fail
legitimate connection attempts, resulting in a denial of service.
(CVE-2014-3639)");

  script_tag(name:"affected", value:"'dbus' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
